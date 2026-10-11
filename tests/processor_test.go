package iprd_test

import (
	"bytes"
	"compress/zlib"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

func validIPReportPacket(mac string, interfaceIndex int, port int) *iprd.IPReportPacket {
	return &iprd.IPReportPacket{
		Timestamp:      time.Now(),
		InterfaceIndex: interfaceIndex,
		SrcIP:          "192.168.1.100",
		SrcMAC:         mac,
		DstPort:        port,
		Datagram:       []byte("IP report from 192.168.1.100"),
		MinerHint:      iprd.UnknownType,
	}
}

func TestIPReportPacketStringIncludesInterfaceName(t *testing.T) {
	packet := validIPReportPacket("aa:bb:cc:dd:ee:00", 1, 14235)
	packet.InterfaceName = "eth0"
	if got := packet.String(); !strings.HasPrefix(got, "[iface: eth0 IP: 192.168.1.100") {
		t.Fatalf("String() = %q, want interface prefix", got)
	}
}

func TestPacketProcessorUpdatesOwnedRecord(t *testing.T) {
	record := iprd.NewRecord(5)
	processor := iprd.NewPacketProcessor(record)
	packet := validIPReportPacket("aa:bb:cc:dd:ee:01", 1, 14235)

	if err := processor.ParseIPReportPacket(packet); err != nil {
		t.Fatalf("ParseIPReportPacket() error = %v", err)
	}
	if record.Length() != 1 {
		t.Fatalf("record length = %d, want 1", record.Length())
	}
	if packet.MinerHint != iprd.Antminer {
		t.Fatalf("miner hint = %v, want %v", packet.MinerHint, iprd.Antminer)
	}
}

func TestPacketProcessorDeduplicatesAcrossInterfaces(t *testing.T) {
	processor := iprd.NewPacketProcessor(nil)
	mac := "aa:bb:cc:dd:ee:02"

	if err := processor.ParseIPReportPacket(validIPReportPacket(mac, 1, 14235)); err != nil {
		t.Fatalf("first ParseIPReportPacket() error = %v", err)
	}
	err := processor.ParseIPReportPacket(validIPReportPacket(mac, 2, 14235))
	if !errors.Is(err, iprd.ErrDuplicatePacket) {
		t.Fatalf("second ParseIPReportPacket() error = %v, want %v", err, iprd.ErrDuplicatePacket)
	}
}

func TestPacketProcessorsHaveIndependentRecords(t *testing.T) {
	first := iprd.NewPacketProcessor(nil)
	second := iprd.NewPacketProcessor(nil)
	mac := "aa:bb:cc:dd:ee:03"

	if err := first.ParseIPReportPacket(validIPReportPacket(mac, 1, 14235)); err != nil {
		t.Fatalf("first processor error = %v", err)
	}
	if err := second.ParseIPReportPacket(validIPReportPacket(mac, 2, 14235)); err != nil {
		t.Fatalf("second processor unexpectedly shared duplicate state: %v", err)
	}
}

func TestPacketProcessorRejectsNilPacket(t *testing.T) {
	processor := iprd.NewPacketProcessor(nil)
	if err := processor.ParseIPReportPacket(nil); err == nil {
		t.Fatal("ParseIPReportPacket(nil) returned nil error")
	}
}

func TestPacketProcessorCleansInvalidUTF8FromIBeLinkPacket(t *testing.T) {
	processor := iprd.NewPacketProcessor(nil)
	packet := validIPReportPacket("aa:bb:cc:dd:ee:04", 1, 6667)
	packet.Datagram = append([]byte{'A', 'Z', 'Z', 0xf0, 0x01, 0x00, 0x00, 0x00}, []byte(packet.SrcIP)...)
	want := append([]byte{'A', 'Z', 'Z', 0x01, 0x00, 0x00, 0x00}, []byte(packet.SrcIP)...)

	if err := processor.ParseIPReportPacket(packet); err != nil {
		t.Fatalf("ParseIPReportPacket() error = %v", err)
	}
	if !bytes.Equal(packet.Datagram, want) {
		t.Fatalf("cleaned datagram = %v, want %v", packet.Datagram, want)
	}
	if packet.Payload != string(want) {
		t.Fatalf("payload = %q, want %q", packet.Payload, want)
	}
	if packet.MinerHint != iprd.IBeLink {
		t.Fatalf("miner hint = %v, want %v", packet.MinerHint, iprd.IBeLink)
	}
}

func TestPacketProcessorLeavesValidPlaintextBeginningWithXUncompressed(t *testing.T) {
	processor := iprd.NewPacketProcessor(nil)
	packet := validIPReportPacket("aa:bb:cc:dd:ee:05", 1, 14235)
	packet.Datagram = []byte("x IP report from " + packet.SrcIP)
	want := bytes.Clone(packet.Datagram)

	if err := processor.ParseIPReportPacket(packet); err != nil {
		t.Fatalf("ParseIPReportPacket() error = %v", err)
	}
	if !bytes.Equal(packet.Datagram, want) {
		t.Fatalf("datagram = %v, want %v", packet.Datagram, want)
	}
}

func TestPacketProcessorDoesNotMistakeInvalidPlaintextForZlib(t *testing.T) {
	processor := iprd.NewPacketProcessor(nil)
	packet := validIPReportPacket("aa:bb:cc:dd:ee:06", 1, 14235)
	packet.Datagram = append([]byte{0xff, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'x', ' '}, []byte(packet.SrcIP)...)
	want := append([]byte("abcdefgx "), []byte(packet.SrcIP)...)

	if err := processor.ParseIPReportPacket(packet); err != nil {
		t.Fatalf("ParseIPReportPacket() error = %v", err)
	}
	if !bytes.Equal(packet.Datagram, want) {
		t.Fatalf("cleaned datagram = %v, want %v", packet.Datagram, want)
	}
}

func TestPacketProcessorDecompressesZlibDatagrams(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix []byte
	}{
		{name: "stream at offset zero"},
		{name: "stream at offset eight", prefix: make([]byte, 8)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			processor := iprd.NewPacketProcessor(nil)
			packet := validIPReportPacket("aa:bb:cc:dd:ee:07", 1, 18650)
			want := []byte("IP report from " + packet.SrcIP)

			var compressed bytes.Buffer
			compressed.Write(tc.prefix)
			writer := zlib.NewWriter(&compressed)
			if _, err := writer.Write(want); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			packet.Datagram = compressed.Bytes()

			if err := processor.ParseIPReportPacket(packet); err != nil {
				t.Fatalf("ParseIPReportPacket() error = %v", err)
			}
			if !bytes.Equal(packet.Datagram, want) {
				t.Fatalf("decompressed datagram = %q, want %q", packet.Datagram, want)
			}
		})
	}
}

func TestPacketProcessorLimitsDecompressedDatagramSize(t *testing.T) {
	const limit = 64 * 1024

	for _, tc := range []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "at limit", size: limit},
		{name: "over limit", size: limit + 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			processor := iprd.NewPacketProcessor(nil)
			packet := validIPReportPacket("aa:bb:cc:dd:ee:09", 1, 18650)
			payload := bytes.Repeat([]byte{'a'}, tc.size)
			copy(payload, packet.SrcIP)

			var compressed bytes.Buffer
			writer := zlib.NewWriter(&compressed)
			if _, err := writer.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			packet.Datagram = compressed.Bytes()

			err := processor.ParseIPReportPacket(packet)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "decompressed datagram exceeds") {
					t.Fatalf("ParseIPReportPacket() error = %v, want size limit error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseIPReportPacket() error = %v", err)
			}
			if len(packet.Datagram) != tc.size {
				t.Fatalf("decompressed datagram size = %d, want %d", len(packet.Datagram), tc.size)
			}
		})
	}
}

func TestPacketProcessorRejectsEntirelyInvalidUTF8(t *testing.T) {
	processor := iprd.NewPacketProcessor(nil)
	packet := validIPReportPacket("aa:bb:cc:dd:ee:08", 1, 14235)
	packet.Datagram = []byte{0xff, 0xfe}

	if err := processor.ParseIPReportPacket(packet); err == nil {
		t.Fatal("ParseIPReportPacket() returned nil error")
	}
}

func TestPacketProcessorAllowsStaticElphapexPacket(t *testing.T) {
	record := iprd.NewRecord(5)
	processor := iprd.NewPacketProcessor(record)
	packet := validIPReportPacket("aa:bb:cc:dd:ee:00", 1, 9999)
	packet.Datagram = []byte("DG_IPREPORT_ONLY")
	if err := processor.ParseIPReportPacket(packet); err != nil {
		t.Fatalf("ParseIPReportPacket() should return valid for Elphapex packet")
	}
	if record.Length() != 1 {
		t.Fatalf("record length = %d, want 1", record.Length())
	}
	if packet.MinerHint != iprd.Elphapex {
		t.Fatalf("packet miner hint = %v, want %v", packet.MinerHint, iprd.Elphapex)
	}
}
