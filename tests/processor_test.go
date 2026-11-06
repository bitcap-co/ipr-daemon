package iprd_test

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	"github.com/gopacket/gopacket/pcapgo"
)

func generateValidPayload(srcIP, srcMAC string, dstPort int) []byte {
	switch dstPort {
	case 14235:
		return []byte(fmt.Sprintf("%s,%s", srcIP, srcMAC))
	default:
		return []byte("IP report from " + srcIP)
	}
}

func validIPReportPacket(mac string, interfaceIndex int, port int) *iprd.IPReportPacket {
	return &iprd.IPReportPacket{
		Timestamp:      time.Now(),
		InterfaceIndex: interfaceIndex,
		SrcIP:          "192.168.1.100",
		SrcMAC:         mac,
		DstPort:        port,
		Datagram:       generateValidPayload("192.168.1.100", mac, port),
		MinerHint:      iprd.UnknownType,
	}
}

func sealminerFixturePacket(t *testing.T) *iprd.IPReportPacket {
	t.Helper()

	file, err := os.Open(filepath.Join("testdata", "captures", "sealminer.pcapng"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	reader, err := pcapgo.NewNgReader(file, pcapgo.NgReaderOptions{WantMixedLinkType: true})
	if err != nil {
		t.Fatal(err)
	}
	data, captureInfo, err := reader.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}
	intf, err := reader.Interface(captureInfo.InterfaceIndex)
	if err != nil {
		t.Fatal(err)
	}

	packet, err := iprd.CapturedPacket{
		Data:        data,
		CaptureInfo: captureInfo,
		LinkType:    intf.LinkType,
	}.ToIPRPacket()
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func decompressSealminerFixture(t *testing.T, datagram []byte) []byte {
	t.Helper()
	if len(datagram) <= 8 {
		t.Fatalf("Sealminer fixture datagram length = %d, want more than 8", len(datagram))
	}

	reader, err := zlib.NewReader(bytes.NewReader(datagram[8:]))
	if err != nil {
		t.Fatal(err)
	}
	decompressed, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		t.Fatal(err)
	}
	return decompressed
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

func TestPacketProcessorLeavesValidPlaintextBeginningWithXUncompressed(t *testing.T) {
	processor := iprd.NewPacketProcessor(nil)
	packet := validIPReportPacket("aa:bb:cc:dd:ee:05", 1, 7777)
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
	packet := validIPReportPacket("aa:bb:cc:dd:ee:06", 1, 7777)
	packet.Datagram = append([]byte{0xff, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'x', ' '}, []byte(packet.SrcIP)...)
	want := bytes.Clone(packet.Datagram)

	if err := processor.ParseIPReportPacket(packet); err != nil {
		t.Fatalf("ParseIPReportPacket() error = %v", err)
	}
	if !bytes.Equal(packet.Datagram, want) {
		t.Fatalf("datagram = %v, want %v", packet.Datagram, want)
	}
}

func TestPacketProcessorDecompressesZlibDatagrams(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset int
	}{
		{name: "stream at offset zero", offset: 0},
		{name: "stream at offset eight", offset: 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			processor := iprd.NewPacketProcessor(nil)
			packet := sealminerFixturePacket(t)
			want := decompressSealminerFixture(t, packet.Datagram)
			if tc.offset == 0 {
				packet.Datagram = bytes.Clone(packet.Datagram[8:])
			} else {
				packet.Datagram = bytes.Clone(packet.Datagram)
			}

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
			packet := sealminerFixturePacket(t)
			payload := decompressSealminerFixture(t, packet.Datagram)
			if len(payload) > tc.size {
				t.Fatalf("Sealminer fixture payload length = %d, want at most %d", len(payload), tc.size)
			}
			payload = append(payload, bytes.Repeat([]byte{' '}, tc.size-len(payload))...)

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
				if err == nil || !errors.Is(err, iprd.ErrPacketTooLarge) {
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
