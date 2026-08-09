package iprd_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

func validIPReportPacket(mac string, interfaceIndex int, datagram []byte) *iprd.IPReportPacket {
	if datagram == nil {
		datagram = []byte("IP report from 192.168.1.100")
	}
	return &iprd.IPReportPacket{
		Timestamp:      time.Now(),
		InterfaceIndex: interfaceIndex,
		SrcIP:          "192.168.1.100",
		SrcMAC:         mac,
		DstPort:        14235,
		Datagram:       datagram,
		MinerHint:      iprd.UnknownType,
	}
}

func TestIPReportPacketStringIncludesInterfaceName(t *testing.T) {
	packet := validIPReportPacket("aa:bb:cc:dd:ee:00", 1, nil)
	packet.InterfaceName = "eth0"
	if got := packet.String(); !strings.HasPrefix(got, "[iface: eth0 IP: 192.168.1.100") {
		t.Fatalf("String() = %q, want interface prefix", got)
	}
}

func TestPacketProcessorUpdatesOwnedRecord(t *testing.T) {
	record := iprd.NewRecord(5)
	processor := iprd.NewPacketProcessor(record)
	packet := validIPReportPacket("aa:bb:cc:dd:ee:01", 1, nil)

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

	if err := processor.ParseIPReportPacket(validIPReportPacket(mac, 1, nil)); err != nil {
		t.Fatalf("first ParseIPReportPacket() error = %v", err)
	}
	err := processor.ParseIPReportPacket(validIPReportPacket(mac, 2, nil))
	if !errors.Is(err, iprd.ErrDuplicatePacket) {
		t.Fatalf("second ParseIPReportPacket() error = %v, want %v", err, iprd.ErrDuplicatePacket)
	}
}

func TestPacketProcessorsHaveIndependentRecords(t *testing.T) {
	first := iprd.NewPacketProcessor(nil)
	second := iprd.NewPacketProcessor(nil)
	mac := "aa:bb:cc:dd:ee:03"

	if err := first.ParseIPReportPacket(validIPReportPacket(mac, 1, nil)); err != nil {
		t.Fatalf("first processor error = %v", err)
	}
	if err := second.ParseIPReportPacket(validIPReportPacket(mac, 2, nil)); err != nil {
		t.Fatalf("second processor unexpectedly shared duplicate state: %v", err)
	}
}

func TestPacketProcessorRejectsNilPacket(t *testing.T) {
	processor := iprd.NewPacketProcessor(nil)
	if err := processor.ParseIPReportPacket(nil); err == nil {
		t.Fatal("ParseIPReportPacket(nil) returned nil error")
	}
}

func TestPacketProcessorAllowsStaticElphapexPacket(t *testing.T) {
	record := iprd.NewRecord(5)
	processor := iprd.NewPacketProcessor(record)
	packet := validIPReportPacket("aa:bb:cc:dd:ee:00", 1, []byte("DG_IPREPORT_ONLY"))
	if err := processor.ParseIPReportPacket(packet); err != nil {
		t.Fatalf("ParseIPReportPacket() should return valid for Elphapex packet")
	}
	if record.Length() != 1 {
		t.Fatalf("record length = %d, want 1", record.Length())
	}
}
