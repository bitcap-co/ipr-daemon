package iprd_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

func TestIPRBroadcastMessageMarshalKeepsPacketID(t *testing.T) {
	report := &iprd.IPReportPacket{
		Timestamp: time.Now(),
		DstPort:   14235,
		SrcIP:     "192.168.1.100",
		SrcMAC:    "aa:bb:cc:dd:ee:ff",
		MinerHint: iprd.Antminer,
	}
	message, err := iprd.NewIPRBroadcastMessage(report)
	if err != nil {
		t.Fatal(err)
	}
	first, err := message.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	second, err := message.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("repeated Marshal calls differ: %s != %s", first, second)
	}
}

func TestNewIPRBroadcastMessageRejectsNilReport(t *testing.T) {
	if _, err := iprd.NewIPRBroadcastMessage(nil); err == nil {
		t.Fatal("NewIPRBroadcastMessage(nil) returned nil error")
	}
}
