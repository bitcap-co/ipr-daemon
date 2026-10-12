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

func TestIPReportPacketValidUTF8(t *testing.T) {
	for _, test := range []struct {
		name     string
		datagram []byte
		expected string
	}{
		{
			name:     "valid UTF-8",
			datagram: []byte("Hello, 世界"),
			expected: "Hello, 世界",
		},
		{
			name:     "invalid UTF-8",
			datagram: []byte("Hello, \xff"),
			expected: "Hello, ",
		},
		{
			name:     "empty",
			datagram: []byte{},
			expected: "",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := bytes.Clone(test.datagram)
			report := &iprd.IPReportPacket{
				Datagram: test.datagram,
			}
			valid := report.ValidUTF8()
			if valid != test.expected {
				t.Fatalf("ValidUTF8 returned %q, expected %q", valid, test.expected)
			}
			if !bytes.Equal(report.Datagram, original) {
				t.Fatalf("ValidUTF8 modified datagram: got %v, want %v", report.Datagram, original)
			}
		})
	}
}
