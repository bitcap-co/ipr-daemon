package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func offlineTestPacket(t *testing.T, ipAddress string) ([]byte, gopacket.CaptureInfo) {
	t.Helper()
	if ipAddress == "" {
		ipAddress = "192.168.1.100"
	}
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x21},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(ipAddress).To4(),
		DstIP:    net.ParseIP("255.255.255.255").To4(),
	}
	udp := &layers.UDP{SrcPort: 5000, DstPort: 14235}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, eth, ip, udp, gopacket.Payload("IP report from 192.168.1.100")); err != nil {
		t.Fatal(err)
	}
	data := append([]byte(nil), buf.Bytes()...)
	return data, gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(data),
		Length:        len(data),
	}
}

func TestDumpPcapNGIncludesInterfaceName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	data, ci := offlineTestPacket(t, "")
	writer := iprd.NewCaptureWriter(path, false, iprd.NewLogger())
	if err := writer.Open(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Write(iprd.CapturedPacket{
		Data:        data,
		CaptureInfo: ci,
		LinkType:    layers.LinkTypeEthernet,
		Interface:   iprd.IPRInterface{Index: 3, Name: "test0"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	log.SetOutput(&output)
	defer log.SetOutput(os.Stdout)
	if err := dumpPcap(path, false, filterConfig{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Summary:") {
		t.Fatalf("output does not contain summary:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "iface: test0") {
		t.Fatalf("output does not identify PCAP-NG interface:\n%s", output.String())
	}
}

func TestDumpClassicPcapRemainsSupported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcap")
	data, ci := offlineTestPacket(t, "")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePacket(ci, data); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	log.SetOutput(&output)
	defer log.SetOutput(os.Stdout)
	if err := dumpPcap(path, false, filterConfig{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Summary:") {
		t.Fatalf("output does not contain summary:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "iface: classic") {
		t.Fatalf("output does not identify classic PCAP input:\n%s", output.String())
	}
}

func TestOfflineFilterOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	data, ci := offlineTestPacket(t, "")
	writer := iprd.NewCaptureWriter(path, false, iprd.NewLogger())
	if err := writer.Open(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Write(iprd.CapturedPacket{
		Data:        data,
		CaptureInfo: ci,
		LinkType:    layers.LinkTypeEthernet,
		Interface:   iprd.IPRInterface{Index: 3, Name: "test0"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Write(iprd.CapturedPacket{
		Data:        data,
		CaptureInfo: ci,
		LinkType:    layers.LinkTypeEthernet,
		Interface:   iprd.IPRInterface{Index: 4, Name: "test1"},
	}); err != nil {
		t.Fatal(err)
	}
	data, ci2 := offlineTestPacket(t, "192.168.1.44")
	if err := writer.Write(iprd.CapturedPacket{
		Data:        data,
		CaptureInfo: ci2,
		LinkType:    layers.LinkTypeEthernet,
		Interface:   iprd.IPRInterface{Index: 4, Name: "test1"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name          string
		filter        filterConfig
		expectedCount int
	}{
		{"filter by interface name (test0)", filterConfig{InterfaceName: "test0"}, 1},
		{"filter by interface name (test1)", filterConfig{InterfaceName: "test1"}, 2},
		{"filter by IP address (192.168.1.100)", filterConfig{IPAddress: "192.168.1.100"}, 2},
		{"filter by MAC address (aa:bb:cc:dd:ee:21)", filterConfig{MACAddress: "aa:bb:cc:dd:ee:21"}, 3},
		{"filter by non-existent interface name (test2)", filterConfig{InterfaceName: "test2"}, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			log.SetOutput(&output)
			defer log.SetOutput(os.Stdout)
			// enable debug here to output all messages including duplicates
			if err := dumpPcap(path, true, test.filter); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(output.String(), "Summary:") {
				t.Fatalf("output contains summary, expected no summary:\n%s", output.String())
			}
			gotCount := strings.Count(output.String(), " - ")
			if gotCount != test.expectedCount {
				t.Fatalf("expected %d packets, got %d:\n%s", test.expectedCount, gotCount, output.String())
			}
		})
	}
}
