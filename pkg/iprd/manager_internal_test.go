package iprd

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func capturedIPReport(t *testing.T, srcMAC string, dstPort layers.UDPPort, interfaceIndex int) CapturedPacket {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       mustHardwareAddr(t, srcMAC),
		DstMAC:       mustHardwareAddr(t, "ff:ff:ff:ff:ff:ff"),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("192.168.1.100").To4(),
		DstIP:    net.ParseIP("255.255.255.255").To4(),
	}
	udp := &layers.UDP{SrcPort: 5000, DstPort: dstPort}
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
	return CapturedPacket{
		Data: data,
		CaptureInfo: gopacket.CaptureInfo{
			Timestamp:      time.Now(),
			CaptureLength:  len(data),
			Length:         len(data),
			InterfaceIndex: interfaceIndex,
		},
		LinkType: layers.LinkTypeEthernet,
		Interface: IPRInterface{
			Index: interfaceIndex,
			Name:  "test-interface",
		},
	}
}

func mustHardwareAddr(t *testing.T, value string) net.HardwareAddr {
	t.Helper()
	addr, err := net.ParseMAC(value)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestListenerManagerProcessesCapturedPacket(t *testing.T) {
	manager := NewListenerManager(DefaultIPRDConfig(), NewLogger())
	captured := capturedIPReport(t, "aa:bb:cc:dd:ee:01", 14235, 3)

	msg := manager.processCapturedPacket(captured)
	if msg == nil {
		t.Fatal("processCapturedPacket() returned no broadcast message")
	}
	var broadcast IPRBroadcastMessage
	if err := json.Unmarshal(msg, &broadcast); err != nil {
		t.Fatal(err)
	}
	if broadcast.SrcMAC != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("source MAC = %q, want %q", broadcast.SrcMAC, "aa:bb:cc:dd:ee:01")
	}
	if broadcast.MinerHint != Antminer {
		t.Fatalf("miner hint = %v, want %v", broadcast.MinerHint, Antminer)
	}
}

func TestListenerManagerDeduplicatesAcrossCapturedInterfaces(t *testing.T) {
	manager := NewListenerManager(DefaultIPRDConfig(), NewLogger())
	mac := "aa:bb:cc:dd:ee:02"
	if msg := manager.processCapturedPacket(capturedIPReport(t, mac, 14235, 1)); msg == nil {
		t.Fatal("first capture returned no broadcast message")
	}
	if msg := manager.processCapturedPacket(capturedIPReport(t, mac, 14235, 2)); msg != nil {
		t.Fatal("duplicate capture from another interface was broadcast")
	}
}

func TestListenerManagerFiltersUnknownMiners(t *testing.T) {
	cfg := DefaultIPRDConfig()
	cfg.ForwardKnown = true
	manager := NewListenerManager(cfg, NewLogger())

	if msg := manager.processCapturedPacket(capturedIPReport(t, "aa:bb:cc:dd:ee:03", 7777, 1)); msg != nil {
		t.Fatal("unknown miner was broadcast with ForwardKnown enabled")
	}
}

func TestNewListenerManagerNormalizesFirstInterface(t *testing.T) {
	cfg := DefaultIPRDConfig()
	cfg.ListenInterfaces = []string{"eth1", "eth2"}
	cfg.ListenInterface = ""
	cfg.CaptureFile = "capture.pcap"
	manager := NewListenerManager(cfg, NewLogger())

	if manager.cfg.ListenInterface != "eth1" {
		t.Fatalf("listener interface = %q, want %q", manager.cfg.ListenInterface, "eth1")
	}
	if manager.cfg.CaptureFile != "capture.pcapng" {
		t.Fatalf("capture path = %q, want %q", manager.cfg.CaptureFile, "capture.pcapng")
	}
	if cfg.ListenInterface != "" {
		t.Fatalf("constructor mutated supplied config interface to %q", cfg.ListenInterface)
	}
	if cfg.CaptureFile != "capture.pcap" {
		t.Fatalf("constructor mutated supplied capture path to %q", cfg.CaptureFile)
	}
}
