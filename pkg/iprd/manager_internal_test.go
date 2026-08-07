package iprd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
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

func TestNewListenerManagerCreatesListenerPerInterface(t *testing.T) {
	cfg := DefaultIPRDConfig()
	cfg.ListenInterfaces = []string{"eth1", "eth2"}
	cfg.ListenInterface = ""
	cfg.CaptureFile = "capture.pcap"
	manager := NewListenerManager(cfg, NewLogger())

	if len(manager.listeners) != 2 {
		t.Fatalf("listener count = %d, want 2", len(manager.listeners))
	}
	for index, selector := range []string{"eth1", "eth2"} {
		listenerCfg := manager.listeners[index].cfg
		if listenerCfg.ListenInterface != selector {
			t.Fatalf("listener %d selector = %q, want %q", index, listenerCfg.ListenInterface, selector)
		}
		if len(listenerCfg.ListenInterfaces) != 1 || listenerCfg.ListenInterfaces[0] != selector {
			t.Fatalf("listener %d interfaces = %v, want [%s]", index, listenerCfg.ListenInterfaces, selector)
		}
	}
	if manager.cfg.ListenInterface != "eth1" {
		t.Fatalf("compatibility interface = %q, want %q", manager.cfg.ListenInterface, "eth1")
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

func TestNewListenerManagerAppliesInterfaceBPFOptions(t *testing.T) {
	cfg := DefaultIPRDConfig()
	cfg.ListenInterfaces = []string{"eth1", "eth2"}
	cfg.IgnoredDevices = []string{"global-mac"}
	cfg.NetworkInclusions = []string{"10"}
	cfg.NetworkExclusions = []string{"172.16"}
	cfg.Interfaces = FlagInterface{
		"eth2": {
			NoRootNetwork:     true,
			IgnoredDevices:    []string{"interface-mac"},
			NetworkInclusions: []string{"192.168.2"},
			NetworkExclusions: []string{"192.168.3"},
		},
	}

	manager := NewListenerManager(cfg, NewLogger())
	eth1 := manager.listeners[0].cfg
	eth2 := manager.listeners[1].cfg
	if eth1.NoRootNetwork {
		t.Fatal("eth1 unexpectedly excludes its root network")
	}
	if eth2.NoRootNetwork != true {
		t.Fatal("eth2 does not exclude its root network")
	}
	if want := []string{"global-mac", "interface-mac"}; !reflect.DeepEqual(eth2.IgnoredDevices, want) {
		t.Fatalf("eth2 ignored devices = %v, want %v", eth2.IgnoredDevices, want)
	}
	if want := []string{"10", "192.168.2"}; !reflect.DeepEqual(eth2.NetworkInclusions, want) {
		t.Fatalf("eth2 inclusions = %v, want %v", eth2.NetworkInclusions, want)
	}
	if want := []string{"172.16", "192.168.3"}; !reflect.DeepEqual(eth2.NetworkExclusions, want) {
		t.Fatalf("eth2 exclusions = %v, want %v", eth2.NetworkExclusions, want)
	}
	if !reflect.DeepEqual(cfg.IgnoredDevices, []string{"global-mac"}) {
		t.Fatalf("constructor mutated global ignored devices: %v", cfg.IgnoredDevices)
	}
}

func TestNewListenerManagerAutoModeCreatesOneListener(t *testing.T) {
	cfg := DefaultIPRDConfig()
	cfg.Auto = true
	cfg.ListenInterfaces = []string{"eth1", "eth2"}
	manager := NewListenerManager(cfg, NewLogger())

	if len(manager.listeners) != 1 {
		t.Fatalf("listener count = %d, want 1", len(manager.listeners))
	}
	if !manager.listeners[0].cfg.Auto {
		t.Fatal("auto listener does not have auto mode enabled")
	}
}

func TestForwardCapturedPacketsFansInListeners(t *testing.T) {
	cfg := DefaultIPRDConfig()
	cfg.ListenInterfaces = []string{"eth1", "eth2"}
	manager := NewListenerManager(cfg, NewLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	captures := make(chan CapturedPacket)
	done := make(chan struct{}, len(manager.listeners))
	for _, listener := range manager.listeners {
		go func() {
			defer func() { done <- struct{}{} }()
			forwardCapturedPackets(ctx, listener.Packets(), captures)
		}()
	}

	for index, listener := range manager.listeners {
		want := capturedIPReport(t, fmt.Sprintf("aa:bb:cc:dd:ee:%02x", index+20), 14235, index+1)
		select {
		case listener.packets <- want:
		case <-time.After(time.Second):
			t.Fatal("timed out sending captured packet")
		}
		select {
		case got := <-captures:
			if got.CaptureInfo.InterfaceIndex != want.CaptureInfo.InterfaceIndex {
				t.Fatalf("capture interface index = %d, want %d", got.CaptureInfo.InterfaceIndex, want.CaptureInfo.InterfaceIndex)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for captured packet")
		}
	}

	cancel()
	for range manager.listeners {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for fan-in shutdown")
		}
	}
}
