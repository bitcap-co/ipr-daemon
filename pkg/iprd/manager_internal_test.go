package iprd

import (
	"context"
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

func TestListenerManagerInitialStatus(t *testing.T) {
	manager, err := NewListenerManager(DefaultListenerConfig(), NewLogger())
	if err != nil {
		t.Fatal(err)
	}

	status := manager.Status()
	if status.State != ManagerStateIdle {
		t.Fatalf("state = %q, want %q", status.State, ManagerStateIdle)
	}
	if status.ListenersConfigured != len(manager.listeners) {
		t.Fatalf("configured listeners = %d, want %d", status.ListenersConfigured, len(manager.listeners))
	}
	if status.ListenersActive != 0 {
		t.Fatalf("active listeners = %d, want 0", status.ListenersActive)
	}
	if len(status.Listeners) != len(manager.listeners) {
		t.Fatalf("listener statuses = %d, want %d", len(status.Listeners), len(manager.listeners))
	}
	for _, listener := range status.Listeners {
		if listener.State != ListenerStateIdle {
			t.Fatalf("listener state = %q, want %q", listener.State, ListenerStateIdle)
		}
	}
}

func TestListenerManagerRunIsOneShotAndClosesReports(t *testing.T) {
	manager, err := NewListenerManager(DefaultListenerConfig(), NewLogger())
	if err != nil {
		t.Fatal(err)
	}
	manager.listeners = nil

	if err := manager.Run(context.Background()); err == nil {
		t.Fatal("Run() returned nil error with no configured listeners")
	}
	status := manager.Status()
	if status.State != ManagerStateFailed {
		t.Fatalf("state = %q, want %q", status.State, ManagerStateFailed)
	}
	if status.LastError == "" || status.LastErrorAt.IsZero() {
		t.Fatalf("failure status did not retain error details: %+v", status)
	}
	if _, ok := <-manager.Reports(); ok {
		t.Fatal("Reports() remained open after Run() returned")
	}
	if err := manager.Run(context.Background()); err == nil {
		t.Fatal("second Run() returned nil error")
	}
}

func TestListenerManagerStatusAggregatesListenerHealth(t *testing.T) {
	cfg := DefaultListenerConfig()
	cfg.ListenInterfaces = []string{"eth1", "eth2"}
	manager, err := NewListenerManager(cfg, NewLogger())
	if err != nil {
		t.Fatal(err)
	}
	manager.telemetry.setState(ManagerStateStarting, nil)

	manager.listeners[0].telemetry.setState(ListenerStateActive, nil)
	manager.listeners[1].telemetry.setState(ListenerStateActive, nil)
	status := manager.Status()
	if status.State != ManagerStateHealthy || status.ListenersActive != 2 {
		t.Fatalf("healthy status = %+v", status)
	}

	manager.listeners[1].telemetry.activationFailures.Add(1)
	manager.listeners[1].telemetry.setState(ListenerStateReconnecting, fmt.Errorf("interface unavailable"))
	status = manager.Status()
	if status.State != ManagerStateDegraded || status.ListenersActive != 1 {
		t.Fatalf("degraded status = %+v", status)
	}
	if status.ActivationFailures != 1 {
		t.Fatalf("activation failures = %d, want 1", status.ActivationFailures)
	}
	if status.Listeners[1].ActivationFailures != 1 || status.Listeners[1].LastError == "" || status.Listeners[1].LastErrorAt.IsZero() {
		t.Fatalf("listener failure status = %+v", status.Listeners[1])
	}
}

func TestListenerManagerStatusTracksActivationFailureAndShutdown(t *testing.T) {
	cfg := DefaultListenerConfig()
	cfg.ListenInterfaces = []string{"iprd-test-interface-that-does-not-exist"}
	manager, err := NewListenerManager(cfg, NewLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- manager.Run(ctx)
	}()

	deadline := time.After(2 * time.Second)
	for {
		status := manager.Status()
		if status.ActivationFailures > 0 {
			if status.State != ManagerStateDegraded {
				t.Fatalf("state after activation failure = %q, want %q", status.State, ManagerStateDegraded)
			}
			if status.ListenersActive != 0 || status.LastError == "" || status.LastErrorAt.IsZero() {
				t.Fatalf("activation failure status = %+v", status)
			}
			break
		}
		select {
		case <-deadline:
			cancel()
			t.Fatal("timed out waiting for activation failure")
		case <-time.After(time.Millisecond):
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() after cancellation returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for manager shutdown")
	}
	if status := manager.Status(); status.State != ManagerStateStopped {
		t.Fatalf("state after shutdown = %q, want %q", status.State, ManagerStateStopped)
	}
}

func TestListenerManagerStatusConcurrent(t *testing.T) {
	cfg := DefaultListenerConfig()
	cfg.ListenInterfaces = []string{"test0"}
	manager, err := NewListenerManager(cfg, NewLogger())
	if err != nil {
		t.Fatal(err)
	}
	manager.telemetry.setState(ManagerStateStarting, nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1_000; i++ {
			manager.listeners[0].telemetry.setState(ListenerStateActive, nil)
			manager.listeners[0].telemetry.reconnects.Add(1)
			manager.listeners[0].telemetry.setState(ListenerStateReconnecting, fmt.Errorf("reconnect %d", i))
		}
	}()
	for i := 0; i < 1_000; i++ {
		_ = manager.Status()
	}
	<-done
}

func TestListenerManagerPacketStatus(t *testing.T) {
	cfg := DefaultListenerConfig()
	cfg.ForwardKnown = true
	manager, err := NewListenerManager(cfg, NewLogger())
	if err != nil {
		t.Fatal(err)
	}

	firstAt := time.Unix(1_700_000_000, 100)
	valid := capturedIPReport(t, "aa:bb:cc:dd:ee:10", 14235, 1)
	valid.CaptureInfo.Timestamp = firstAt
	if report := manager.processCapturedPacket(valid); report == nil {
		t.Fatal("valid capture returned no report")
	}

	duplicate := valid
	duplicate.CaptureInfo.Timestamp = firstAt.Add(time.Second)
	if report := manager.processCapturedPacket(duplicate); report != nil {
		t.Fatal("duplicate capture returned a report")
	}

	unknown := capturedIPReport(t, "aa:bb:cc:dd:ee:11", 7777, 1)
	unknown.CaptureInfo.Timestamp = firstAt.Add(2 * time.Second)
	if report := manager.processCapturedPacket(unknown); report != nil {
		t.Fatal("unknown capture returned a report")
	}

	invalidAt := firstAt.Add(3 * time.Second)
	invalid := CapturedPacket{
		Data:        []byte{0x01, 0x02, 0x03},
		LinkType:    layers.LinkTypeEthernet,
		CaptureInfo: gopacket.CaptureInfo{Timestamp: invalidAt},
	}
	if report := manager.processCapturedPacket(invalid); report != nil {
		t.Fatal("invalid capture returned a report")
	}

	status := manager.Status()
	want := PacketCounters{Processed: 4, Reports: 1, Invalid: 1, Duplicates: 1, UnknownFiltered: 1}
	if status.Packets != want {
		t.Fatalf("packet counters = %+v, want %+v", status.Packets, want)
	}
	if !status.LastPacketAt.Equal(invalidAt) {
		t.Fatalf("last packet = %s, want %s", status.LastPacketAt, invalidAt)
	}
	if !status.LastReportAt.Equal(firstAt) {
		t.Fatalf("last report = %s, want %s", status.LastReportAt, firstAt)
	}

	status.Packets.Processed = 0
	status.Listeners = nil
	fresh := manager.Status()
	if fresh.Packets.Processed != 4 || len(fresh.Listeners) != len(manager.listeners) {
		t.Fatalf("mutating snapshot changed manager status: %+v", fresh)
	}
}

func TestListenerManagerProcessesCapturedPacket(t *testing.T) {
	manager, err := NewListenerManager(DefaultListenerConfig(), NewLogger())
	if err != nil {
		t.Fatal(err)
	}
	captured := capturedIPReport(t, "aa:bb:cc:dd:ee:01", 14235, 3)

	report := manager.processCapturedPacket(captured)
	if report == nil {
		t.Fatal("processCapturedPacket() returned no IP report")
	}
	if report.SrcMAC != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("source MAC = %q, want %q", report.SrcMAC, "aa:bb:cc:dd:ee:01")
	}
	if report.MinerHint != Antminer {
		t.Fatalf("miner hint = %v, want %v", report.MinerHint, Antminer)
	}
}

func TestListenerManagerDeduplicatesAcrossCapturedInterfaces(t *testing.T) {
	manager, err := NewListenerManager(DefaultListenerConfig(), NewLogger())
	if err != nil {
		t.Fatal(err)
	}
	mac := "aa:bb:cc:dd:ee:02"
	if report := manager.processCapturedPacket(capturedIPReport(t, mac, 14235, 1)); report == nil {
		t.Fatal("first capture returned no IP report")
	}
	if report := manager.processCapturedPacket(capturedIPReport(t, mac, 14235, 2)); report != nil {
		t.Fatal("duplicate capture from another interface was reported")
	}
}

func TestListenerManagerFiltersUnknownMiners(t *testing.T) {
	cfg := DefaultListenerConfig()
	cfg.ForwardKnown = true
	manager, err := NewListenerManager(cfg, NewLogger())
	if err != nil {
		t.Fatal(err)
	}

	if report := manager.processCapturedPacket(capturedIPReport(t, "aa:bb:cc:dd:ee:03", 7777, 1)); report != nil {
		t.Fatal("unknown miner was reported with ForwardKnown enabled")
	}
}

func TestNewListenerManagerCreatesListenerPerInterface(t *testing.T) {
	cfg := DefaultListenerConfig()
	cfg.ListenInterfaces = []string{"eth1", "eth2"}
	cfg.ListenInterface = ""
	cfg.CaptureFile = "capture.pcap"
	manager, err := NewListenerManager(cfg, NewLogger())
	if err != nil {
		t.Fatal(err)
	}

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
	cfg := DefaultListenerConfig()
	cfg.ListenInterfaces = []string{"eth1", "eth2"}
	cfg.IgnoredDevices = []string{"global-mac"}
	cfg.NetworkInclusions = []string{"10"}
	cfg.NetworkExclusions = []string{"172.16"}
	cfg.Interfaces = []InterfaceConfig{
		{
			Selector:          "eth2",
			NoRootNetwork:     true,
			IgnoredDevices:    []string{"interface-mac"},
			NetworkInclusions: []string{"192.168.2"},
			NetworkExclusions: []string{"192.168.3"},
		},
	}

	manager, err := NewListenerManager(cfg, NewLogger())
	if err != nil {
		t.Fatal(err)
	}
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
	cfg := DefaultListenerConfig()
	cfg.Auto = true
	cfg.ListenInterfaces = []string{"eth1", "eth2"}
	manager, err := NewListenerManager(cfg, NewLogger())
	if err != nil {
		t.Fatal(err)
	}

	if len(manager.listeners) != 1 {
		t.Fatalf("listener count = %d, want 1", len(manager.listeners))
	}
	if !manager.listeners[0].cfg.Auto {
		t.Fatal("auto listener does not have auto mode enabled")
	}
}

func TestForwardCapturedPacketsFansInListeners(t *testing.T) {
	cfg := DefaultListenerConfig()
	cfg.ListenInterfaces = []string{"eth1", "eth2"}
	manager, err := NewListenerManager(cfg, NewLogger())
	if err != nil {
		t.Fatal(err)
	}
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
