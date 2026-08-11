package iprd_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func offlineCapturePacket(t *testing.T) ([]byte, gopacket.CaptureInfo) {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x31},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("192.168.1.100").To4(),
		DstIP:    net.ParseIP("255.255.255.255").To4(),
	}
	udp := &layers.UDP{SrcPort: 5000, DstPort: 14235}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, eth, ip, udp, gopacket.Payload("IP report from 192.168.1.100")); err != nil {
		t.Fatal(err)
	}
	data := append([]byte(nil), buffer.Bytes()...)
	return data, gopacket.CaptureInfo{
		Timestamp:     time.Unix(1_700_000_000, 0),
		CaptureLength: len(data),
		Length:        len(data),
	}
}

func classicOfflineCapture(t *testing.T) []byte {
	t.Helper()
	data, ci := offlineCapturePacket(t)
	var capture bytes.Buffer
	writer := pcapgo.NewWriter(&capture)
	if err := writer.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePacket(ci, data); err != nil {
		t.Fatal(err)
	}
	return capture.Bytes()
}

func pcapNGOfflineCapture(t *testing.T) []byte {
	t.Helper()
	data, ci := offlineCapturePacket(t)
	var capture bytes.Buffer
	intf := pcapgo.DefaultNgInterface
	intf.Name = "test0"
	intf.LinkType = layers.LinkTypeEthernet
	writer, err := pcapgo.NewNgWriterInterface(&capture, intf, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePacket(ci, data); err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePacket(ci, data); err != nil {
		t.Fatal(err)
	}
	laterCI := ci
	laterCI.Timestamp = laterCI.Timestamp.Add(11 * time.Second)
	if err := writer.WritePacket(laterCI, data); err != nil {
		t.Fatal(err)
	}
	invalid := []byte{0x00, 0x01, 0x02, 0x03}
	invalidCI := ci
	invalidCI.CaptureLength = len(invalid)
	invalidCI.Length = len(invalid)
	if err := writer.WritePacket(invalidCI, invalid); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	return capture.Bytes()
}

func TestProcessCaptureClassicPCAP(t *testing.T) {
	var events []iprd.OfflinePacketResult
	result, err := iprd.ProcessCapture(context.Background(), bytes.NewReader(classicOfflineCapture(t)), func(event iprd.OfflinePacketResult) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("ProcessCapture() error = %v", err)
	}
	if result != (iprd.OfflineResult{Processed: 1, Reports: 1}) {
		t.Fatalf("ProcessCapture() result = %+v", result)
	}
	if len(events) != 1 {
		t.Fatalf("handler calls = %d, want 1", len(events))
	}
	event := events[0]
	if event.Err != nil {
		t.Fatalf("packet error = %v", event.Err)
	}
	if event.InterfaceName != "classic" || event.Report.InterfaceName != "classic" {
		t.Fatalf("interface names = %q, %q; want classic", event.InterfaceName, event.Report.InterfaceName)
	}
	if event.Report.SrcIP != "192.168.1.100" || event.Report.SrcMAC != "aa:bb:cc:dd:ee:31" {
		t.Fatalf("unexpected report = %+v", event.Report)
	}
	if event.Report.MinerHint != iprd.Antminer {
		t.Fatalf("miner hint = %v, want %v", event.Report.MinerHint, iprd.Antminer)
	}
}

func TestProcessCapturePCAPNGClassifiesFrames(t *testing.T) {
	var events []iprd.OfflinePacketResult
	result, err := iprd.ProcessCapture(context.Background(), bytes.NewReader(pcapNGOfflineCapture(t)), func(event iprd.OfflinePacketResult) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("ProcessCapture() error = %v", err)
	}
	want := iprd.OfflineResult{Processed: 4, Reports: 2, Invalid: 1, Duplicates: 1}
	if result != want {
		t.Fatalf("ProcessCapture() result = %+v, want %+v", result, want)
	}
	if len(events) != 4 {
		t.Fatalf("handler calls = %d, want 4", len(events))
	}
	if events[0].InterfaceName != "test0" || events[0].Report.InterfaceName != "test0" {
		t.Fatalf("PCAP-NG interface was not preserved: %+v", events[0])
	}
	if !errors.Is(events[1].Err, iprd.ErrDuplicatePacket) {
		t.Fatalf("second packet error = %v, want duplicate", events[1].Err)
	}
	if events[2].Err != nil {
		t.Fatalf("packet outside duplicate window error = %v", events[2].Err)
	}
	if events[3].Err == nil || events[3].Report != nil {
		t.Fatalf("invalid packet outcome = %+v", events[3])
	}
}

func TestProcessCaptureReturnsHandlerError(t *testing.T) {
	handlerErr := errors.New("stop processing")
	result, err := iprd.ProcessCapture(context.Background(), bytes.NewReader(classicOfflineCapture(t)), func(iprd.OfflinePacketResult) error {
		return handlerErr
	})
	if !errors.Is(err, handlerErr) {
		t.Fatalf("ProcessCapture() error = %v, want %v", err, handlerErr)
	}
	if result.Processed != 1 || result.Reports != 1 {
		t.Fatalf("ProcessCapture() result = %+v", result)
	}
}

func TestProcessCaptureHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	result, err := iprd.ProcessCapture(ctx, bytes.NewReader(classicOfflineCapture(t)), func(iprd.OfflinePacketResult) error {
		calls++
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ProcessCapture() error = %v, want %v", err, context.Canceled)
	}
	if result != (iprd.OfflineResult{}) || calls != 0 {
		t.Fatalf("result = %+v, handler calls = %d; want no processing", result, calls)
	}
}

func TestProcessCaptureRejectsInvalidInput(t *testing.T) {
	_, err := iprd.ProcessCapture(context.Background(), strings.NewReader("not a capture"), func(iprd.OfflinePacketResult) error {
		return nil
	})
	if err == nil {
		t.Fatal("ProcessCapture() returned nil error for invalid input")
	}
}
