package main

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func testFrame(t *testing.T, sourceIP, sourceMAC string) []byte {
	t.Helper()
	payload := []byte(sourceIP + "," + sourceMAC)
	payload = append(payload, net.ParseIP(sourceIP).To4()...)
	payload = append(payload, mustMAC(t, sourceMAC)...)
	return testFrameWithPayload(t, sourceIP, sourceMAC, payload)
}

func testFrameWithPayload(t *testing.T, sourceIP, sourceMAC string, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       mustMAC(t, sourceMAC),
		DstMAC:       mustMAC(t, "ff:ff:ff:ff:ff:ff"),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(sourceIP).To4(),
		DstIP:    net.ParseIP("255.255.255.255").To4(),
	}
	udp := &layers.UDP{SrcPort: 5000, DstPort: 14235}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buffer.Bytes()...)
}

func mustMAC(t *testing.T, value string) net.HardwareAddr {
	t.Helper()
	address, err := net.ParseMAC(value)
	if err != nil {
		t.Fatal(err)
	}
	return address
}

func TestFrameAnonymizesHeadersAndPayloadConsistently(t *testing.T) {
	anonymizer := newAddressAnonymizer()
	originalIP := "192.168.50.25"
	originalMAC := "aa:bb:cc:dd:ee:25"
	data, err := anonymizer.frame(testFrame(t, originalIP, originalMAC), layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(originalIP)) || bytes.Contains(data, []byte(originalMAC)) {
		t.Fatalf("anonymized frame still contains a textual source address: %q", data)
	}
	if bytes.Contains(data, net.ParseIP(originalIP).To4()) || bytes.Contains(data, mustMAC(t, originalMAC)) {
		t.Fatal("anonymized frame still contains a binary source address")
	}

	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	if packet.ErrorLayer() != nil {
		t.Fatal(packet.ErrorLayer().Error())
	}
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if got, want := ip.SrcIP.String(), "198.18.0.1"; got != want {
		t.Fatalf("source IP = %q, want %q", got, want)
	}
	if got, want := eth.SrcMAC.String(), "02:00:00:00:00:01"; got != want {
		t.Fatalf("source MAC = %q, want %q", got, want)
	}
	if !bytes.Contains(udp.Payload, []byte(ip.SrcIP.String())) {
		t.Fatalf("payload does not contain mapped source IP %s: %q", ip.SrcIP, udp.Payload)
	}
	if !bytes.Contains(udp.Payload, []byte(eth.SrcMAC.String())) {
		t.Fatalf("payload does not contain mapped source MAC %s: %q", eth.SrcMAC, udp.Payload)
	}
	if !bytes.Contains(udp.Payload, []byte(ip.SrcIP.To4())) || !bytes.Contains(udp.Payload, []byte(eth.SrcMAC)) {
		t.Fatal("binary payload addresses do not match header mappings")
	}
}

func TestFrameAnonymizesPrefixedZlibPayload(t *testing.T) {
	const (
		originalIP  = "172.16.50.29"
		originalMAC = "50:d4:48:4b:08:1b"
	)
	plain := []byte(`{"MAC":"` + originalMAC + `","IPV4":"` + originalIP + `","Gateway":"172.16.50.1"}`)
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 8, 8+compressed.Len())
	copy(payload[4:], []byte{0x20, 0x19, 0x03, 0x14})
	payload = append(payload, compressed.Bytes()...)
	binary.BigEndian.PutUint32(payload[:4], uint32(len(payload)-4))

	anonymized, err := newAddressAnonymizer().frame(testFrameWithPayload(t, originalIP, originalMAC, payload), layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	packet := gopacket.NewPacket(anonymized, layers.LayerTypeEthernet, gopacket.Default)
	udpPayload := packet.Layer(layers.LayerTypeUDP).(*layers.UDP).Payload
	if got, want := binary.BigEndian.Uint32(udpPayload[:4]), uint32(len(udpPayload)-4); got != want {
		t.Fatalf("compressed envelope length = %d, want %d", got, want)
	}
	reader, err := zlib.NewReader(bytes.NewReader(udpPayload[8:]))
	if err != nil {
		t.Fatal(err)
	}
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(decompressed, []byte(originalIP)) || bytes.Contains(decompressed, []byte(originalMAC)) {
		t.Fatalf("decompressed payload retains original addresses: %s", decompressed)
	}
	if !bytes.Contains(decompressed, []byte("198.18.0.1")) || !bytes.Contains(decompressed, []byte("02:00:00:00:00:01")) {
		t.Fatalf("decompressed payload does not use header mappings: %s", decompressed)
	}
}

func TestFramePreservesDuplicatesAndDistinctMappings(t *testing.T) {
	anonymizer := newAddressAnonymizer()
	first := testFrame(t, "192.168.1.10", "aa:bb:cc:dd:ee:10")
	duplicate, err := anonymizer.frame(first, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	again, err := anonymizer.frame(first, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(duplicate, again) {
		t.Fatal("identical source frames produced different anonymized frames")
	}
	second, err := anonymizer.frame(testFrame(t, "192.168.1.11", "aa:bb:cc:dd:ee:11"), layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	firstPacket := gopacket.NewPacket(duplicate, layers.LayerTypeEthernet, gopacket.Default)
	secondPacket := gopacket.NewPacket(second, layers.LayerTypeEthernet, gopacket.Default)
	firstIP := firstPacket.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP
	secondIP := secondPacket.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP
	if firstIP.Equal(secondIP) {
		t.Fatalf("distinct source IPs mapped to the same address %s", firstIP)
	}
}

func TestAnonymizePCAPNGSanitizesInterfaceNames(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source.pcapng")
	destination := filepath.Join(t.TempDir(), "fixture.pcapng")
	file, err := os.Create(source)
	if err != nil {
		t.Fatal(err)
	}
	intf := pcapgo.DefaultNgInterface
	intf.Name = "enp0s31f6-private"
	intf.Description = "Matt's private LAN"
	intf.LinkType = layers.LinkTypeEthernet
	writer, err := pcapgo.NewNgWriterInterface(file, intf, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		t.Fatal(err)
	}
	data := testFrame(t, "10.20.30.40", "aa:bb:cc:dd:ee:40")
	ci := gopacket.CaptureInfo{Timestamp: time.Unix(100, 0), CaptureLength: len(data), Length: len(data)}
	if err := writer.WritePacket(ci, data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	if err := anonymizeCapture(source, destination); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()
	reader, err := pcapgo.NewNgReader(fixture, pcapgo.NgReaderOptions{WantMixedLinkType: true})
	if err != nil {
		t.Fatal(err)
	}
	anonymizedData, anonymizedCI, err := reader.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}
	outputInterface, err := reader.Interface(anonymizedCI.InterfaceIndex)
	if err != nil {
		t.Fatal(err)
	}
	if outputInterface.Name != "interface-1" {
		t.Fatalf("interface name = %q, want interface-1", outputInterface.Name)
	}
	if outputInterface.Description != "" {
		t.Fatalf("interface description was retained: %q", outputInterface.Description)
	}
	if bytes.Contains(anonymizedData, []byte("10.20.30.40")) {
		t.Fatal("fixture retains source IP payload")
	}
	if _, _, err := reader.ReadPacketData(); err != io.EOF {
		t.Fatalf("second packet read = %v, want EOF", err)
	}
}
