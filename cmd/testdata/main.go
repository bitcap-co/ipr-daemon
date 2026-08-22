package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

var (
	flPcapFile = flag.String("f", "", "path to a .pcap or .pcapng capture file")

	log = iprd.NewLogger()
)

const maxDecompressedPayloadSize = 64 * 1024 * 1024

var (
	pcapNGMagic      = []byte{0x0a, 0x0d, 0x0d, 0x0a}
	payloadIPv4RE    = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\b`)
	payloadMACRE     = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)
	payloadIPv6Token = regexp.MustCompile(`(?i)\b[0-9a-f:.]*:[0-9a-f:.]+\b`)
)

func main() {
	flag.Parse()

	if *flPcapFile == "" {
		log.Fatal(fmt.Errorf("missing -f <FILE>"))
	}

	fd, err := filepath.Abs(*flPcapFile)
	if err != nil {
		log.Fatal(err)
	}
	if err := publishCapture(fd); err != nil {
		log.Fatal(err)
	}
}

// publishCapture creates an anonymized capture fixture in tests/testdata/captures.
func publishCapture(fd string) error {
	ext := strings.ToLower(filepath.Ext(fd))
	if ext != ".pcap" && ext != ".pcapng" {
		return fmt.Errorf("unsupported capture extension %q", ext)
	}
	root, err := projectRoot()
	if err != nil {
		return err
	}
	destination := filepath.Join(root, "tests", "testdata", "captures", filepath.Base(fd))
	if samePath(fd, destination) {
		return fmt.Errorf("input is already the destination fixture: %s", destination)
	}
	if _, err := os.Stat(destination); err == nil {
		return fmt.Errorf("fixture already exists: %s", destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect destination: %w", err)
	}

	if err := anonymizeCapture(fd, destination); err != nil {
		return err
	}
	log.Info(fmt.Sprintf("created anonymized fixture -> %s", destination))
	return nil
}

func projectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	for {
		data, readErr := os.ReadFile(filepath.Join(dir, "go.mod"))
		if readErr == nil && bytes.Contains(data, []byte("module github.com/bitcap-co/ipr-daemon")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not locate ipr-daemon project root from %s", dir)
		}
		dir = parent
	}
}

func samePath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil && leftAbs == rightAbs
}

func anonymizeCapture(source, destination string) (err error) {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open source capture: %w", err)
	}
	defer input.Close()

	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("create fixture directory: %w", err)
	}
	output, err := os.CreateTemp(filepath.Dir(destination), ".anonymized-*")
	if err != nil {
		return fmt.Errorf("create temporary fixture: %w", err)
	}
	temporary := output.Name()
	defer func() {
		_ = output.Close()
		if err != nil {
			_ = os.Remove(temporary)
		}
	}()

	buffered := bufio.NewReader(input)
	magic, err := buffered.Peek(len(pcapNGMagic))
	if err != nil {
		return fmt.Errorf("read capture header: %w", err)
	}
	anonymizer := newAddressAnonymizer()
	if bytes.Equal(magic, pcapNGMagic) {
		err = anonymizePCAPNG(buffered, output, anonymizer)
	} else {
		err = anonymizePCAP(buffered, output, anonymizer)
	}
	if err != nil {
		return err
	}
	if err := output.Chmod(0o644); err != nil {
		return fmt.Errorf("set fixture permissions: %w", err)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close fixture: %w", err)
	}
	if err := os.Rename(temporary, destination); err != nil {
		return fmt.Errorf("publish fixture: %w", err)
	}
	return nil
}

func anonymizePCAP(reader io.Reader, writer io.Writer, anonymizer *addressAnonymizer) error {
	captureReader, err := pcapgo.NewReader(reader)
	if err != nil {
		return fmt.Errorf("read PCAP header: %w", err)
	}
	captureWriter := pcapgo.NewWriter(writer)
	if err := captureWriter.WriteFileHeader(captureReader.Snaplen(), captureReader.LinkType()); err != nil {
		return fmt.Errorf("write PCAP header: %w", err)
	}
	for packetNumber := 1; ; packetNumber++ {
		data, ci, readErr := captureReader.ReadPacketData()
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("read PCAP packet %d: %w", packetNumber, readErr)
		}
		data, err = anonymizer.frame(data, captureReader.LinkType())
		if err != nil {
			return fmt.Errorf("anonymize PCAP packet %d: %w", packetNumber, err)
		}
		ci.CaptureLength = len(data)
		ci.Length = len(data)
		if err := captureWriter.WritePacket(ci, data); err != nil {
			return fmt.Errorf("write PCAP packet %d: %w", packetNumber, err)
		}
	}
}

func anonymizePCAPNG(reader io.Reader, writer io.Writer, anonymizer *addressAnonymizer) error {
	captureReader, err := pcapgo.NewNgReader(reader, pcapgo.NgReaderOptions{WantMixedLinkType: true})
	if err != nil {
		return fmt.Errorf("read PCAP-NG header: %w", err)
	}
	var captureWriter *pcapgo.NgWriter
	interfaces := make(map[int]int)
	for packetNumber := 1; ; packetNumber++ {
		data, ci, readErr := captureReader.ReadPacketData()
		if errors.Is(readErr, io.EOF) {
			if captureWriter != nil {
				return captureWriter.Flush()
			}
			return fmt.Errorf("capture contains no packets")
		}
		if readErr != nil {
			return fmt.Errorf("read PCAP-NG packet %d: %w", packetNumber, readErr)
		}
		intf, err := captureReader.Interface(ci.InterfaceIndex)
		if err != nil {
			return fmt.Errorf("read PCAP-NG packet %d interface: %w", packetNumber, err)
		}
		outputInterface, ok := interfaces[ci.InterfaceIndex]
		if !ok {
			intf.Name = fmt.Sprintf("interface-%d", len(interfaces)+1)
			intf.Comment = ""
			intf.Description = ""
			intf.Filter = anonymizer.text(intf.Filter)
			intf.OS = ""
			if captureWriter == nil {
				options := pcapgo.NgWriterOptions{SectionInfo: pcapgo.NgSectionInfo{Application: "ipr-daemon test fixture anonymizer"}}
				captureWriter, err = pcapgo.NewNgWriterInterface(writer, intf, options)
				outputInterface = 0
			} else {
				outputInterface, err = captureWriter.AddInterface(intf)
			}
			if err != nil {
				return fmt.Errorf("write anonymized interface: %w", err)
			}
			interfaces[ci.InterfaceIndex] = outputInterface
		}
		data, err = anonymizer.frame(data, intf.LinkType)
		if err != nil {
			return fmt.Errorf("anonymize PCAP-NG packet %d: %w", packetNumber, err)
		}
		ci.InterfaceIndex = outputInterface
		ci.CaptureLength = len(data)
		ci.Length = len(data)
		if err := captureWriter.WritePacket(ci, data); err != nil {
			return fmt.Errorf("write PCAP-NG packet %d: %w", packetNumber, err)
		}
	}
}

type addressAnonymizer struct {
	ips      map[string]net.IP
	macs     map[string]net.HardwareAddr
	nextIPv4 uint32
	nextIPv6 uint64
	nextMAC  uint64
}

func newAddressAnonymizer() *addressAnonymizer {
	return &addressAnonymizer{
		ips:      make(map[string]net.IP),
		macs:     make(map[string]net.HardwareAddr),
		nextIPv4: 1,
		nextIPv6: 1,
		nextMAC:  1,
	}
}

func (a *addressAnonymizer) ip(original net.IP) net.IP {
	if original == nil {
		return nil
	}
	key := original.String()
	if replacement, ok := a.ips[key]; ok {
		return append(net.IP(nil), replacement...)
	}
	var replacement net.IP
	if original4 := original.To4(); original4 != nil {
		value := a.nextIPv4
		a.nextIPv4++
		replacement = net.IPv4(198, byte(18+(value>>16)&1), byte(value>>8), byte(value)).To4()
	} else {
		value := a.nextIPv6
		a.nextIPv6++
		replacement = net.IP{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, byte(value >> 56), byte(value >> 48), byte(value >> 40), byte(value >> 32), byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
	}
	a.ips[key] = append(net.IP(nil), replacement...)
	return replacement
}

func (a *addressAnonymizer) mac(original net.HardwareAddr) net.HardwareAddr {
	if original == nil {
		return nil
	}
	key := strings.ToLower(original.String())
	if replacement, ok := a.macs[key]; ok {
		return append(net.HardwareAddr(nil), replacement...)
	}
	value := a.nextMAC
	a.nextMAC++
	replacement := net.HardwareAddr{0x02, byte(value >> 32), byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
	a.macs[key] = append(net.HardwareAddr(nil), replacement...)
	return replacement
}

func (a *addressAnonymizer) text(value string) string {
	return string(a.plainPayload([]byte(value)))
}

func (a *addressAnonymizer) payload(payload []byte) ([]byte, error) {
	offset := zlibPayloadOffset(payload)
	if offset < 0 {
		return a.plainPayload(payload), nil
	}

	reader, err := zlib.NewReader(bytes.NewReader(payload[offset:]))
	if err != nil {
		return nil, fmt.Errorf("open zlib payload at offset %d: %w", offset, err)
	}
	decompressed, readErr := io.ReadAll(io.LimitReader(reader, maxDecompressedPayloadSize+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		return nil, fmt.Errorf("decompress zlib payload: %w", errors.Join(readErr, closeErr))
	}
	if len(decompressed) > maxDecompressedPayloadSize {
		return nil, fmt.Errorf("decompressed zlib payload exceeds %d bytes", maxDecompressedPayloadSize)
	}

	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	if _, err := writer.Write(a.plainPayload(decompressed)); err != nil {
		return nil, fmt.Errorf("recompress zlib payload: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("finish zlib payload: %w", err)
	}

	result := append([]byte(nil), payload[:offset]...)
	result = append(result, compressed.Bytes()...)
	if offset == 8 && len(payload) >= 4 && binary.BigEndian.Uint32(payload[:4]) == uint32(len(payload)-4) {
		binary.BigEndian.PutUint32(result[:4], uint32(len(result)-4))
	}
	return result, nil
}

func zlibPayloadOffset(payload []byte) int {
	for _, offset := range []int{0, 8} {
		if len(payload) < offset+2 {
			continue
		}
		header := binary.BigEndian.Uint16(payload[offset : offset+2])
		if payload[offset]&0x0f == 8 && header%31 == 0 {
			return offset
		}
	}
	return -1
}

func (a *addressAnonymizer) plainPayload(payload []byte) []byte {
	result := append([]byte(nil), payload...)

	// Discover textual values first so binary occurrences of the same address use
	// the same mapping as packet headers and human-readable payload fields.
	for _, match := range payloadMACRE.FindAll(result, -1) {
		if parsed, err := net.ParseMAC(string(match)); err == nil {
			a.mac(parsed)
		}
	}
	for _, match := range payloadIPv4RE.FindAll(result, -1) {
		a.ip(net.ParseIP(string(match)))
	}
	for _, match := range payloadIPv6Token.FindAll(result, -1) {
		if _, err := net.ParseMAC(string(match)); err == nil {
			continue
		}
		if parsed := net.ParseIP(string(match)); parsed != nil && parsed.To4() == nil {
			a.ip(parsed)
		}
	}

	for original, replacement := range a.macs {
		parsed, err := net.ParseMAC(original)
		if err == nil {
			result = bytes.ReplaceAll(result, []byte(parsed), []byte(replacement))
		}
	}
	for original, replacement := range a.ips {
		parsed := net.ParseIP(original)
		if parsed4 := parsed.To4(); parsed4 != nil {
			result = bytes.ReplaceAll(result, []byte(parsed4), []byte(replacement.To4()))
		} else if parsed != nil {
			result = bytes.ReplaceAll(result, []byte(parsed.To16()), []byte(replacement.To16()))
		}
	}
	result = payloadMACRE.ReplaceAllFunc(result, func(match []byte) []byte {
		parsed, err := net.ParseMAC(string(match))
		if err != nil {
			return match
		}
		return []byte(a.mac(parsed).String())
	})
	result = payloadIPv4RE.ReplaceAllFunc(result, func(match []byte) []byte {
		return []byte(a.ip(net.ParseIP(string(match))).String())
	})
	result = payloadIPv6Token.ReplaceAllFunc(result, func(match []byte) []byte {
		if _, err := net.ParseMAC(string(match)); err == nil {
			return match
		}
		parsed := net.ParseIP(string(match))
		if parsed == nil || parsed.To4() != nil {
			return match
		}
		return []byte(a.ip(parsed).String())
	})
	return result
}

func (a *addressAnonymizer) frame(data []byte, linkType layers.LinkType) ([]byte, error) {
	packet := gopacket.NewPacket(data, linkType, gopacket.DecodeOptions{Lazy: false, NoCopy: false})
	if errLayer := packet.ErrorLayer(); errLayer != nil {
		return nil, fmt.Errorf("decode frame: %v", errLayer.Error())
	}

	var network gopacket.NetworkLayer
	serializable := make([]gopacket.SerializableLayer, 0, len(packet.Layers()))
packetLayers:
	for _, layer := range packet.Layers() {
		var transportPayload []byte
		var payloadErr error
		switch value := layer.(type) {
		case *layers.Ethernet:
			value.SrcMAC = a.mac(value.SrcMAC)
			value.DstMAC = a.mac(value.DstMAC)
		case *layers.ARP:
			if len(value.SourceHwAddress) == 6 {
				value.SourceHwAddress = a.mac(net.HardwareAddr(value.SourceHwAddress))
			}
			if len(value.DstHwAddress) == 6 {
				value.DstHwAddress = a.mac(net.HardwareAddr(value.DstHwAddress))
			}
			if len(value.SourceProtAddress) == net.IPv4len {
				value.SourceProtAddress = a.ip(net.IP(value.SourceProtAddress)).To4()
			}
			if len(value.DstProtAddress) == net.IPv4len {
				value.DstProtAddress = a.ip(net.IP(value.DstProtAddress)).To4()
			}
		case *layers.IPv4:
			value.SrcIP = a.ip(value.SrcIP)
			value.DstIP = a.ip(value.DstIP)
			network = value
		case *layers.IPv6:
			value.SrcIP = a.ip(value.SrcIP)
			value.DstIP = a.ip(value.DstIP)
			network = value
		case *layers.UDP:
			if network == nil {
				return nil, fmt.Errorf("UDP layer has no decoded network layer")
			}
			if err := value.SetNetworkLayerForChecksum(network); err != nil {
				return nil, fmt.Errorf("configure UDP checksum: %w", err)
			}
			transportPayload, payloadErr = a.payload(value.Payload)
		case *layers.TCP:
			if network == nil {
				return nil, fmt.Errorf("TCP layer has no decoded network layer")
			}
			if err := value.SetNetworkLayerForChecksum(network); err != nil {
				return nil, fmt.Errorf("configure TCP checksum: %w", err)
			}
			transportPayload, payloadErr = a.payload(value.Payload)
		case gopacket.Payload:
			var anonymized []byte
			anonymized, payloadErr = a.payload([]byte(value))
			layer = gopacket.Payload(anonymized)
		case *gopacket.Payload:
			var anonymized []byte
			anonymized, payloadErr = a.payload([]byte(*value))
			layer = gopacket.Payload(anonymized)
		}
		if payloadErr != nil {
			return nil, payloadErr
		}
		serialized, ok := layer.(gopacket.SerializableLayer)
		if !ok {
			return nil, fmt.Errorf("unsupported decoded layer %s", layer.LayerType())
		}
		serializable = append(serializable, serialized)
		if transportPayload != nil {
			serializable = append(serializable, gopacket.Payload(transportPayload))
			break packetLayers
		}
	}
	if len(serializable) == 0 {
		return nil, fmt.Errorf("frame has no serializable layers")
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, serializable...); err != nil {
		return nil, fmt.Errorf("serialize frame: %w", err)
	}
	return append([]byte(nil), buffer.Bytes()...), nil
}
