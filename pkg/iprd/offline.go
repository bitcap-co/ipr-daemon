package iprd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

var pcapNGMagic = []byte{0x0a, 0x0d, 0x0d, 0x0a}

// OfflineResult summarizes the packets processed from an offline capture.
type OfflineResult struct {
	Processed  int
	Reports    int
	Invalid    int
	Duplicates int
}

// OfflinePacketResult describes the outcome of processing one captured frame.
// Report is nil when the frame could not be decoded as an IP report packet.
type OfflinePacketResult struct {
	Number        int64
	InterfaceName string
	Packet        gopacket.Packet
	Report        *IPReportPacket
	Err           error
}

// OfflineHandler handles the result of processing one captured frame.
type OfflineHandler func(OfflinePacketResult) error

// ProcessCapture reads a classic PCAP or PCAP-NG stream and invokes handler for
// every captured frame. Packet decoding and duplicate detection use the same
// PacketProcessor behavior as live capture processing.
func ProcessCapture(ctx context.Context, reader io.Reader, handler OfflineHandler) (OfflineResult, error) {
	if ctx == nil {
		return OfflineResult{}, fmt.Errorf("context must not be nil")
	}
	if reader == nil {
		return OfflineResult{}, fmt.Errorf("reader must not be nil")
	}
	if handler == nil {
		return OfflineResult{}, fmt.Errorf("handler must not be nil")
	}

	buffered := bufio.NewReader(reader)
	magic, err := buffered.Peek(len(pcapNGMagic))
	if err != nil {
		return OfflineResult{}, fmt.Errorf("read capture header: %w", err)
	}

	processor := NewPacketProcessor(nil)
	if bytes.Equal(magic, pcapNGMagic) {
		return processPCAPNG(ctx, buffered, processor, handler)
	}
	return processClassicPCAP(ctx, buffered, processor, handler)
}

func processClassicPCAP(ctx context.Context, reader io.Reader, processor *PacketProcessor, handler OfflineHandler) (OfflineResult, error) {
	pcapReader, err := pcapgo.NewReader(reader)
	if err != nil {
		return OfflineResult{}, fmt.Errorf("read classic PCAP header: %w", err)
	}

	var result OfflineResult
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		data, ci, err := pcapReader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			return result, nil
		}
		if err != nil {
			return result, fmt.Errorf("read classic PCAP packet: %w", err)
		}
		if err := processOfflineFrame(data, ci, pcapReader.LinkType(), "classic", processor, handler, &result); err != nil {
			return result, err
		}
	}
}

func processPCAPNG(ctx context.Context, reader io.Reader, processor *PacketProcessor, handler OfflineHandler) (OfflineResult, error) {
	pcapReader, err := pcapgo.NewNgReader(reader, pcapgo.NgReaderOptions{WantMixedLinkType: true})
	if err != nil {
		return OfflineResult{}, fmt.Errorf("read PCAP-NG header: %w", err)
	}

	var result OfflineResult
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		data, ci, err := pcapReader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			return result, nil
		}
		if err != nil {
			return result, fmt.Errorf("read PCAP-NG packet: %w", err)
		}

		intf, err := pcapReader.Interface(ci.InterfaceIndex)
		if err != nil {
			return result, fmt.Errorf("read PCAP-NG interface %d: %w", ci.InterfaceIndex, err)
		}
		interfaceName := intf.Name
		if interfaceName == "" {
			interfaceName = fmt.Sprintf("#%d", ci.InterfaceIndex)
		}
		linkType := intf.LinkType
		if len(ci.AncillaryData) > 0 {
			if capturedLinkType, ok := ci.AncillaryData[0].(layers.LinkType); ok {
				linkType = capturedLinkType
			}
		}
		if err := processOfflineFrame(data, ci, linkType, interfaceName, processor, handler, &result); err != nil {
			return result, err
		}
	}
}

func processOfflineFrame(data []byte, ci gopacket.CaptureInfo, linkType layers.LinkType, interfaceName string, processor *PacketProcessor, handler OfflineHandler, result *OfflineResult) error {
	result.Processed++
	packet := gopacket.NewPacket(data, linkType, gopacket.Default)
	packet.Metadata().CaptureInfo = ci
	event := OfflinePacketResult{
		Number:        int64(result.Processed),
		InterfaceName: interfaceName,
		Packet:        packet,
	}

	report, err := NewIPReportPacket(packet)
	if err == nil {
		report.InterfaceName = interfaceName
		event.Report = report
		err = processor.ParseIPReportPacket(report)
	}
	event.Err = err

	switch {
	case err == nil:
		result.Reports++
	case errors.Is(err, ErrDuplicatePacket):
		result.Duplicates++
	default:
		result.Invalid++
	}

	if err := handler(event); err != nil {
		return fmt.Errorf("handle capture packet %d: %w", event.Number, err)
	}
	return nil
}
