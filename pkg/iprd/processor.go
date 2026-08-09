package iprd

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf8"

	"github.com/gopacket/gopacket"
)

const (
	defaultRecordCapacity       = 10
	zlibSealMinerOffset         = 8
	recordMinAge          int64 = 10_000
)

var (
	// ErrDuplicatePacket indicates that the processor recently handled an IP
	// report from the same source MAC address.
	ErrDuplicatePacket = errors.New("duplicate packet")
	// zlib payload offsets
	zlibOffsets = []int{0, zlibSealMinerOffset}
)

// PacketProcessor validates IP report packets and owns their duplicate record.
// A processor should be shared anywhere duplicate detection must be shared.
// Calls must be serialized because Record is not safe for concurrent use.
type PacketProcessor struct {
	record *Record
}

// NewPacketProcessor returns a processor using record for duplicate detection.
// A default record is created when record is nil.
func NewPacketProcessor(record *Record) *PacketProcessor {
	if record == nil {
		record = NewRecord(defaultRecordCapacity)
	}
	return &PacketProcessor{record: record}
}

// ParseIPReportPacket analyzes packet for a valid IP report packet.
func (p *PacketProcessor) ParseIPReportPacket(packet *IPReportPacket) error {
	if packet == nil {
		return fmt.Errorf("packet must not be nil")
	}

	// retrieve miner hint from DstPort.
	minerHint, ok := MinerPorts[packet.DstPort]
	if ok {
		packet.MinerHint = minerHint
	}
	// check for existing record.
	if p.record.Contains(packet.SrcMAC) {
		ent := p.record.Get(packet.SrcMAC)
		// if record exists and is not over minimum record age, mark as dup packet.
		if time.Now().UnixMilli()-ent.UpdatedAt <= recordMinAge {
			return ErrDuplicatePacket
		}
	}
	// if not valid UTF-8, it could be encoded/compressed.
	if !utf8.Valid(packet.Datagram) {
		// check for start of zlib payload given a list of offsets.
		zlibStart := -1
		for _, offset := range zlibOffsets {
			if offset < len(packet.Datagram) && packet.Datagram[offset] == byte(0x78) {
				zlibStart = offset
				break
			}
		}
		if zlibStart == -1 {
			return fmt.Errorf("failed to decode payload - invalid utf8")
		}
		b := bytes.NewReader(packet.Datagram[zlibStart:])
		r, err := zlib.NewReader(b)
		if err != nil {
			return fmt.Errorf("failed to decompress payload - %w", err)
		}
		defer r.Close()
		packet.Datagram, err = io.ReadAll(r)
		if err != nil {
			return fmt.Errorf("failed to read from zlib reader - %w", err)
		}
	}

	packet.Payload = string(packet.Datagram)
	// ignore packet if it doesn't contain source IP within UDP datagram.
	if !bytes.Contains(packet.Datagram, []byte(packet.SrcIP)) {
		// edge case: elphapex sends static message with no source IP
		if !MsgPatterns[Elphapex].Match(packet.Datagram) {
			return fmt.Errorf("no source IP found in datagram")
		}
	}
	// update record with new packet data.
	p.record.Add(packet.SrcMAC, RecordEntry{
		SrcIP:     packet.SrcIP,
		SrcMAC:    packet.SrcMAC,
		MinerHint: packet.MinerHint,
		CreatedAt: packet.Timestamp.UnixMilli(),
	})
	return nil
}

// CaptureToIPRPacket decodes a captured packet into an IPReportPacket.
func (p *PacketProcessor) CaptureToIPRPacket(captured CapturedPacket) (*IPReportPacket, error) {
	packet := gopacket.NewPacket(captured.Data, captured.LinkType, gopacket.Default)
	packet.Metadata().CaptureInfo = captured.CaptureInfo
	ipr, err := NewIPReportPacket(packet)
	if err != nil {
		return nil, err
	}
	return ipr, nil
}
