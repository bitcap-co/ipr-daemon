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
	recordMinAge          int64 = 10_000

	zlibSealMinerOffset int = 8
)

var (
	// ErrDuplicatePacket indicates that the processor recently handled an IP
	// report from the same source MAC address.
	ErrDuplicatePacket = errors.New("duplicate packet")
	errNoSourceIP      = errors.New("no source IP found in datagram")

	// known zlib paylaod offsets
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

// ToIPRPacket decodes a captured packet into an IPReportPacket.
func (p *PacketProcessor) ToIPRPacket(captured CapturedPacket) (*IPReportPacket, error) {
	packet := gopacket.NewPacket(captured.Data, captured.LinkType, gopacket.Default)
	packet.Metadata().CaptureInfo = captured.CaptureInfo

	iprPacket, err := NewIPReportPacket(packet)
	if err != nil {
		return nil, err
	}
	return iprPacket, nil
}

// IsDuplicate returns true if the packet is a duplicate based on the processor's record.
// A packet is considered a duplicate if it has the same source MAC as an existing record entry and is within the record's minimum age.
// After the record's minimum age (10 seconds), the packet is no longer considered a duplicate and can be reported again.
func (p *PacketProcessor) IsDuplicate(packet *IPReportPacket) bool {
	return p.isDuplicateAt(packet, time.Now())
}

func (p *PacketProcessor) isDuplicateAt(packet *IPReportPacket, observedAt time.Time) bool {
	if p.record.Length() == 0 {
		return false
	}
	key := packet.SrcMAC
	if ent, ok := p.record.Get(key); ok {
		if observedAt.UnixMilli()-ent.UpdatedAt <= recordMinAge {
			return true
		}
	}
	return false
}

// ParseIPReportPacket analyzes packet for a valid IP report packet. Returns an error if the packet is invalid or a duplicate.
func (p *PacketProcessor) ParseIPReportPacket(packet *IPReportPacket) error {
	return p.parseIPReportPacketAt(packet, time.Now())
}

func (p *PacketProcessor) parseIPReportPacketAt(packet *IPReportPacket, observedAt time.Time) error {
	if packet == nil {
		return fmt.Errorf("packet must not be nil")
	}

	// retrieve miner hint from destination port
	if minerHint, ok := GetMinerHintFromPort(packet.DstPort); ok {
		packet.MinerHint = minerHint
	}

	// throw error if duplicate packet
	if p.isDuplicateAt(packet, observedAt) {
		return ErrDuplicatePacket
	}

	// check UDP payload for encoding/compression
	if !utf8.Valid(packet.Datagram) {
		// payload is not valid UTF-8, check for start of zlib payload given a list of known offsets
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
			return fmt.Errorf("zlib read - %w", err)
		}
	}

	packet.Payload = string(packet.Datagram)
	// Ignore packets that don't contain their source IP
	if !bytes.Contains(packet.Datagram, []byte(packet.SrcIP)) {
		// edge case: Elphapex sends static IP report payload without source IP
		pattern, ok := GetMsgPatternFromHint(Elphapex)
		if packet.MinerHint != Elphapex || !ok || !pattern.Match(packet.Datagram) {
			return errNoSourceIP
		}
	}
	// update record with new IP report entry
	p.record.addAt(packet.SrcMAC, RecordEntry{
		SrcIP:     packet.SrcIP,
		SrcMAC:    packet.SrcMAC,
		MinerHint: packet.MinerHint,
		CreatedAt: packet.Timestamp.UnixMilli(),
	}, observedAt)
	return nil
}
