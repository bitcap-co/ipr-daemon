package iprd

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"time"
	"unicode/utf8"

	"github.com/goccy/go-json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

const (
	zlibSealMinerOffset int   = 8
	recordMinAge        int64 = 10_000
)

var (
	zlibOffsets = []int{0, zlibSealMinerOffset}
	minerPorts  = map[int]MinerTypeHint{
		14235: Antminer, // Assume antminer but could be a multitude of miner types (i.e. Volcminer, Hammer)
		11503: Iceriver,
		8888:  Whatsminer,
		1314:  Goldshell,
		18650: Sealminer,
		9999:  Elphapex,
		12345: Auradine,
	}
	record = NewRecord(10)
)

// IPRBroadcastMessage describes the JSON message structure of a IPReportPacket.
type IPRBroadcastMessage struct {
	Timestamp int64         `json:"timestamp"`
	PacketID  string        `json:"packetID"`
	DstPort   int           `json:"dstPort"`
	SrcIP     string        `json:"srcIP"`
	SrcMAC    string        `json:"srcMAC"`
	MinerHint MinerTypeHint `json:"minerHint"`
}

// IPReportPacket represents a IP Report packet.
type IPReportPacket struct {
	Timestamp      time.Time
	Length         int
	CaptureLength  int
	InterfaceIndex int
	SrcIP          string
	DstIP          string
	SrcMAC         string
	DstMAC         string
	SrcPort        int
	DstPort        int
	Datagram       []byte
	Payload        string
	MinerHint      MinerTypeHint
}

// String returns relevent IPReportPacket info as a string.
func (r IPReportPacket) String() string {
	return fmt.Sprintf("[IP: %s -> %s, MAC: %s -> %s, UDP: %d -> %d, Len: %d, Hint: %s]",
		r.SrcIP, r.DstIP,
		r.SrcMAC, r.DstMAC,
		r.SrcPort, r.DstPort,
		r.CaptureLength, r.MinerHint)
}

// Marshal returns the IPReportPacket data to marshalled IPRBroadcastMessage.
func (r *IPReportPacket) Marshal() ([]byte, error) {
	packetID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	broadcastData := IPRBroadcastMessage{
		Timestamp: r.Timestamp.UnixMilli(),
		PacketID:  packetID.String(),
		DstPort:   r.DstPort,
		SrcIP:     r.SrcIP,
		SrcMAC:    r.SrcMAC,
		MinerHint: r.MinerHint,
	}
	msg, err := json.Marshal(broadcastData)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// NewIPReportPacket initializes packet into IPReportPacket. Returns an error on failure.
func NewIPReportPacket(packet gopacket.Packet) (*IPReportPacket, error) {
	// decode packet layers.
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil, fmt.Errorf("invalid layer - Ethernet")
	}
	eth := ethLayer.(*layers.Ethernet)

	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return nil, fmt.Errorf("invalid layer - IPv4")
	}
	ip := ip4Layer.(*layers.IPv4)

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil, fmt.Errorf("invalid layer - UDP")
	}
	udp := udpLayer.(*layers.UDP)

	// ignore if UDP payload is empty.
	if len(udp.Payload) == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	return &IPReportPacket{
		Timestamp:      packet.Metadata().Timestamp,
		Length:         packet.Metadata().Length,
		CaptureLength:  packet.Metadata().CaptureLength,
		InterfaceIndex: packet.Metadata().InterfaceIndex,
		SrcIP:          ip.SrcIP.String(),
		DstIP:          ip.DstIP.String(),
		SrcMAC:         eth.SrcMAC.String(),
		DstMAC:         eth.DstMAC.String(),
		SrcPort:        int(udp.SrcPort),
		DstPort:        int(udp.DstPort),
		Datagram:       udp.Payload,
		MinerHint:      UnknownType,
	}, nil
}

// ParseIPReportPacket analyzes packet for valid IP Report packet. Returns an error on failure.
func ParseIPReportPacket(packet *IPReportPacket) error {
	// retrieve miner hint from DstPort.
	minerHint, ok := minerPorts[packet.DstPort]
	if ok {
		packet.MinerHint = minerHint
	}
	// check for existing record.
	if record.Contains(packet.SrcIP) {
		ent := record.Get(packet.SrcIP)
		if ent.SrcMAC == packet.SrcMAC && ent.MinerHint == packet.MinerHint {
			// if record exists and is not over minimun record age, mark as duplicate packet.
			if time.Now().UnixMilli()-ent.UpdatedAt <= recordMinAge {
				return fmt.Errorf("duplicate packet")
			}
		}
	}
	// if not valid UTF-8, it could be encoded/compressed.
	if !utf8.Valid(packet.Datagram) {
		// check for start of zlib payload given a list of offsets.
		var zlibStart int
		zlibStart = -1
		for _, offset := range zlibOffsets {
			if offset < len(packet.Datagram) {
				if packet.Datagram[offset] == byte(0x78) {
					zlibStart = offset
					break
				}
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
		// edge case for Elphapex: it sends a static message that doesn't contain source IP.
		if !MsgPatterns["DG"].Match(packet.Datagram) {
			return fmt.Errorf("no source IP found in datagram")
		}
	}
	// update record with new packet data.
	record.Add(packet.SrcIP, RecordEntry{
		SrcIP:     packet.SrcIP,
		SrcMAC:    packet.SrcMAC,
		MinerHint: packet.MinerHint,
		CreatedAt: packet.Timestamp.UnixMilli()})
	return nil
}
