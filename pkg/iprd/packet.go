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
		14235: Antminer,
		11503: Iceriver,
		8888:  Whatsminer,
		1314:  Goldshell,
		18650: Sealminer,
		9999:  Elphapex,
	}
	record = NewRecord(10)
)

// IPRBroadcastMessage describes a TCP JSON message for broadcasting.
type IPRBroadcastMessage struct {
	Timestamp int64         `json:"timestamp"`
	PacketID  string        `json:"packetID"`
	DstPort   int           `json:"dstPort"`
	SrcIP     string        `json:"srcIP"`
	SrcMAC    string        `json:"srcMAC"`
	MinerHint MinerTypeHint `json:"minerHint"`
}

// IPRReportPacket describes the structure of a IP Report packet.
type IPRReportPacket struct {
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

func (r IPRReportPacket) String() string {
	return fmt.Sprintf("[IP: %s -> %s, MAC: %s -> %s, UDP: %d -> %d, Len: %d, Hint: %s]",
		r.SrcIP, r.DstIP,
		r.SrcMAC, r.DstMAC,
		r.SrcPort, r.DstPort,
		r.CaptureLength, r.MinerHint)
}

// Marshall returns the IPRReportPacket data marshalled into IPRBroadcastMessage.
func (r *IPRReportPacket) Marshall() ([]byte, error) {
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

// NewIPRReportPacket initializes packet as IPRReportPacket if able to decode.
func NewIPRReportPacket(packet gopacket.Packet) (*IPRReportPacket, error) {
	// decode layers
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

	// check for empty payload
	if len(udp.Payload) == 0 {
		return nil, fmt.Errorf("empty payload")
	}

	return &IPRReportPacket{
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

// ParseIPRReportPacket returns nil if packet is a valid IPRReportPacket, otherwise error.
func ParseIPRReportPacket(packet *IPRReportPacket) error {
	// try and retreive miner hint
	minerHint, ok := minerPorts[packet.DstPort]
	if ok {
		packet.MinerHint = minerHint
	}

	// check if packet is duplicate
	if record.Contains(packet.SrcIP) {
		ent := record.Get(packet.SrcIP)
		if ent.SrcMAC == packet.SrcMAC && ent.MinerHint == packet.MinerHint {
			// match found, check record age
			if time.Now().UnixMilli()-ent.UpdatedAt <= recordMinAge {
				return fmt.Errorf("duplicate packet")
			}
		}
	}

	// start datagram analysis
	if !utf8.Valid(packet.Datagram) {
		// look for start of zlib payload
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
	if !bytes.Contains(packet.Datagram, []byte(packet.SrcIP)) {
		// elphapex doesn't contain source IP
		if !MsgPatterns["DG"].Match(packet.Datagram) {
			return fmt.Errorf("no source IP found in datagram")
		}
	}
	// update record
	record.Add(packet.SrcIP, RecordEntry{
		SrcIP:     packet.SrcIP,
		SrcMAC:    packet.SrcMAC,
		MinerHint: packet.MinerHint,
		CreatedAt: packet.Timestamp.UnixMilli()})
	return nil
}
