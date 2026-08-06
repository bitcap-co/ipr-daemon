package iprd

import (
	"fmt"
	"time"

	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// CapturedPacket is a raw packet and the interface metadata associated with its
// capture. The listener emits these events without parsing their contents.
type CapturedPacket struct {
	Data        []byte
	CaptureInfo gopacket.CaptureInfo
	LinkType    layers.LinkType
	Interface   IPRInterface
}

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
