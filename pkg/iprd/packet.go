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
	zlibSealMinerOffset int = 8
)

var (
	zlibOffsets = []int{0, zlibSealMinerOffset}
	minerPorts  = map[int]MinerTypeHint{
		14235: BitmainCommon,
		11503: Iceriver,
		8888:  Whatsminer,
		1314:  Goldshell,
		18650: Sealminer,
		9999:  Elphapex,
	}
)

// IPRBroadcastMessage describes a TCP JSON message for broadcasting.
type IPRBroadcastMessage struct {
	PacketID  string        `json:"id"`
	SrcIP     string        `json:"src_ip"`
	SrcMAC    string        `json:"src_mac"`
	MinerType MinerTypeHint `json:"miner_type"`
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
	MinerType      MinerTypeHint
	Datagram       []byte
	Payload        string
}

// ToBroadcastMessage returns the IPRReportPacket data marshalled into IPRBroadcastMessage.
func (r *IPRReportPacket) ToBroadcastMessage() ([]byte, error) {
	packetID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	broadcastData := IPRBroadcastMessage{
		PacketID:  packetID.String(),
		SrcIP:     r.SrcIP,
		SrcMAC:    r.SrcMAC,
		MinerType: r.MinerType,
	}
	msg, err := json.Marshal(broadcastData)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// ParseIPReportPacket returns IPRReportPacket if packet is a IP Report packet.
func ParseIPReportPacket(packet gopacket.Packet) (*IPRReportPacket, error) {
	// decode layers
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil, fmt.Errorf("invalid layer: Ethernet")
	}
	eth, _ := ethLayer.(*layers.Ethernet)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil, fmt.Errorf("invalid layer: IPv4")
	}
	ip, _ := ipLayer.(*layers.IPv4)

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil, fmt.Errorf("invalid layer: UDP")
	}
	udp, _ := udpLayer.(*layers.UDP)

	// Check for empty datagram/paylaod
	if len(udp.Payload) == 0 {
		return nil, fmt.Errorf("empty UDP payload")
	}

	// check for valid datagram
	if !utf8.Valid(udp.Payload) {
		// look for start of zlib payload
		var zlibStart int
		zlibStart = -1
		for _, offset := range zlibOffsets {
			if offset <= len(udp.Payload) {
				if udp.Payload[offset] == byte(0x78) {
					zlibStart = offset
					break
				}
			}
		}
		if zlibStart == -1 {
			return nil, fmt.Errorf("failed to decode payload - invalid utf8.")
		}
		b := bytes.NewReader(udp.Payload[zlibStart:])
		r, err := zlib.NewReader(b)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress payload - %v", err)
		}
		defer r.Close()
		udp.Payload, err = io.ReadAll(r)
		if err != nil {
			return nil, err
		}
	}

	if !bytes.Contains(udp.Payload, []byte(ip.SrcIP.String())) {
		if !MsgPatterns["DG"].Match(udp.Payload) {
			return nil, fmt.Errorf("no source IP found")
		}
	}

	// try and retreive miner type
	minerType, ok := minerPorts[int(udp.DstPort)]
	if !ok {
		minerType = UnknownType
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
		MinerType:      minerType,
		Datagram:       udp.Payload,
		Payload:        string(udp.Payload),
	}, nil
}
