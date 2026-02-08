package iprd

import (
	"bytes"
	"compress/zlib"
	"io"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/goccy/go-json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

var (
	mutex sync.Mutex

	minerPorts = map[int]MinerTypeHint{
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
	SrcIP    string
	DstIP    string
	SrcMAC   string
	DstMAC   string
	SrcPort  int
	DstPort  int
	Datagram []byte
	Metadata *gopacket.PacketMetadata
}

// Timestamp exposes timestamp of IPRReportPacket Metadata.
func (r *IPRReportPacket) Timestamp() time.Time {
	return r.Metadata.Timestamp
}

// CaptureLength exposes the capture length of IPRReportPacket Metadata.
func (r *IPRReportPacket) CaptureLength() int {
	return r.Metadata.CaptureLength
}

// Length exposes the length of IPRReportPacket Metadata.
func (r *IPRReportPacket) Length() int {
	return r.Metadata.Length
}

// InterfaceIndex exposes the interface index of IPRReportPacket Metadata.
func (r *IPRReportPacket) InterfaceIndex() int {
	return r.Metadata.InterfaceIndex
}

// Payload returns Datagram as string.
func (r *IPRReportPacket) Payload() string {
	return string(r.Datagram)
}

// MinerType returns MinerTypeHint based off of DstPort.
func (r *IPRReportPacket) MinerType() MinerTypeHint {
	hint, ok := minerPorts[r.DstPort]
	if !ok {
		return UnknownType
	}
	return hint
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
		MinerType: r.MinerType(),
	}
	msg, err := json.Marshal(broadcastData)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// IsValidIPReportPacket returns IPRReportPacket if packet is a valid IP Report packet.
func IsValidIPReportPacket(packet gopacket.Packet) (*IPRReportPacket, bool) {
	mutex.Lock()
	defer mutex.Unlock()

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil, false
	}
	eth, _ := ethLayer.(*layers.Ethernet)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil, false
	}
	ip, _ := ipLayer.(*layers.IPv4)

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil, false
	}
	udp, _ := udpLayer.(*layers.UDP)

	// Check for empty datagram/paylaod
	if len(udp.Payload) == 0 {
		return nil, false
	}

	data := bytes.Clone(udp.Payload)
	b := bytes.NewReader(data)

	// check for valid datagram
	if !utf8.Valid(data) {
		r, err := zlib.NewReader(b)
		if err != nil {
			if err == zlib.ErrHeader {
				// try finding at static offsets
				// sealminer
				if matchHeaderAtOffset(b, smHeaderOffset) {
					r, _ = zlibReaderAtOffset(b, smHeaderOffset)
				}
			}
		}
		if r == nil {
			return nil, false
		}
		defer r.Close()
		data, err = io.ReadAll(r)
		if err != nil {
			return nil, false
		}
	}
	if !bytes.Contains(data, []byte(ip.SrcIP.String())) {
		if !MsgPatterns["DG"].Match(data) {
			return nil, false
		}
	}

	return &IPRReportPacket{
		SrcIP:    ip.SrcIP.String(),
		DstIP:    ip.DstIP.String(),
		SrcMAC:   eth.SrcMAC.String(),
		DstMAC:   eth.DstMAC.String(),
		SrcPort:  int(udp.SrcPort),
		DstPort:  int(udp.DstPort),
		Datagram: data,
		Metadata: packet.Metadata(),
	}, true
}
