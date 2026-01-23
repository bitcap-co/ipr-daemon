package iprd

import (
	"bytes"
	"compress/zlib"
	"io"
	"sync"
	"unicode/utf8"

	"github.com/goccy/go-json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

// IPRReportPacket defines the structure of a IP Report packet.
type IPRReportPacket struct {
	SrcIP    string
	DstIP    string
	SrcMAC   string
	DstMAC   string
	SrcPort  int
	DstPort  int
	Datagram []byte
}

// IPRBroadcastMessage defines the structure of a TCP broadcast message.
type IPRBroadcastMessage struct {
	ID        string `json:"id"`
	IPAddr    string `json:"ip_addr"`
	MACAddr   string `json:"mac_addr"`
	MinerType string `json:"miner_type"`
}

var (
	mutex sync.Mutex

	zlibDefaultMagic = []byte{0x78, 0x9c}
	knownMinerTypes  = map[int]string{
		14235: "bitmain-common",
		11503: "iceriver",
		8888:  "whatsminer",
		1314:  "goldshell",
		18650: "sealminer",
		9999:  "elphapex",
	}
	smHeaderOffset int64 = 8
)

// IsValidIPReportPacket checks if packet is a valid IP Report packet. Returns a IPRReportPacket if valid.
// Ignores packet if datagram is empty.
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
		// check for magic header
		headerBuffer := make([]byte, 2)
		_, err := b.ReadAt(headerBuffer, smHeaderOffset)
		if err != nil {
			return nil, false
		}
		if bytes.Equal(headerBuffer, zlibDefaultMagic) {
			if _, err := b.Seek(smHeaderOffset, io.SeekStart); err != nil {
				return nil, false
			}
			r, err := zlib.NewReader(b)
			if err != nil {
				return nil, false
			}
			defer r.Close()
			data, err = io.ReadAll(r)
			if err != nil {
				return nil, false
			}
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
	}, true
}

// GetMinerType returns known miner type.
func (r *IPRReportPacket) GetMinerType() string {
	minerType, ok := knownMinerTypes[r.DstPort]
	if !ok {
		return "Unknown"
	}
	return minerType
}

// ToJson marshals the IP Report packet data into IPRBroadcastMessage struct.
func (r *IPRReportPacket) ToJson() ([]byte, error) {
	packetID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	jsonObj := IPRBroadcastMessage{
		ID:        packetID.String(),
		IPAddr:    r.SrcIP,
		MACAddr:   r.SrcMAC,
		MinerType: r.GetMinerType(),
	}
	data, err := json.Marshal(jsonObj)
	if err != nil {
		return nil, err
	}
	return data, nil
}
