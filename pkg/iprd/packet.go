package iprd

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"sync"
	"unicode/utf8"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

type IPRReportPacket struct {
	SrcIP    string
	DstIP    string
	SrcMAC   string
	DstMAC   string
	SrcPort  int
	DstPort  int
	Datagram []byte
}

var mutex sync.Mutex

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

	// check for valid datagram
	if !utf8.Valid(udp.Payload) {
		// sealminer data is compressed with standard zlib compression
		if int(udp.DstPort) == 18650 {
			_, err := zlib.NewReader(bytes.NewReader(udp.Payload))
			if err != nil {
				return nil, false
			}
		} else {
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
		Datagram: udp.Payload,
	}, true
}

type IPRJSONObject struct {
	ID      string `json:"id"`
	IPAddr  string `json:"ip_addr"`
	MACAddr string `json:"mac_addr"`
}

func (r *IPRReportPacket) ToJson() ([]byte, error) {
	packetID, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	jsonObj := IPRJSONObject{
		ID:      packetID.String(),
		IPAddr:  r.SrcIP,
		MACAddr: r.SrcMAC,
	}
	data, err := json.Marshal(jsonObj)
	if err != nil {
		return nil, err
	}
	return data, nil
}
