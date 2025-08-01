package iprd

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

func HandlePacket(packet gopacket.Packet) *IPRReportPacket {
	mutex.Lock()
	defer mutex.Unlock()

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil
	}
	eth, _ := ethLayer.(*layers.Ethernet)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	ip, _ := ipLayer.(*layers.IPv4)

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil
	}
	udp, _ := udpLayer.(*layers.UDP)

	// Check for empty datagram/payload
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return nil
	}
	payload := appLayer.Payload()

	return &IPRReportPacket{
		SrcIP:    ip.SrcIP.String(),
		DstIP:    ip.DstIP.String(),
		SrcMAC:   eth.SrcMAC.String(),
		DstMAC:   eth.DstMAC.String(),
		SrcPort:  int(udp.SrcPort),
		DstPort:  int(udp.DstPort),
		Datagram: payload,
	}
}
