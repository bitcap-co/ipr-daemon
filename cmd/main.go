package main

import (
	"fmt"
	"log"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	iface, err := iprd.FindLANInterface()
	if err != nil {
		log.Panicln(err)
	}
	fmt.Printf("%+v\n", *iface)
	if iface.IsUp() {
		fmt.Println("interface is up!")
	}
	if iface.IsLan() {
		fmt.Println("interface is marked LAN.")
	}

	handle, err := pcap.OpenLive(iface.Name, int32(1600), true, pcap.BlockForever)
	if err != nil {
		log.Panicln(err)
	}
	defer handle.Close()
	var filter string = "udp port 14235"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Panicln(err)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		ipreport := iprd.HandlePacket(packet)
		if ipreport == nil {
			continue
		}
		fmt.Println("received IP Report packet.")
		fmt.Printf("IP: %s -> %s, MAC: %s -> %s, UDP: %d -> %d\n",
			ipreport.SrcIP, ipreport.DstIP,
			ipreport.SrcMAC, ipreport.DstMAC,
			ipreport.SrcPort, ipreport.DstPort)
	}
}
