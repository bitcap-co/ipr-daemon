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
	var filter string = "udp port 14235"
	if err := listen(iface.Name, filter); err != nil {
		log.Panicf("Failed to start listening: %v", err)
	}
}

func listen(iface, filter string) error {
	handle, err := pcap.OpenLive(iface, int32(1600), true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open handle for interface %s", iface)
	}
	defer handle.Close()
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return fmt.Errorf("failed to set BPF filter.")
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		ipReport := iprd.HandlePacket(packet)
		if ipReport == nil {
			continue
		}
		fmt.Println("received IP Report packet.")
		fmt.Printf("IP: %s -> %s, MAC: %s -> %s, UDP: %d -> %d\n",
			ipReport.SrcIP, ipReport.DstIP,
			ipReport.SrcMAC, ipReport.DstMAC,
			ipReport.SrcPort, ipReport.DstPort)
	}
	return nil
}
