package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type flagSlice []string

func (f *flagSlice) String() string {
	return fmt.Sprintf("%v", *f)
}

func (f *flagSlice) Set(value string) error {
	*f = append(*f, value)
	return nil
}

var defaultPortConfig = []string{
	"14235", // bitmain-common
	"11503", // iceriver
	"8888",  // whatsminer
	"18650", // sealminer
	"1314",  // goldshell
	"9999",  // elphapex
}

func main() {
	// flags
	var flInterface = flag.String("i", "", "name of network interface to listen on.")
	var flFilterPorts flagSlice
	flag.Var(&flFilterPorts, "f", "list of UDP ports for BPF filter.")
	flag.Parse()

	iface := getInterfaceFromFlag(*flInterface)
	fmt.Printf("Found %s interface...\n", iface.Name)
	if !iface.IsUp() {
		log.Panicf("interface %s is not marked as up\n", iface.Name)
	}

	if flFilterPorts == nil {
		flFilterPorts = defaultPortConfig
	}
	filter := getBPFFilterFromPorts(flFilterPorts)

	if err := listen(iface.Name, filter); err != nil {
		log.Panicf("Failed to start listening: %v", err)
	}
}

func getInterfaceFromFlag(name string) *iprd.IPRInterface {
	if name != "" {
		if iface, err := iprd.GetInterfaceByName(name); err == nil {
			return iface
		}
	}
	// Try and find interface marked as LAN
	iface, err := iprd.FindLANInterface()
	if err != nil {
		log.Panicln(err)
	}
	return iface
}

func getBPFFilterFromPorts(ports []string) string {
	var filter strings.Builder
	for _, port := range ports {
		sep := "or"
		if ports[len(ports)-1] == port {
			sep = ""
		}
		filter.WriteString(fmt.Sprintf("udp port %s %s ", port, sep))
	}
	return filter.String()
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
