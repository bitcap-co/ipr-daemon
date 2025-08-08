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
	var (
		flInterface   = flag.String("i", "", "network interface name")
		flFilterPorts flagSlice
	)
	flag.Var(&flFilterPorts, "f", "list of UDP ports for BPF filter")
	flag.Parse()

	iface := get_interface(*flInterface)
	fmt.Printf("%+v\n", *iface)
	if iface.IsUp() {
		fmt.Println("interface is up!")
	}
	if iface.IsLan() {
		fmt.Println("interface is marked LAN.")
	}
	if flFilterPorts == nil {
		flFilterPorts = defaultPortConfig
	}

	bpf := bpf_builder(flFilterPorts)
	if err := listen(iface.Name, bpf); err != nil {
		log.Panicf("Failed to start listening: %v", err)
	}
}

func get_interface(name string) *iprd.IPRInterface {
	if name != "" {
		iface, err := iprd.GetInterfaceByName(name)
		if err != nil {
			log.Panicln(err)
		}
		return iface
	}
	iface, err := iprd.FindLANInterface()
	if err != nil {
		log.Panicln(err)
	}
	return iface
}

func bpf_builder(ports []string) string {
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
