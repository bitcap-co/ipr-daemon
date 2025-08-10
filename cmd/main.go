package main

import (
	"flag"
	"fmt"
	"log"
	"os"
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

var iprlog = log.New(os.Stdout, "iprd: ", log.LstdFlags)

func main() {
	// flags
	var flAutoFind bool
	flag.BoolVar(&flAutoFind, "a", false, "switch to toggle to try and auto find interface.")
	var flInterface = flag.String("i", "", "name of network interface to listen on.")
	var flPortConfig flagSlice
	flag.Var(&flPortConfig, "f", "list of UDP ports for BPF filter.")
	flag.Parse()

	iprlog.Println("start ipr daemon...")

	if flAutoFind && *flInterface != "" {
		iprlog.Fatalln("error: -a and -i are mutually exclusive")
	}

	if !flAutoFind && *flInterface == "" {
		iprlog.Fatalln("error: must specify interface name.")
	}

	var iface *iprd.IPRInterface
	if !flAutoFind {
		iface = getInterfaceFromFlag(*flInterface)
	} else {
		iface = autoFindLANInterface()
	}
	iprlog.Printf("set interface: %s", iface.Name)
	if !iface.IsUp() {
		iprlog.Fatalf("interface %s is not marked as up\n", iface.Name)
	}

	iprlog.Println("get port config.")
	if flPortConfig == nil {
		flPortConfig = defaultPortConfig
	}
	filter := getBPFFilterFromConfig(flPortConfig)
	iprlog.Printf("set BPF filter: %s", filter)

	iprlog.Println("start listen...")
	if err := listen(iface.Name, filter); err != nil {
		iprlog.Fatalf("Failed to start listening: %v", err)
	}
}

func getInterfaceFromFlag(name string) *iprd.IPRInterface {
	iface, err := iprd.GetInterfaceByName(name)
	if err != nil {
		iprlog.Fatalln(err)
	}
	return iface
}

func autoFindLANInterface() *iprd.IPRInterface {
	iface, err := iprd.FindLANInterface()
	if err != nil {
		iprlog.Fatalln(err)
	}
	return iface
}

func getBPFFilterFromConfig(ports []string) string {
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
		ipReport := iprd.GetIPRReportPacket(packet)
		if ipReport == nil {
			continue
		}
		iprlog.Println("received IP Report packet.")
		iprlog.Printf("IP: %s -> %s, MAC: %s -> %s, UDP: %d -> %d\n",
			ipReport.SrcIP, ipReport.DstIP,
			ipReport.SrcMAC, ipReport.DstMAC,
			ipReport.SrcPort, ipReport.DstPort)
	}
	return nil
}
