package main

import (
	"flag"
	"fmt"
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

// logger
var iprlog = iprd.NewLogger()

// broadcast msg channel
var broadcastCh = make(chan []byte)

func main() {
	// flags
	var flAutoFind bool
	flag.BoolVar(&flAutoFind, "a", false, "switch to toggle to try and auto find interface.")
	var flInterface = flag.String("i", "", "name of network interface to listen on.")
	var flPortConfig flagSlice
	flag.Var(&flPortConfig, "f", "list of UDP ports for BPF filter.")
	var flTCPForwardPort = flag.Int("p", 7788, "tcp port to forward packet data. Default: :7788")
	flag.Parse()

	iprlog.Info("start ipr daemon...")

	if flAutoFind && *flInterface != "" {
		iprlog.Error(fmt.Errorf("argurment error: -i and -a are mutually exclusive"))
		os.Exit(1)
	}

	if !flAutoFind && *flInterface == "" {
		iprlog.Error(fmt.Errorf("argurment error: must include -i or -a"))
		os.Exit(1)
	}

	var iface *iprd.IPRInterface
	if !flAutoFind {
		iface = getInterfaceFromFlag(*flInterface)
	} else {
		iface = autoFindLANInterface()
	}
	if !iface.IsUp() {
		iprlog.Error(fmt.Errorf("interface %s is not marked at up", iface.Name))
		os.Exit(1)
	}
	iprlog.Info(fmt.Sprintf("set interface: %s", iface.Name))

	if flPortConfig == nil {
		flPortConfig = defaultPortConfig
	}
	filter := getBPFFilterFromConfig(flPortConfig)
	iprlog.Info(fmt.Sprintf("set BPF filter: %s", filter))

	broadcaster, err := iprd.NewBroadcaster(*flTCPForwardPort)
	if err != nil {
		iprlog.Fatalln(err)
	}
	go broadcaster.Listen()
	go func() {
		for {
			select {
			case msg := <-broadcastCh:
				broadcaster.Msgs <- msg
			case err := <-broadcaster.Errs:
				iprlog.Error(err)
			}
		}
	}()
	iprlog.Info(fmt.Sprintf("set tcp forwarding -> :%d", *flTCPForwardPort))
	iprlog.Info("successfully started iprd!")

	iprlog.Info("start listen...")
	if err := listen(iface.Name, filter); err != nil {
		iprlog.Error(fmt.Errorf("listen error: %v", err))
		os.Exit(1)
	}
}

func getInterfaceFromFlag(name string) *iprd.IPRInterface {
	iface, err := iprd.GetInterfaceByName(name)
	if err != nil {
		iprlog.Error(err)
		os.Exit(1)
	}
	return iface
}

func autoFindLANInterface() *iprd.IPRInterface {
	iface, err := iprd.FindLANInterface()
	if err != nil {
		iprlog.Error(err)
		os.Exit(1)
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
		ipr, ok := iprd.IsValidIPReportPacket(packet)
		if !ok {
			continue
		}
		iprlog.Info("received IP Report packet.")
		iprlog.Debug(fmt.Sprintf("IP: %s -> %s, MAC: %s -> %s, UDP: %d -> %d",
			ipr.SrcIP, ipr.DstIP,
			ipr.SrcMAC, ipr.DstMAC,
			ipr.SrcPort, ipr.DstPort))
		msg, err := ipr.ToJson()
		if err != nil {
			iprlog.Error(fmt.Errorf("failed to marshal packet to JSON: %v", err))
			continue
		}
		// send msg to be broadcasted
		broadcastCh <- msg
	}
	return nil
}
