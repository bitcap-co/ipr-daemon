package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	iprlog      = iprd.NewLogger()
	broadcastCh = make(chan []byte)
)

func main() {
	// flags
	var flAutoFind bool
	flag.BoolVar(&flAutoFind, "a", false, "switch to toggle to try and auto find interface.")
	var flInterface = flag.String("i", "", "name of network interface to listen on.")
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

	bpf := fmt.Sprintf("src host %s and (dst net 255 or dst net %s) and udp dst portrange 1024-49151", iface.LocalNet(), iface.LocalNet())
	iprlog.Info(fmt.Sprintf("set BPF filter: %s", bpf))

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
	if err := listen(iface.Name, bpf); err != nil {
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
