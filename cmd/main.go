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
	iprl = iprd.NewIPRDLogger()

	// flags
	flDebug     = flag.Bool("d", false, "enable debug packet logging")
	flInterface = flag.String("i", "eth0", "interface name for listening")
	flAuto      = flag.Bool("a", false, "use the defined LAN interface on system for listening. overrides -i")
	flPort      = flag.Int("p", 7788, "forward port for tcp broadcasting. default :7788")

	broadcastCh = make(chan []byte)
)

func main() {
	iprl.Info("start IP Reporter daemon...")
	flag.Parse()

	// get interface from flags
	var iface *iprd.IPRInterface
	if *flAuto {
		iface = autoFindLANInterface()
	} else {
		iface = getInterfaceFromFlag(*flInterface)
	}
	if !iface.IsUp() {
		exitWithError(fmt.Errorf("interface %s is not marked as up", iface.FriendlyName))
	}
	iprl.Info(fmt.Sprintf("set interface: %s (%s)", iface.FriendlyName, iface.MACAddr()))

	// generate bpf expression
	bpfExpr := fmt.Sprintf(
		"src host %s and (dst net 255 or dst net %s) and udp src portrange 1024-65535 and udp dst portrange 1024-49151",
		iface.NetworkPrefix(),
		iface.NetworkPrefix())
	iprl.Info(fmt.Sprintf("set BPF filter expression: %s", bpfExpr))

	// create live handle
	handle, err := pcap.OpenLive(iface.Name, int32(1600), true, pcap.BlockForever)
	if err != nil {
		exitWithError(fmt.Errorf("failed to create handle on %s: %w", iface.FriendlyName, err))
	}

	if err := handle.SetBPFFilter(bpfExpr); err != nil {
		exitWithError(fmt.Errorf("failed to set BPF expression: %w", err))
	}

	// open tcp broadcaster
	broadcaster, err := iprd.NewBroadcaster(*flPort)
	if err != nil {
		exitWithError(err)
	}
	go broadcaster.Listen()
	go func() {
		for {
			select {
			case msg := <-broadcastCh:
				broadcaster.Msgs <- msg
			case err := <-broadcaster.Errs:
				iprl.Error(err)
			}
		}
	}()

	iprl.Info(fmt.Sprintf("set tcp forwarding -> :%d", *flPort))
	iprl.Info("successfully started iprd!")
	if *flDebug {
		iprl.Debug("--- DEBUG ON ---")
	}
	iprl.Info("start listen...")
	listen(handle)
}

func listen(handle *pcap.Handle) {
	defer handle.Close()

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		r, _ := iprd.NewIPRReportPacket(packet)
		if r == nil {
			// invalid layer or empty UDP paylaod. ignore
			continue
		}
		if err := iprd.IsValidIPRReportPacket(r); err != nil {
			if *flDebug {
				iprl.Error(fmt.Errorf("%s - not valid: %w", r.String(), err))
				iprl.Debug("--- PACKET DUMP ---")
				iprl.Debug(fmt.Sprintf("%s\n", packet.Dump()))
			}
			continue
		}
		iprl.Info(fmt.Sprintf("received IP Report %s", r.String()))
		if *flDebug {
			iprl.Debug(fmt.Sprintf("UDP Paylaod (%d) -> %s", r.CaptureLength, r.Payload))
		}

		msg, err := r.Marshall()
		if err != nil {
			iprl.Error(fmt.Errorf("failed to marshal packet: %w", err))
			continue
		}
		broadcastCh <- msg
	}
}

func autoFindLANInterface() *iprd.IPRInterface {
	iface, err := iprd.FindLANInterface()
	if err != nil {
		iprl.Error(err)
		os.Exit(1)
	}
	return iface
}

func getInterfaceFromFlag(name string) *iprd.IPRInterface {
	iface, err := iprd.GetInterfaceByName(name)
	if err != nil {
		iprl.Error(err)
		os.Exit(1)
	}
	return iface
}

func exitWithError(err error) {
	iprl.Error(err)
	os.Exit(1)
}
