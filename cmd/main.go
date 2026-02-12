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

	broadcastCh = make(chan []byte)

	// flags
	flInterface = flag.String("i", "eth0", "interface name to read packets from")
	flAuto      = flag.Bool("a", false, "automatically find and use the defined LAN interface on system, overrides -i")
	flPort      = flag.Int("p", 7788, "tcp port to forward packet data to. defaults to :7788")
	flDebug     = flag.Bool("d", false, "enable debug packet logging")
)

func main() {
	iprl.Info("start IP Reporter daemon...")
	flag.Parse()

	var iface *iprd.IPRInterface
	if *flAuto {
		iface = autoFindLANInterface()
	} else {
		iface = getInterfaceFromFlag(*flInterface)
	}
	if !iface.IsUp() {
		iprl.Error(fmt.Errorf("interface %s is not marked as up", iface.Name))
		os.Exit(1)
	}
	iprl.Info(fmt.Sprintf("set interface: %s", iface.Name))

	bpfExpr := fmt.Sprintf("src host %s and (dst net 255 or dst net %s) and udp src portrange 1024-65535 and udp dst portrange 1024-49151", iface.NetworkPrefix(), iface.NetworkPrefix())
	iprl.Info(fmt.Sprintf("set BPF filter expression: %s", bpfExpr))
	// create handle
	handle, err := pcap.OpenLive(iface.Name, int32(1600), true, pcap.BlockForever)
	if err != nil {
		iprl.Error(fmt.Errorf("failed to create handle on %s: %w", iface.Name, err))
		os.Exit(1)
	}
	// compile bpfExpr from active handle
	bpf, err := handle.CompileBPFFilter(bpfExpr)
	if err != nil {
		iprl.Error(fmt.Errorf("failed to compile BPF expression: %w", err))
		os.Exit(1)
	}
	// set bpf instructions on active handle
	if err := handle.SetBPFInstructionFilter(bpf); err != nil {
		iprl.Error(fmt.Errorf("failed to set BPF instructions: %w", err))
		os.Exit(1)
	}

	broadcaster, err := iprd.NewBroadcaster(*flPort)
	if err != nil {
		iprl.Error(err)
		os.Exit(1)
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
	if err := listen(handle); err != nil {
		iprl.Error(fmt.Errorf("listen error: %v", err))
		os.Exit(1)
	}
}

func getInterfaceFromFlag(name string) *iprd.IPRInterface {
	iface, err := iprd.GetInterfaceByName(name)
	if err != nil {
		iprl.Error(err)
		os.Exit(1)
	}
	return iface
}

func autoFindLANInterface() *iprd.IPRInterface {
	iface, err := iprd.FindLANInterface()
	if err != nil {
		iprl.Error(err)
		os.Exit(1)
	}
	return iface
}

func listen(handle *pcap.Handle) error {
	defer handle.Close()

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		r, _ := iprd.NewIPRReportPacket(packet)
		if r == nil {
			// malformed or empty UDP payload; ignore
			continue
		}
		if err := iprd.IsValidIPRReportPacket(r); err != nil {
			if *flDebug {
				iprl.Error(fmt.Errorf("%s - not valid: %w", r.String(), err))
				iprl.Debug("--- PACKET DUMP --")
				iprl.Debug(fmt.Sprintf("%s\n", packet.Dump()))
			}
			continue
		}
		iprl.Info(fmt.Sprintf("received %s", r.String()))
		if *flDebug {
			iprl.Debug(fmt.Sprintf("UDP Payload (%d) -> %s", r.CaptureLength, r.Payload))
		}

		msg, err := r.ToBroadcastMessage()
		if err != nil {
			iprl.Error(fmt.Errorf("failed to marshal msg: %v", err))
			continue
		}
		// send msg to be broadcasted
		broadcastCh <- msg
	}
	return nil
}
