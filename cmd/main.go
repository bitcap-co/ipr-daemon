package main

import (
	"flag"
	"fmt"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

var (
	// flags
	flDebug     = flag.Bool("d", false, "Switch to enable packet debugging output.")
	flInterface = flag.String("i", "eth0", "Name of network interface for listening.")
	flAuto      = flag.Bool("a", false, "Switch to use the defined LAN interface (matching description) for listening. Overrides -i flag.")
	flTCPPort   = flag.Int("p", 7788, "Forward port for TCP broadcast. Default: 7788.")

	// iprd logger
	log = iprd.NewLogger()
)

func main() {
	flag.Parse()
	log.Info("start IPReporter Daemon...")

	// get interface from flags.
	var iface *iprd.IPRInterface
	if *flAuto {
		iface = autoFindLANInterface()
	} else {
		iface = getInterfaceFromFlag(*flInterface)
	}
	// sanity check: make sure that interface is marked as UP.
	if !iface.IsUp() {
		log.Fatal(fmt.Errorf("interface %s is not marked as UP", iface.FriendlyName))
	}

	// initialize IPRListener handle.
	listener := iprd.NewListener(log, *flDebug, iface)
	if err := listener.Activate(); err != nil {
		log.Fatal(err)
	}

	// open TCP broadcast.
	broadcaster, err := iprd.NewBroadcaster(log, *flTCPPort)
	if err != nil {
		log.Fatal(err)
	}
	// start listening for incoming clients.
	go broadcaster.Listen()
	// handle channel messages.
	go func() {
		for {
			select {
			case msg := <-listener.Broadcast():
				// send message to subscribed clients.
				broadcaster.Msgs <- msg
			case err := <-broadcaster.Errs:
				log.Error(err)
			}
		}
	}()
	log.Info(fmt.Sprintf("set tcp forwarding -> :%d", *flTCPPort))
	log.Info("successfully started iprd!")
	if *flDebug {
		log.Debug("--- DEBUG OUTPUT ON ---")
	}
	// start listening for packets.
	listener.Listen()
}

func autoFindLANInterface() *iprd.IPRInterface {
	iface, err := iprd.FindLANInterface()
	if err != nil {
		log.Fatal(err)
	}
	return iface
}

func getInterfaceFromFlag(name string) *iprd.IPRInterface {
	iface, err := iprd.GetInterfaceByName(name)
	if err != nil {
		log.Fatal(err)
	}
	return iface
}
