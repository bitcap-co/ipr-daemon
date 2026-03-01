package main

import (
	"flag"
	"fmt"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

var (
	// flags
	flDebug     = flag.Bool("d", false, "enable debug packet logging")
	flInterface = flag.String("i", "eth0", "interface name for listening")
	flAuto      = flag.Bool("a", false, "use the defined LAN interface on system for listening. overrides -i")
	flPort      = flag.Int("p", 7788, "forward port for tcp broadcasting. default :7788")

	log = iprd.InitIPRLogger()
)

func main() {
	log.Info("start IP Reporter daemon...")
	flag.Parse()

	// get interface from flags
	var iface *iprd.IPRInterface
	if *flAuto {
		iface = autoFindLANInterface()
	} else {
		iface = getInterfaceFromFlag(*flInterface)
	}
	if !iface.IsUp() {
		log.Fatal(fmt.Errorf("interface %s is not marked as up", iface.FriendlyName))
	}

	listener := iprd.NewIPRListener(log, *flDebug, iface)
	if err := listener.Activate(); err != nil {
		log.Fatal(err)
	}

	// open tcp broadcaster
	broadcast, err := iprd.NewIPRBroadcast(log, *flPort)
	if err != nil {
		log.Fatal(err)
	}
	go broadcast.Listen()
	go func() {
		for {
			select {
			case msg := <-listener.Broadcast():
				broadcast.Msgs <- msg
			case err := <-broadcast.Errs:
				log.Error(err)
			}
		}
	}()

	log.Info(fmt.Sprintf("set tcp forwarding -> :%d", *flPort))
	log.Info("successfully started iprd!")
	if *flDebug {
		log.Debug("--- DEBUG ON ---")
	}
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
