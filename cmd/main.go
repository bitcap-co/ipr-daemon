package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

var (
	log = iprd.NewLogger()

	// flags
	flConfig          = flag.String("c", "", "Path to config file. Overrides any other supplied flags.")
	flDebug           = flag.Bool("d", false, "Switch to enable packet debugging output.")
	flAuto            = flag.Bool("a", false, "Switch to use the defined LAN interface (matching description of 'lan' or 'LAN') for listening. Overrides -i flag.")
	flFilter          = flag.Bool("filter", false, "Switch to only broadcast known ports/miner types over forward port. Excludes 'unknown' type.")
	flInterface       = flag.String("i", "eth0", "Name of interface to listen/capture on.")
	flForwardPort     = flag.Int("p", 7788, "TCP stream/broadcast port for forwarding packet data.")
	flIgnoreAddresses = flag.String("ignore", "", "List of MAC addresses to ignore packets from. Separated by comma.")
)

func main() {
	flag.Parse()
	var cfg *iprd.IPRDConfig
	cfg = &iprd.IPRDConfig{
		Debug:           *flDebug,
		Auto:            *flAuto,
		Filter:          *flFilter,
		ListenInterface: *flInterface,
		ForwardPort:     *flForwardPort,
		IgnoreAddresses: strings.Split(*flIgnoreAddresses, ","),
	}
	var err error
	if *flConfig != "" {
		cfg, err = iprd.NewIPRDConfigFromFile(*flConfig)
		if err != nil {
			log.Fatal(err)
		}
	}

	// get interface from flags.
	var iface *iprd.IPRInterface
	if cfg.Auto {
		iface = autoFindLANInterface()
	} else {
		iface = getInterfaceFromFlag(cfg.ListenInterface)
	}
	// sanity check: make sure that interface is marked as UP.
	if !iface.IsUp() {
		log.Fatal(fmt.Errorf("interface %s is not marked as UP", iface.FriendlyName))
	}
	log.Info("start IPReporter Daemon...")
	// initialize IPRListener handle.
	listener := iprd.NewListener(cfg, log, iface)
	if err := listener.Activate(); err != nil {
		log.Fatal(err)
	}

	// open TCP broadcast.
	broadcaster, err := iprd.NewBroadcaster(log, cfg.ForwardPort)
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
	log.Info(fmt.Sprintf("set tcp forwarding -> :%d", cfg.ForwardPort))
	log.Info("successfully started iprd!")
	if *flDebug {
		log.Debug("--- DEBUG OUTPUT ON ---")
	}
	// start listening for packets.
	if *flFilter {
		log.Info("option -filter set: ignoring 'unknown' miner types.")
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
