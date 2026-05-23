package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

type flagSlice []string

func (f *flagSlice) String() string {
	return fmt.Sprintf("%s", strings.Join(*f, ","))
}

func (f *flagSlice) Set(value string) error {
	*f = append(*f, value)
	return nil
}

var (
	log = iprd.NewLogger()

	// flags
	flAuto            = flag.Bool("a", false, "Switch to use the defined LAN interface (matching description of 'lan' or 'LAN') for listening. Overrides -i flag.")
	flConfig          = flag.String("c", "", "Path to config file. Overrides any other supplied flags.")
	flDebug           = flag.Bool("d", false, "Switch to enable packet debugging output.")
	flFilter          = flag.Bool("filter", false, "Switch to only broadcast known ports/miner types over forward port. Excludes 'unknown' type.")
	flInterface       = flag.String("i", "eth0", "Name or index of interface to listen/capture on.")
	flList            = flag.Bool("list", false, "List all available system network interfaces to listen on.")
	flForwardPort     = flag.Int("p", 7788, "TCP stream/broadcast port for forwarding packet data.")
	flCaptureFile     = flag.String("capture-file", "", "Path to write received packets to in pcap format for replay/debugging. Empty disables.")
	flNetworkPrefixes flagSlice
	flIgnoreAddresses flagSlice
)

func main() {
	flag.Var(&flIgnoreAddresses, "ignore", "List of MAC addresses to ignore packets from.")
	flag.Var(&flNetworkPrefixes, "add-prefix", "List of network prefixes to append to BPF filter.")
	flag.Parse()

	// list interfaces and exit.
	if *flList {
		ifaces, err := iprd.GetInterfaces()
		if err != nil {
			log.Fatal(err)
		}
		for _, iface := range ifaces {
			fmt.Println(iface.String())
		}
		os.Exit(0)
	}

	// build/read configuration.
	var err error
	var cfg *iprd.IPRDConfig
	cfg = &iprd.IPRDConfig{
		Debug:           *flDebug,
		Auto:            *flAuto,
		Filter:          *flFilter,
		ListenInterface: *flInterface,
		ForwardPort:     *flForwardPort,
		IgnoreAddresses: strings.Split(flIgnoreAddresses.String(), ","),
		NetworkPrefixes: strings.Split(flNetworkPrefixes.String(), ","),
		CaptureFile:     *flCaptureFile,
	}
	if *flConfig != "" {
		cfg, err = iprd.NewIPRDConfigFromFile(*flConfig)
		if err != nil {
			log.Fatal(err)
		}
	}

	// get interface from flags.
	var iface *iprd.IPRInterface
	if cfg.Auto {
		iface, err = iprd.FindLANInterface()
		if err != nil {
			log.Fatal(err)
		}
	} else {
		iface = getInterfaceFromFlag(cfg.ListenInterface)
	}
	// sanity check to make sure that interface is marked as UP.
	if !iface.IsUp() {
		log.Fatal(fmt.Errorf("interface %s is not marked as UP", iface.FriendlyName))
	}
	log.Info("start IPReporter Daemon...")
	// initialize IPRListener handle on iface, passing in cfg.
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

	// start listening
	listener.Listen()
}

func getInterfaceFromFlag(name string) *iprd.IPRInterface {
	if index, err := strconv.Atoi(name); err == nil {
		iface, err := iprd.GetInterfaceByIndex(index)
		if err != nil {
			log.Fatal(err)
		}
		return iface
	}
	iface, err := iprd.GetInterfaceByName(name)
	if err != nil {
		log.Fatal(err)
	}
	return iface
}
