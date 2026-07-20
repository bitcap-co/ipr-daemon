package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

type flagSlice []string

func (f *flagSlice) String() string {
	return strings.Join(*f, ",")
}

func (f *flagSlice) Set(value string) error {
	*f = append(*f, value)
	return nil
}

var (
	// build info
	VERSION   = "unknown"
	BUILDINFO = "unknown"
	TAG       = "NO-TAG"
	COMMIT    = "unknown"
	DELTA     = ""

	log = iprd.NewLogger()

	// flags
	flVersion            = flag.Bool("version", false, "Prints version info and exits")
	flList               = flag.Bool("list", false, "Lists all available network interfaces that can be listened on.")
	flDebug              = flag.Bool("d", false, "Switch to enable packet debugging output.")
	flAuto               = flag.Bool("a", false, "Switch to use the defined LAN interface (description matching 'lan' or 'LAN') for listening. Overrides -i flag.")
	flInterface          = flag.String("i", "eth0", "Name or index of interface to listen/capture on.")
	flForwardBind        = flag.String("b", "", "IP address to bind the TCP broadcast stream to. Empty binds all interfaces.")
	flForwardPort        = flag.Int("p", 7788, "TCP stream/broadcast port for forwarding IP report packet data.")
	flForwardKnown       = flag.Bool("known", false, "Switch to only forward IP reports from known miner types/ports over forward port.")
	flMDNS               = flag.Bool("mdns", false, "Advertise the TCP forwarding endpoint over mDNS/DNS-SD.")
	flNoRootNetwork      = flag.Bool("no-root-network", false, "Switch to not include the interface network in BPF filter.")
	flNetworkInclusions  flagSlice
	flNetworkExclusions  flagSlice
	flIgnoredDevices     flagSlice
	flCaptureFile        = flag.String("capture-file", "", "Path to write received packets to in PCAP format for replay/debugging.")
	flRotateCaptureFiles = flag.Bool("rotate-capture", false, "Rotate up to four capture files instead of flushing the active file at its size limit.")
	flConfig             = flag.String("c", "", "Path to TOML config file. Overrides any other supplied flags.")
	flWrite              = flag.String("w", "", "Path to new TOML config file. Writes the supplied arguments to new config path.")
)

func main() {
	flag.Var(&flIgnoredDevices, "ignore", "List of source MAC addresses to exclude in BPF filter.\nThis flag supports chaining or comma-separated string.")
	flag.Var(&flNetworkInclusions, "add-network", "List of networks to append to BPF filter. Networks are IPv4 network numbers that can be written as a dotted quad, triple, pair or a single number.\nThis flag supports chaining or comma-separated string.")
	flag.Var(&flNetworkExclusions, "exclude", "List of networks to additionally exclude from BPF filter.\nThis flag supports chaining or comma-separated string.")
	flag.Parse()

	// print version info and exit
	if *flVersion {
		delta := ""
		if len(DELTA) > 0 {
			delta = fmt.Sprintf(" [%s delta]", DELTA)
			TAG = "Unknown"
		}
		fmt.Printf("ipr-daemon v%s\n", VERSION)
		fmt.Printf("%s (%s)%s built at %s\n", COMMIT, TAG, delta, BUILDINFO)
		os.Exit(0)
	}

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

	if *flNoRootNetwork && flNetworkInclusions.String() == "" {
		log.Fatal(fmt.Errorf("no networks supplied. Use -add-network to add a network"))
	}

	// build/read configuration.
	var err error
	var cfg *iprd.IPRDConfig
	cfg = &iprd.IPRDConfig{
		Debug:              *flDebug,
		Auto:               *flAuto,
		ListenInterface:    *flInterface,
		ForwardBind:        *flForwardBind,
		ForwardPort:        *flForwardPort,
		ForwardKnown:       *flForwardKnown,
		MDNS:               *flMDNS,
		NoRootNetwork:      *flNoRootNetwork,
		IgnoredDevices:     strings.Split(flIgnoredDevices.String(), ","),
		NetworkInclusions:  strings.Split(flNetworkInclusions.String(), ","),
		NetworkExclusions:  strings.Split(flNetworkExclusions.String(), ","),
		CaptureFile:        *flCaptureFile,
		RotateCaptureFiles: *flRotateCaptureFiles,
	}
	if *flWrite != "" {
		*flWrite = strings.Split(*flWrite, ".")[0]
		*flWrite = *flWrite + ".toml"
		err = iprd.WriteIPRDConfigToFile(cfg, *flWrite)
		if err != nil {
			log.Fatal(err)
		}
		log.Info(fmt.Sprintf("successfully wrote -> %s", *flWrite))
		os.Exit(0)
	}
	if *flConfig != "" {
		cfg, err = iprd.NewIPRDConfigFromFile(*flConfig)
		if err != nil {
			log.Fatal(err)
		}
	}
	log.Info("start IPReporter Daemon...")

	// cancel on SIGINT/SIGTERM for a clean shutdown of the reconnect loop.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// initialize IPRListener on iface, passing in cfg.
	listener := iprd.NewListener(cfg, log, nil)

	// open TCP broadcast.
	broadcaster, err := iprd.NewBroadcaster(log, cfg.ForwardBind, cfg.ForwardPort)
	if err != nil {
		log.Fatal(err)
	}
	// start listening for incoming clients.
	go broadcaster.Listen()

	var mdnsAdvertiser *iprd.MDNSAdvertiser
	if cfg.MDNS {
		mdnsAdvertiser, err = iprd.NewMDNSAdvertiser(cfg.ForwardBind, cfg.ForwardPort, VERSION)
		if err != nil {
			log.Warn(fmt.Sprintf("failed to advertise mDNS service: %v", err))
		} else {
			defer func() {
				if err := mdnsAdvertiser.Close(); err != nil {
					log.Warn(fmt.Sprintf("failed to withdraw mDNS service: %v", err))
				}
			}()
			log.Info(fmt.Sprintf("advertising mDNS service -> %s.local. port %d", iprd.MDNSServiceType, cfg.ForwardPort))
		}
	}
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
	log.Info(fmt.Sprintf("set tcp forwarding -> %s", net.JoinHostPort(cfg.ForwardBind, strconv.Itoa(cfg.ForwardPort))))
	log.Info("successfully started iprd!")

	// supervise capture: activates the handle and reconnects on interface loss
	// until the context is cancelled.
	if err := listener.Run(ctx); err != nil {
		if mdnsAdvertiser != nil {
			if closeErr := mdnsAdvertiser.Close(); closeErr != nil {
				log.Warn(fmt.Sprintf("failed to withdraw mDNS service: %v", closeErr))
			}
		}
		log.Fatal(err)
	}
	log.Info("shutting down iprd...")
}
