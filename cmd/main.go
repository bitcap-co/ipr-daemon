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
	flInterfaces         = make(iprd.FlagInterface)
	flForwardBind        = flag.String("b", "", "IP address to bind the TCP broadcast stream to. Empty binds all interfaces.")
	flForwardPort        = flag.Int("p", 7788, "TCP stream/broadcast port for forwarding IP report packet data.")
	flForwardKnown       = flag.Bool("known", false, "Switch to only forward IP reports from known miner types/ports over forward port.")
	flMDNS               = flag.Bool("mdns", false, "Advertise the TCP forwarding endpoint over mDNS/DNS-SD.")
	flNoRootNetwork      = flag.Bool("no-root-network", false, "Switch to not include the interface network in BPF filter.")
	flNetworkInclusions  iprd.FlagSlice
	flNetworkExclusions  iprd.FlagSlice
	flIgnoredDevices     iprd.FlagSlice
	flCaptureFile        = flag.String("capture-file", "", "Path to write received packets to in PCAP-NG format for replay/debugging.")
	flRotateCaptureFiles = flag.Bool("rotate-capture", false, "Rotate up to four capture files instead of flushing the active file at its size limit.")
	flConfig             = flag.String("c", "", "Path to TOML config file. Overrides any other supplied flags.")
	flWrite              = flag.String("w", "", "Path to new TOML config file. Writes the supplied arguments to new config path.")
)

func main() {
	flag.Var(&flInterfaces, "i", "Interface name/index, optionally followed by BPF options (for example: eth0:no-root-network,add-network=192.168.1). This flag supports chaining; plain interface names may also be comma-separated.")
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

	// build/read configuration.
	var err error
	listenInterfaces := flInterfaces.Selectors()
	if len(listenInterfaces) == 0 {
		listenInterfaces = append([]string(nil), iprd.DefaultIPRDConfig().ListenInterfaces...)
	}
	cfg, err := iprd.ParseConfig(&iprd.IPRDConfig{
		ListenerConfig: iprd.ListenerConfig{
			Debug:            *flDebug,
			Auto:             *flAuto,
			ListenInterfaces: listenInterfaces,
			// Keep the first selector available through the legacy singular field.
			ListenInterface:    listenInterfaces[0],
			Interfaces:         flInterfaces.Configs(),
			ForwardKnown:       *flForwardKnown,
			NoRootNetwork:      *flNoRootNetwork,
			IgnoredDevices:     []string(flIgnoredDevices),
			NetworkInclusions:  []string(flNetworkInclusions),
			NetworkExclusions:  []string(flNetworkExclusions),
			CaptureFile:        *flCaptureFile,
			RotateCaptureFiles: *flRotateCaptureFiles,
		},
		ForwardConfig: iprd.ForwardConfig{
			Bind: *flForwardBind,
			Port: *flForwardPort,
			MDNS: *flMDNS,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	if *flWrite != "" {
		*flWrite = strings.Split(*flWrite, ".")[0]
		*flWrite = *flWrite + ".toml"
		if err := iprd.WriteIPRDConfigToFile(cfg, *flWrite); err != nil {
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

	// Initialize the capture and packet-processing manager.
	manager := iprd.NewListenerManager(&cfg.ListenerConfig, log)

	// open TCP broadcast.
	broadcaster, err := iprd.NewBroadcaster(log, cfg.Bind, cfg.Port)
	if err != nil {
		log.Fatal(err)
	}
	// start listening for incoming clients.
	go broadcaster.Listen()

	var mdnsAdvertiser *iprd.MDNSAdvertiser
	if cfg.MDNS {
		mdnsAdvertiser, err = iprd.NewMDNSAdvertiser(cfg.Bind, cfg.Port, VERSION)
		if err != nil {
			log.Warn(fmt.Sprintf("failed to advertise mDNS service: %v", err))
		} else {
			defer func() {
				if err := mdnsAdvertiser.Close(); err != nil {
					log.Warn(fmt.Sprintf("failed to withdraw mDNS service: %v", err))
				}
			}()
			log.Info(fmt.Sprintf("advertising mDNS service -> %s.local. port %d", iprd.MDNSServiceType, cfg.Port))
		}
	}
	// handle channel messages.
	go func() {
		for {
			select {
			case report, ok := <-manager.Reports():
				if !ok {
					return
				}
				// send message to subscribed clients.
				msg, err := report.Marshal()
				if err != nil {
					log.Error(err)
					continue
				}
				select {
				case broadcaster.Msgs <- msg:
				case <-ctx.Done():
					return
				}
			case err := <-broadcaster.Errs:
				log.Error(err)
			case <-ctx.Done():
				return
			}
		}
	}()
	log.Info(fmt.Sprintf("set tcp forwarding -> %s", net.JoinHostPort(cfg.Bind, strconv.Itoa(cfg.Port))))
	log.Info("successfully started iprd!")

	// Supervise capture and packet processing until the context is cancelled.
	if err := manager.Run(ctx); err != nil {
		if mdnsAdvertiser != nil {
			if closeErr := mdnsAdvertiser.Close(); closeErr != nil {
				log.Warn(fmt.Sprintf("failed to withdraw mDNS service: %v", closeErr))
			}
		}
		log.Fatal(err)
	}
	log.Info("shutting down iprd...")
}
