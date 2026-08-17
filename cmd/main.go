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
	// build variables set at build time via ldflags
	VERSION   = "unknown"
	BUILDINFO = "unknown"
	TAG       = "NO-TAG"
	COMMIT    = "unknown"
	DELTA     = ""

	log = iprd.NewLogger()

	// flags
	flVersion            = flag.Bool("version", false, "Prints version information and exits.")
	flList               = flag.Bool("list", false, "Lists all available network interfaces that can be listened on and exits.")
	flStatus             = flag.Bool("status", false, "Queries a running daemon for its current IP Report status and exits.")
	flStatusJSON         = flag.Bool("status-json", false, "Queries a running daemon and prints its current IP Report status as JSON.")
	flDebug              = flag.Bool("d", false, "Switch to enable packet debugging output.")
	flAuto               = flag.Bool("a", false, "Switch to use the defined LAN interface for listening (OPNSense/pfSense). Overrides -i flag.")
	flInterfaces         = make(iprd.FlagInterface)
	flForwardBind        = flag.String("b", "", "Bind address for the TCP broadcast stream; target host in status mode. Empty binds all interfaces.")
	flForwardPort        = flag.Int("p", 0, "Forwarding port for the TCP broadcast stream.")
	flForwardKnown       = flag.Bool("known", false, "Switch to only forward IP reports from known miner types/ports over TCP broadcast stream.\nUnknown IP reports are logged but not forwarded.")
	flMDNS               = flag.Bool("mdns", false, "Switch to enable mDNS/DNS-SD advertising of the TCP forwarding endpoint.")
	flNoRootNetwork      = flag.Bool("no-root-network", false, "Switch to remove interface network from BPF filter. Must add additional network inclusion(s) via -add-network flag.\n(Global: applies to all interface selectors.)")
	flNetworkInclusions  iprd.FlagSlice
	flNetworkExclusions  iprd.FlagSlice
	flIgnoredDevices     iprd.FlagSlice
	flCaptureFile        = flag.String("capture-file", "", "Path to write received packets to in PCAP-NG format for replay/debugging.")
	flRotateCaptureFiles = flag.Bool("rotate-capture", false, "Switch to rotate up to four capture files instead of flushing the active file at its size limit.")
	flConfigFile         = flag.String("c", "", "Path to TOML configuration file. Overrides any other supplied flags.")
	flWriteConfig        = flag.String("w", "", "Path to TOML configuration file. Writes the supplied arguments to new config file or updates an existing one.")
)

func main() {
	flag.Var(&flInterfaces, "i", "Interface selectors (name/index), optionally followed by BPF options (for example: eth0:no-root-network,add-network=192.168.1).\nThis flag supports chaining; plain interface names may also be comma-separated.")
	flag.Var(&flIgnoredDevices, "ignore", "List of source MAC addresses to exclude in BPF filter.\nThis flag supports chaining or comma-separated string.\n(Global: applies to all interface selectors.)")
	flag.Var(&flNetworkInclusions, "add-network", "List of networks to append to BPF filter. Networks are IPv4 network numbers that can be written as a dotted quad, triple, pair or a single number.\nThis flag supports chaining or comma-separated string.\n(Global: applies to all interface selectors.)")
	flag.Var(&flNetworkExclusions, "exclude", "List of networks to additionally exclude from BPF filter.\nThis flag supports chaining or comma-separated string.\n(Global: applies to all interface selectors.)")
	flag.Parse()

	// print version information and exit.
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

	// build/set configuration.
	var err error
	listenInterfaces := flInterfaces.Selectors()
	listenInterface := ""
	if len(listenInterfaces) > 0 {
		listenInterface = listenInterfaces[0]
	}
	// no interface providers and not in config mode; exit.
	if len(listenInterfaces) == 0 && *flConfigFile == "" && *flWriteConfig == "" {
		log.Fatal(fmt.Errorf("no listen interface(s) specified.\nUSAGE: use -i/-c to specify at least one listen interface."))
	}
	cfg, err := iprd.ParseConfig(&iprd.IPRDConfig{
		ListenerConfig: iprd.ListenerConfig{
			Debug:            *flDebug,
			Auto:             *flAuto,
			ListenInterfaces: listenInterfaces,
			// Keep the first selector available through the legacy singular field.
			ListenInterface:    listenInterface,
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
	if *flWriteConfig != "" {
		// normalize the output file path to .toml extension
		*flWriteConfig = strings.Split(*flWriteConfig, ".")[0]
		*flWriteConfig = *flWriteConfig + ".toml"
		if curr, err := iprd.NewIPRDConfigFromFile(*flWriteConfig); err == nil {
			// config file exists, merge with current config.
			newCfg := updateExistingConfig(curr, cfg)
			mergedCfg, err := iprd.ParseConfig(newCfg)
			if err != nil {
				log.Fatal(err)
			}
			if err := iprd.WriteIPRDConfigToFile(mergedCfg, *flWriteConfig); err != nil {
				log.Fatal(err)
			}
		} else {
			// write new config file.
			if err := iprd.WriteIPRDConfigToFile(cfg, *flWriteConfig); err != nil {
				log.Fatal(err)
			}
		}
		log.Info(fmt.Sprintf("successfully wrote -> %s", *flWriteConfig))
		os.Exit(0)
	}
	if *flConfigFile != "" {
		cfg, err = iprd.NewIPRDConfigFromFile(*flConfigFile)
		if err != nil {
			log.Fatal(err)
		}
	}
	if *flStatus || *flStatusJSON {
		response, err := requestStatus(cfg.Bind, cfg.Port)
		if err != nil {
			log.Fatal(err)
		}
		if err := writeStatus(os.Stdout, response, *flStatusJSON); err != nil {
			log.Fatal(err)
		}
		return
	}

	log.Info("start IPReporter Daemon...")
	// cancel on SIGINT/SIGTERM for a clean shutdown of the reconnect loop.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// initialize the capture and packet-processing manager.
	manager, err := iprd.NewListenerManager(&cfg.ListenerConfig, log)
	if err != nil {
		log.Fatal(err)
	}

	// initialize TCP broadcast stream.
	broadcaster, err := iprd.NewBroadcaster(log, cfg.Bind, cfg.Port)
	if err != nil {
		log.Fatal(err)
	}
	broadcaster.SetStatusProvider(manager)
	// start listening for incoming connections.
	go broadcaster.Listen()

	// start opted-in mDNS service advertisement (_iprd._tcp.local.)
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

	// start message handler func.
	go func() {
		for {
			select {
			case report, ok := <-manager.Reports():
				if !ok {
					return
				}
				// Create the transport message once so its packet ID remains stable.
				broadcast, err := iprd.NewIPRBroadcastMessage(report)
				if err != nil {
					log.Error(err)
					continue
				}
				msg, err := broadcast.Marshal()
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
	log.Info("successfully initialized iprd!")

	// Supervise capture and packet processing until the context is cancelled.
	if err := manager.Run(ctx); err != nil {
		if mdnsAdvertiser != nil {
			if closeErr := mdnsAdvertiser.Close(); closeErr != nil {
				log.Warn(fmt.Sprintf("failed to withdraw mDNS service: %v", closeErr))
			}
		}
		log.Fatal(err)
	}
	log.Info("exiting...")
}
