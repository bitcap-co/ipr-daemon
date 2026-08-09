package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

var (
	log = iprd.NewLogger()
)

func main() {
	// Listener config
	cfg := iprd.DefaultListenerConfig()
	cfg.ListenInterfaces = []string{"eth0"} // set list of interface names/indexes to listen on
	// configure interface BPF filters
	cfg.Interfaces = []iprd.InterfaceConfig{
		{
			Selector:          "eth0",     // set to the name/index of the interface to apply configuration
			NoRootNetwork:     false,      // set to true to exclude the root IPv4 network of interface (If true, must set at least one NetworkInclusions)
			IgnoredDevices:    []string{}, // set to ignore a list of devices by MAC addresses
			NetworkInclusions: []string{}, // Append a list of networks to include FORMAT: IPv4 dotted quad, triple, pair or single (e.g. 192.168.1.0, 192.168.1, 172.16, 10)
			NetworkExclusions: []string{}, // Append a list of networks to exclude
		},
		// ...
	}

	// cancel on SIGINT/SIGTERM for a clean shutdown of the reconnect loop.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// initialize listener manager with listener config
	manager, err := iprd.NewListenerManager(cfg, log)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		if err := manager.Run(ctx); err != nil {
			log.Error(fmt.Errorf("listener stopped: %v", err))
		}
	}()

	for {
		select {
		case report, ok := <-manager.Reports():
			if !ok {
				return
			}
			// process reports...
			fmt.Println(report)
		case <-ctx.Done():
			return
		}
	}
}
