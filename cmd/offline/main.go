package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

var (
	// flags
	flPcapFile        = flag.String("f", "", "Path to a .pcap or .pcapng capture file.")
	flDebug           = flag.Bool("d", false, "Switch to enable packet dumping output to stdout.")
	flFilterInterface = flag.String("i", "", "Filter packets by interface name.")
	flFilterPort      = flag.Int("p", 0, "Filter packets by port number.")
	flFilterIP        = flag.String("ip", "", "Filter packets by IP address.")
	flFilterMAC       = flag.String("mac", "", "Filter packets by MAC address.")
	flLimit           = flag.Int("l", 0, "Limit the number of packets to process. Defaults to 0 (no limit).")

	log = iprd.NewLogger()
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("iprd-offline: ")
	flag.Parse()

	if *flPcapFile == "" {
		log.Fatal(fmt.Errorf("missing -f <FILE>"))
	}

	var fd string
	if !strings.HasPrefix(*flPcapFile, "/") {
		// assume its in local directory
		dir, err := filepath.Abs("./")
		if err != nil {
			log.Fatal(err)
		}
		fd = fmt.Sprintf("%s/%s", dir, *flPcapFile)
	} else {
		fd = *flPcapFile
	}

	filter := filterConfig{
		InterfaceName: *flFilterInterface,
		IPAddress:     *flFilterIP,
		MACAddress:    *flFilterMAC,
		UDPPort:       *flFilterPort,
		Limit:         *flLimit,
	}
	if err := filter.Validate(); err != nil {
		log.Fatal(err)
	}

	err := dumpPcap(fd, *flDebug, filter)
	if err != nil {
		log.Fatal(err)
	}
}

func dumpPcap(fd string, debug bool, filter filterConfig) error {
	file, err := os.Open(fd)
	if err != nil {
		return err
	}
	defer file.Close()

	count := 0
	isLimited := filter.Limit != 0
	result, err := iprd.ProcessCapture(context.Background(), file, func(packet iprd.OfflinePacketResult) error {
		if !filterPacket(packet, filter) {
			return nil
		}
		count++
		if isLimited && count > filter.Limit {
			return nil
		}
		prefix := fmt.Sprintf("%s cnt:%d", packet.Timestamp.Format("2006-01-02 15:04:05"), packet.Number)
		if debug {
			log.Debug(fmt.Sprintf("%s\n", packet.Packet.Dump()))
		}
		if packet.Report == nil {
			log.Error(fmt.Errorf("%s iface:%s - failed to decode packet: %w", prefix, packet.InterfaceName, packet.Err))
			return nil
		}
		if packet.Err != nil {
			if errors.Is(packet.Err, iprd.ErrDuplicatePacket) {
				if debug {
					log.Warn(fmt.Sprintf("%s %s - Duplicate", prefix, packet.Report.String()))
				}
				return nil
			}
			log.Error(fmt.Errorf("%s %s - Not valid: %w", prefix, packet.Report.String(), packet.Err))
			return nil
		}
		log.Info(fmt.Sprintf("%s %s - Valid IP report", prefix, packet.Report.String()))
		return nil
	})
	if filter.String() != "None" {
		log.Info(fmt.Sprintf("Filter:%s", filter.String()))
	} else {
		log.Info(fmt.Sprintf("Summary: %s", result.String()))
	}
	return err
}
