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
	flPcapFile = flag.String("f", "", "Path to a .pcap or .pcapng capture file.")
	flDebug    = flag.Bool("d", false, "Switch to enable packet dumping output to stdout.")

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
	err := dumpPcap(fd, *flDebug)
	if err != nil {
		log.Fatal(err)
	}
}

func dumpPcap(fd string, debug bool) error {
	file, err := os.Open(fd)
	if err != nil {
		return err
	}
	defer file.Close()

	result, err := iprd.ProcessCapture(context.Background(), file, func(result iprd.OfflinePacketResult) error {
		prefix := fmt.Sprintf("%s cnt:%d", result.Timestamp.Format("2006-01-02 15:04:05"), result.Number)
		if debug {
			log.Debug("--- Dumped Packet ---")
			log.Debug(fmt.Sprintf("%s\n", result.Packet.Dump()))
		}
		if result.Report == nil {
			log.Error(fmt.Errorf("%s iface:%s - failed to decode packet: %w", prefix, result.InterfaceName, result.Err))
			return nil
		}
		if result.Err != nil {
			if errors.Is(result.Err, iprd.ErrDuplicatePacket) {
				if debug {
					log.Warn(fmt.Sprintf("%s %s - Duplicate", prefix, result.Report.String()))
				}
				return nil
			}
			log.Error(fmt.Errorf("%s %s - Not valid: %w", prefix, result.Report.String(), result.Err))
			return nil
		}
		log.Info(fmt.Sprintf("%s %s - Valid IP report", prefix, result.Report.String()))
		return nil
	})
	log.Info(fmt.Sprintf("SUMMARY: %s", result.String()))
	return err
}
