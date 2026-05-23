package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

var (
	// flags
	flPcapFile = flag.String("f", "", "File descriptor for .pcap file.")
	flDebug    = flag.Bool("d", false, "Switch to enable packet debugging output to stdout.")

	log = iprd.NewLogger()
)

func main() {
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
	handle, err := pcap.OpenOffline(fd)
	if err != nil {
		return err
	}
	var packetCount int64 = 0
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		packetCount++
		if debug {
			log.Debug("--- Dumped Packet ---")
			log.Debug(fmt.Sprintf("%s\n", packet.Dump()))
		}
		ipr, err := iprd.NewIPReportPacket(packet)
		if err != nil {
			log.Error(fmt.Errorf("failed to decode packet %d: %s", packetCount, err))
			continue
		}
		if err := iprd.ParseIPReportPacket(ipr); err != nil {
			if err.Error() == "duplicate packet" {
				// ignore duplicate packets
				if debug {
					log.Warn(fmt.Sprintf("Cnt:%d %s - Duplicate", packetCount, ipr.String()))
				}
				continue
			}
			log.Error(fmt.Errorf("Cnt:%d %s - Not valid: %w", packetCount, ipr.String(), err))
			continue
		}
		log.Info(fmt.Sprintf("Cnt:%d %s - Valid IP report", packetCount, ipr.String()))
	}
	return nil
}
