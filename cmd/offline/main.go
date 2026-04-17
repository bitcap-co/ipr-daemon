package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
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
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if debug {
			log.Debug("--- Dumped Packet ---")
			log.Debug(fmt.Sprintf("%s\n", packet.Dump()))
		}
		ipr, _ := iprd.NewIPReportPacket(packet)
		if ipr == nil {
			log.Error(fmt.Errorf("failed to decode packet"))
			continue
		}
		if err := iprd.ParseIPReportPacket(ipr); err != nil {
			log.Error(fmt.Errorf("%s - Not valid: %w",
				ipr.String(), err))
			continue
		}
		log.Info("Valid IP Report!")
		if debug {
			log.Debug(ipr.String())
			log.Debug(fmt.Sprintf("Received UDP Payload (%d) -> %s", len(ipr.Datagram), ipr.Payload))
		}
	}
	return nil
}
