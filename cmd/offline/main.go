package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	iprl = iprd.InitIPRLogger()
)

func main() {
	iprl.SetPrefix("iprd-offline: ")
	// flags
	var flPcapFile = flag.String("f", "", "file descriptor of pcap file")
	var flDebug bool
	flag.BoolVar(&flDebug, "d", false, "switch to enable debug to stdout.")
	flag.Parse()

	if *flPcapFile == "" {
		log.Fatalln("argument error: missing -f <FILE>")
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
	err := dumpPcap(fd, flDebug)
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
			iprl.Debug("--- Dumped Packet ---")
			iprl.Debug(fmt.Sprintf("%s\n", packet.Dump()))
		}
		ipr, _ := iprd.NewIPRReportPacket(packet)
		if ipr == nil {
			iprl.Error(fmt.Errorf("failed to decode packet"))
			continue
		}
		if err := iprd.ParseIPRReportPacket(ipr); err != nil {
			iprl.Error(fmt.Errorf("%s - Not valid: %w",
				ipr.String(), err))
			continue
		}
		iprl.Info("Valid IP Report!")
		if debug {
			iprl.Debug(ipr.String())
			iprl.Debug(fmt.Sprintf("Received UDP Payload (%d) -> %s", len(ipr.Datagram), ipr.Payload))
		}
	}
	return nil
}
