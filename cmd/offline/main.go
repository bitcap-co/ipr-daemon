package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	mutux sync.Mutex
	iprl  = iprd.NewIPRDLogger()
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
			iprl.Debug(fmt.Sprintf("%s", packet.Dump()))
		}
		ipr, err := iprd.ParseIPReportPacket(packet)
		if err != nil {
			iprl.Error(err)
		} else {
			iprl.Info("Valid IP Report!")
			if debug {
				iprl.Debug(fmt.Sprintf("IP: %s -> %s, MAC: %s -> %s, UDP: %d -> %d, Len: %d, Hint: %s",
					ipr.SrcIP, ipr.DstIP,
					ipr.SrcMAC, ipr.DstMAC,
					ipr.SrcPort, ipr.DstPort,
					ipr.CaptureLength(), ipr.MinerType()))
				iprl.Debug(fmt.Sprintf("Received UDP Payload (%d) -> %s", len(ipr.Datagram), ipr.Payload()))
			}
		}
	}
	return nil
}
