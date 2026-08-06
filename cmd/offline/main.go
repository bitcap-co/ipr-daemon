package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
)

var (
	// flags
	flPcapFile = flag.String("f", "", "Path to a .pcap or .pcapng capture file.")
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
	file, err := os.Open(fd)
	if err != nil {
		return err
	}
	var magic [4]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return err
	}
	if bytes.Equal(magic[:], []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		defer file.Close()
		return dumpPcapNG(file, debug)
	}
	file.Close()
	return dumpClassicPcap(fd, debug)
}

func dumpClassicPcap(fd string, debug bool) error {
	handle, err := pcap.OpenOffline(fd)
	if err != nil {
		return err
	}
	defer handle.Close()

	processor := iprd.NewPacketProcessor(nil)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var packetCount int64
	for packet := range packetSource.Packets() {
		packetCount++
		processOfflinePacket(packet, processor, packetCount, "classic", debug)
	}
	return nil
}

func dumpPcapNG(file *os.File, debug bool) error {
	reader, err := pcapgo.NewNgReader(file, pcapgo.NgReaderOptions{WantMixedLinkType: true})
	if err != nil {
		return err
	}
	processor := iprd.NewPacketProcessor(nil)
	var packetCount int64
	for {
		data, ci, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		packetCount++

		intf, err := reader.Interface(ci.InterfaceIndex)
		if err != nil {
			return err
		}
		interfaceName := intf.Name
		if interfaceName == "" {
			interfaceName = fmt.Sprintf("#%d", ci.InterfaceIndex)
		}
		linkType := intf.LinkType
		if len(ci.AncillaryData) > 0 {
			if capturedLinkType, ok := ci.AncillaryData[0].(layers.LinkType); ok {
				linkType = capturedLinkType
			}
		}
		packet := gopacket.NewPacket(data, linkType, gopacket.Default)
		packet.Metadata().CaptureInfo = ci
		processOfflinePacket(packet, processor, packetCount, interfaceName, debug)
	}
}

func processOfflinePacket(packet gopacket.Packet, processor *iprd.PacketProcessor, packetCount int64, interfaceName string, debug bool) {
	prefix := fmt.Sprintf("cnt:%d iface:%s", packetCount, interfaceName)
	if debug {
		log.Debug("--- Dumped Packet ---")
		log.Debug(fmt.Sprintf("%s\n", packet.Dump()))
	}
	ipr, err := iprd.NewIPReportPacket(packet)
	if err != nil {
		log.Error(fmt.Errorf("%s - failed to decode packet: %w", prefix, err))
		return
	}
	if err := processor.ParseIPReportPacket(ipr); err != nil {
		if errors.Is(err, iprd.ErrDuplicatePacket) {
			if debug {
				log.Warn(fmt.Sprintf("%s %s - Duplicate", prefix, ipr.String()))
			}
			return
		}
		log.Error(fmt.Errorf("%s %s - Not valid: %w", prefix, ipr.String(), err))
		return
	}
	log.Info(fmt.Sprintf("%s %s - Valid IP report", prefix, ipr.String()))
}
