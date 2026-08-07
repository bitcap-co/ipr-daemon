// starter is an example program that demonstrates how to use the ipr-daemon library.
package main

import (
	"errors"
	"fmt"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

var (
	log = iprd.NewLogger()
)

func processPacket(captured iprd.CapturedPacket, processor *iprd.PacketProcessor) {
	// decode captured packet into IPReportPacket
	packet, err := processor.CaptureToIPRPacket(captured)
	if err != nil {
		log.Error(fmt.Errorf("failed to decode packet: %w", err))
		return
	}
	// parse IPReportPacket
	if err := processor.ParseIPReportPacket(packet); err != nil {
		// check for duplicate packets with ErrDuplicatePacket
		if errors.Is(err, iprd.ErrDuplicatePacket) {
			log.Warn(fmt.Sprintf("%s - %s", packet.String(), err))
		}
		return
	}
	log.Info(fmt.Sprintf("received IP Report %s", packet.String()))
	return
}

func main() {
	// get interface by name
	iface, err := iprd.GetInterfaceByName("eth0")
	if err != nil {
		log.Fatal(err)
	}
	// initialize packet processer
	processor := iprd.NewPacketProcessor(nil)
	// initialize & activate single IPRListener on iface
	listener := iprd.NewListener(nil, log, iface)
	if err := listener.Activate(); err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			select {
			case captured := <-listener.Packets():
				processPacket(captured, processor)
			}
		}
	}()
	// start listening for packets
	listener.Listen()
}
