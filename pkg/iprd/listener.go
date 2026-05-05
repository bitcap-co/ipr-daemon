package iprd

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	bpfTemplate string = "src host %s and (dst net 255 or dst net %s) and udp src portrange 1024-65535 and udp dst portrange 1024-49151"
)

type IPRListener struct {
	cfg      *IPRDConfig
	log      *IPRLogger
	iface    *IPRInterface
	inactive *pcap.InactiveHandle
	handle   *pcap.Handle
	ch       chan []byte
}

// NewListener returns a new IPRListener. If logger is nil, a new IPRLogger is created.
// Setting logDebug to true enables debug packet logging. Setting filter to true excludes 'unknown' MinerTypeHint.
func NewListener(cfg *IPRDConfig, logger *IPRLogger, iface *IPRInterface) *IPRListener {
	if logger == nil {
		logger = NewLogger()
	}
	inactive, _ := pcap.NewInactiveHandle(iface.Name)
	return &IPRListener{
		cfg:      cfg,
		log:      logger,
		iface:    iface,
		inactive: inactive,
		ch:       make(chan []byte),
	}
}

// Broadcast returns a channel of messages for broadcasting.
func (l *IPRListener) Broadcast() chan []byte {
	return l.ch
}

// Activate sets a new active pcap handle on iface. This must be called once before Listen().
func (l *IPRListener) Activate() error {
	if l.inactive == nil {
		return fmt.Errorf("failed to create handle: %w", l.inactive.Error())
	}
	defer l.inactive.CleanUp()

	// configure new handle.
	var err error
	if err = l.inactive.SetSnapLen(1600); err != nil {
		return fmt.Errorf("could not set snap len: %w", err)
	} else if err = l.inactive.SetPromisc(true); err != nil {
		return fmt.Errorf("could not set promisc mode: %w", err)
	} else if err = l.inactive.SetTimeout(pcap.BlockForever); err != nil {
		return fmt.Errorf("could not set timeout: %w", err)
	}
	if l.handle, err = l.inactive.Activate(); err != nil {
		return fmt.Errorf("failed to activate handle: %w", err)
	}
	l.log.Info(fmt.Sprintf("activate handle on interface: %s (%s)", l.iface.FriendlyName, l.iface.MACAddr()))

	// set BPF expression on new active handle.
	bpfExpr := fmt.Sprintf(bpfTemplate, l.iface.NetworkPrefix(), l.iface.NetworkPrefix())
	if err = l.handle.SetBPFFilter(bpfExpr); err != nil {
		return fmt.Errorf("failed to set BPF expression: %w", err)
	}
	l.log.Info(fmt.Sprintf("set BPF filter expression: %s", bpfExpr))
	if l.cfg.Debug {
		l.log.Debug("--- DEBUG OUTPUT ON ---")
	}
	if l.cfg.Filter {
		l.log.Info("filter option is set: only broadcast known ports!")
	}
	return nil
}

// Listen will start reading packets from the active handle and sends the marshalled IPReportPacket to Broadcast().
func (l *IPRListener) Listen() {
	defer l.handle.Close()
	l.log.Info("start listen...")

	source := gopacket.NewPacketSource(l.handle, l.handle.LinkType())
	for packet := range source.Packets() {
		// try and initialize as IPReportPacket.
		r, _ := NewIPReportPacket(packet)
		if r == nil {
			// invalid layer or empty UDP paylaod.
			continue
		}
		// parse IPReportPacket to validate that it is an IP Report packet.
		if err := ParseIPReportPacket(r, l.cfg.IgnoreAddresses...); err != nil {
			// warn on duplicate packet.
			if err.Error() == "duplicate packet" {
				l.log.Warn(fmt.Sprintf("%s - %s", r.String(), err))
			}
			if l.cfg.Debug {
				l.log.Error(fmt.Errorf("%s - not valid: %w", r.String(), err))
				l.log.Debug("--- PACKET DUMP ---")
				l.log.Debug(fmt.Sprintf("%s\n", packet.Dump()))
			}
			continue
		}
		if l.cfg.Filter {
			if r.MinerHint == UnknownType {
				l.log.Warn(fmt.Sprintf("received unknown IP Report %s", r.String()))
				continue
			}
		}
		l.log.Info(fmt.Sprintf("received IP Report %s", r.String()))
		if l.cfg.Debug {
			l.log.Debug(fmt.Sprintf("UDP Payload (%d) -> %s", r.CaptureLength, r.Payload))
		}

		// prepare new broadcast message.
		msg, err := r.Marshal()
		if err != nil {
			l.log.Error(fmt.Errorf("failed to marshal packet: %w", err))
			continue
		}
		l.ch <- msg
	}
}
