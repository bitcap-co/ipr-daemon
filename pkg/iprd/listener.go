package iprd

import (
	"fmt"
	"os"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
)

const captureSnapLen uint32 = 1600

const (
	bpfTemplate string = "(%s) and (dst net 255 or %s) and udp src portrange 1024-65535 and udp dst portrange 1024-49151"
)

type IPRListener struct {
	cfg         *IPRDConfig
	log         *IPRLogger
	iface       *IPRInterface
	inactive    *pcap.InactiveHandle
	handle      *pcap.Handle
	ch          chan []byte
	captureFile *os.File
	captureW    *pcapgo.Writer
}

// NewListener returns a new IPRListener. If logger is nil, a new IPRLogger is created.
// Setting logDebug to true enables debug packet logging. Setting filter to true excludes 'unknown' MinerTypeHint.
func NewListener(cfg *IPRDConfig, logger *IPRLogger, iface *IPRInterface) *IPRListener {
	if cfg == nil {
		// pass in default config if not supplied
		cfg = DefaultIPRDConfig()
	}
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
	if err = l.inactive.SetSnapLen(int(captureSnapLen)); err != nil {
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
	// build network prefixes into expression
	var prefixes = []string{}
	if !l.cfg.NoRootNetwork {
		prefixes = []string{l.iface.NetworkPrefix()}
	}
	if len(l.cfg.NetworkPrefixes) > 0 && l.cfg.NetworkPrefixes[0] != "" {
		prefixes = append(prefixes, l.cfg.NetworkPrefixes...)
	}
	var src_prefix strings.Builder
	var dst_prefix strings.Builder
	for _, prefix := range prefixes {
		sep := " or "
		if prefixes[len(prefixes)-1] == prefix {
			sep = ""
		}
		fmt.Fprintf(&src_prefix, "src host %s%s", prefix, sep)
		fmt.Fprintf(&dst_prefix, "dst net %s%s", prefix, sep)
	}
	bpfExpr := fmt.Sprintf(bpfTemplate, src_prefix.String(), dst_prefix.String())
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
	if len(l.cfg.IgnoreAddresses) > 0 && l.cfg.IgnoreAddresses[0] != "" {
		for i, mac := range l.cfg.IgnoreAddresses {
			newMac := ParseMACAddress(mac)
			if len(newMac) == 0 {
				l.log.Warn(fmt.Sprintf("invalid mac: %d - %s", i, mac))
			}
			l.cfg.IgnoreAddresses[i] = newMac
		}
		l.log.Info(fmt.Sprintf("set ignored addresses: [%s]", strings.Join(l.cfg.IgnoreAddresses, ",")))
	}
	if l.cfg.CaptureFile != "" {
		f, err := os.Create(l.cfg.CaptureFile)
		if err != nil {
			return fmt.Errorf("failed to open capture file: %w", err)
		}
		w := pcapgo.NewWriter(f)
		if err = w.WriteFileHeader(captureSnapLen, l.handle.LinkType()); err != nil {
			f.Close()
			return fmt.Errorf("failed to write pcap file header: %w", err)
		}
		l.captureFile = f
		l.captureW = w
		l.log.Info(fmt.Sprintf("capturing packets to: %s", l.cfg.CaptureFile))
	}
	return nil
}

// Listen will start reading packets from the active handle and sends the marshalled IPReportPacket to Broadcast().
func (l *IPRListener) Listen() {
	defer l.handle.Close()
	if l.captureFile != nil {
		defer l.captureFile.Close()
	}
	l.log.Info("start listen...")

	source := gopacket.NewPacketSource(l.handle, l.handle.LinkType())
	for packet := range source.Packets() {
		if l.captureW != nil {
			if err := l.captureW.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				l.log.Error(fmt.Errorf("failed to write packet to capture file: %w", err))
			}
		}
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
