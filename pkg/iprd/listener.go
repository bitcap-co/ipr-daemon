package iprd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
)

const (
	captureSnapLen     uint32 = 1600
	maxCaptureFileSize int64  = 4 * 1024 * 1024 // max capture file size of 4mb
	pcapFileHeaderSize int64  = 24
	pcapRecordHeader   int64  = 16
)

const (
	bpfTemplate string = "(%s) and (dst net 255 or %s) and udp src portrange 1024-65535 and udp dst portrange 1024-65535"
)

type IPRListener struct {
	cfg          *IPRDConfig
	log          *IPRLogger
	iface        *IPRInterface
	inactive     *pcap.InactiveHandle
	handle       *pcap.Handle
	ch           chan []byte
	captureFile  *os.File
	captureW     *pcapgo.Writer
	captureBytes int64
}

// NewListener returns a new IPRListener, taking in a IPRDConfig to configure behavior. If logger is nil, a new IPRLogger is created.
func NewListener(cfg *IPRDConfig, logger *IPRLogger, iface *IPRInterface) *IPRListener {
	if cfg == nil {
		// pass in default config if not supplied
		cfg = DefaultIPRDConfig()
	}
	if logger == nil {
		logger = NewLogger()
	}

	return &IPRListener{
		cfg:   cfg,
		log:   logger,
		iface: iface,
		ch:    make(chan []byte),
	}
}

// Broadcast returns a channel of messages for broadcasting.
func (l *IPRListener) Broadcast() chan []byte {
	return l.ch
}

// Activate sets a new active pcap handle on iface. This must be called once before Listen().
func (l *IPRListener) Activate() error {
	var err error
	if l.iface == nil {
		err = l.setInterface()
		if err != nil {
			return err
		}
	}
	l.inactive, err = pcap.NewInactiveHandle(l.iface.Name)
	if err != nil {
		return fmt.Errorf("failed to create handle: %w", err)
	}
	defer l.inactive.CleanUp()

	// configure new handle.
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
	for _, p := range l.cfg.NetworkPrefixes {
		if p != "" {
			prefixes = append(prefixes, p)
		}
	}
	var src_prefix strings.Builder
	src_prefix.WriteString("src host ")
	var dst_prefix strings.Builder
	for i, prefix := range prefixes {
		if p := ParseBPFNetwork(prefix); p == "" {
			continue
		}
		sep := " or "
		if i == len(prefixes)-1 {
			sep = ""
		}
		fmt.Fprintf(&src_prefix, "%s%s", prefix, sep)
		fmt.Fprintf(&dst_prefix, "%s%s", prefix, sep)
	}
	// build source exclusions to src_prefix if supplied
	for _, ex := range l.cfg.NetworkExclusions {
		if e := ParseBPFNetwork(ex); e != "" {
			fmt.Fprintf(&src_prefix, " and not %s", e)
		}
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
		l.captureBytes = pcapFileHeaderSize
		l.log.Info(fmt.Sprintf("capturing packets to -> %s", l.cfg.CaptureFile))
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
			} else {
				l.captureBytes += pcapRecordHeader + int64(len(packet.Data()))
				if l.captureBytes >= maxCaptureFileSize {
					if err := l.flushCaptureFile(); err != nil {
						l.log.Error(fmt.Errorf("failed to flush capture file: %w", err))
					}
				}
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

// flushCaptureFile truncates the capture file and rewrites the pcap header,
// keeping disk usage bounded by maxCaptureFileSize.
func (l *IPRListener) flushCaptureFile() error {
	if _, err := l.captureFile.Seek(0, 0); err != nil {
		return fmt.Errorf("seek: %w", err)
	}
	if err := l.captureFile.Truncate(0); err != nil {
		return fmt.Errorf("truncate: %w", err)
	}
	w := pcapgo.NewWriter(l.captureFile)
	if err := w.WriteFileHeader(captureSnapLen, l.handle.LinkType()); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	l.captureW = w
	l.captureBytes = pcapFileHeaderSize
	l.log.Info(fmt.Sprintf("capture file reached %d bytes, flushed", maxCaptureFileSize))
	return nil
}

// setInterface finds the specified interface from config and sets on listener.
// returns error if fails to find
func (l *IPRListener) setInterface() error {
	var err error
	var iface *IPRInterface
	if l.cfg.Auto {
		iface, err = FindLANInterface()
		if err != nil {
			return err
		}
	} else {
		// find interface by name or index from config
		if index, err := strconv.Atoi(l.cfg.ListenInterface); err == nil {
			iface, err = GetInterfaceByIndex(index)
			if err != nil {
				return err
			}
		} else {
			iface, err = GetInterfaceByName(l.cfg.ListenInterface)
			if err != nil {
				return err
			}
		}
	}
	// sanity check to make sure that interface has UP flag
	if !iface.IsUp() {
		return fmt.Errorf("interface %s is not marked at UP", iface.FriendlyName)
	}
	l.iface = iface
	return nil
}
