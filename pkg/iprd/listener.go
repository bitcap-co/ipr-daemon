package iprd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

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
	// captureTimeout bounds a single blocking read so the capture loop can
	// periodically check for shutdown/cancellation rather than block forever.
	captureTimeout = time.Second
	// reconnect backoff bounds for the supervised Run loop.
	reconnectMinBackoff = time.Second
	reconnectMaxBackoff = 30 * time.Second
)

const (
	bpfTemplate string = "(%s and (dst net 255 or %s) and udp src portrange 1024-65535 and udp dst portrange 1024-65535"
)

type IPRListener struct {
	cfg          *IPRDConfig
	log          *IPRLogger
	iface        *IPRInterface
	ifacePinned  bool
	resolvedName string
	inactive     *pcap.InactiveHandle
	handle       *pcap.Handle
	ch           chan []byte
	captureFile  *os.File
	captureW     *pcapgo.Writer
	captureBytes int64
}

// NewListener returns a new IPRListener, taking in a IPRDConfig to configure behavior. If logger is nil, a new IPRLogger is created.
// If iface is supplied it is pinned and reused; otherwise the interface is resolved from cfg (and re-resolved on each reconnect).
func NewListener(cfg *IPRDConfig, logger *IPRLogger, iface *IPRInterface) *IPRListener {
	if cfg == nil {
		// pass in default config if not supplied
		cfg = DefaultIPRDConfig()
	}
	if logger == nil {
		logger = NewLogger()
	}

	return &IPRListener{
		cfg:         cfg,
		log:         logger,
		iface:       iface,
		ifacePinned: iface != nil,
		ch:          make(chan []byte),
	}
}

// Broadcast returns a channel of messages for broadcasting.
func (l *IPRListener) Broadcast() chan []byte {
	return l.ch
}

func (l *IPRListener) setupBPF(root string) error {
	// build networks into expression
	var networks = []string{}
	if !l.cfg.NoRootNetwork {
		networks = append(networks, root)
	}
	for _, prefix := range l.cfg.NetworkInclusions {
		if p := ParseBPFNetwork(prefix); p != "" {
			networks = append(networks, p)
		}
	}

	var src_prefix strings.Builder
	src_prefix.WriteString("src host ")
	var dst_prefix strings.Builder
	for i, p := range networks {
		sep := " or "
		if i == len(networks)-1 {
			sep = ""
		}
		fmt.Fprintf(&src_prefix, "%s%s", p, sep)
		fmt.Fprintf(&dst_prefix, "%s%s", p, sep)
	}

	// build source network exclusions
	for _, ex := range l.cfg.NetworkExclusions {
		if p := ParseBPFNetwork(ex); p != "" {
			fmt.Fprintf(&src_prefix, " and not %s", p)
		}
	}
	fmt.Fprint(&src_prefix, ")")

	// build source MAC addresses to exclude (ignored addresses)
	var ignored = []string{}
	for _, mac := range l.cfg.IgnoredDevices {
		if m := ParseMACAddress(mac); m != "" {
			ignored = append(ignored, m)
		}
	}
	if len(ignored) > 0 {
		var ignore_addrs strings.Builder
		ignore_addrs.WriteString(" and not (ether src ")
		for i, mac := range ignored {
			sep := " or "
			if i == len(ignored)-1 {
				sep = ""
			}
			fmt.Fprintf(&ignore_addrs, "%s%s", mac, sep)
		}
		fmt.Fprint(&ignore_addrs, ")")
		fmt.Fprint(&src_prefix, ignore_addrs.String())
	}

	bpfExpr := fmt.Sprintf(bpfTemplate, src_prefix.String(), dst_prefix.String())
	if err := l.handle.SetBPFFilter(bpfExpr); err != nil {
		return fmt.Errorf("failed to set BPF expression: %w", err)
	}
	l.log.Info(fmt.Sprintf("set BPF filter expression: %s", bpfExpr))
	return nil
}

// setupHandle resolves the interface (if not already set), opens and activates a new
// pcap handle, and installs the BPF filter. It leaves l.handle ready for capture.
func (l *IPRListener) setupHandle() error {
	var err error
	if l.iface == nil {
		if err = l.setInterface(); err != nil {
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
	} else if err = l.inactive.SetTimeout(captureTimeout); err != nil {
		return fmt.Errorf("could not set timeout: %w", err)
	}
	if l.handle, err = l.inactive.Activate(); err != nil {
		return fmt.Errorf("failed to activate handle: %w", err)
	}
	l.log.Info(fmt.Sprintf("activate handle on interface: %s (%s)", l.iface.FriendlyName, l.iface.MACAddr()))

	if err = l.setupBPF(l.iface.NetworkPrefix()); err != nil {
		return err
	}
	return nil
}

// logStartupModes logs enabled one-off modes (debug, forward-known).
func (l *IPRListener) logStartupModes() {
	if l.cfg.Debug {
		l.log.Debug("--- DEBUG OUTPUT ON ---")
	}
	if l.cfg.ForwardKnown {
		l.log.Info("fowarding known ports only")
	}
}

// openCaptureFile opens the PCAP capture file if configured. It is idempotent:
// once opened the writer persists across reconnects so captures are not truncated.
// Requires an active handle (for the link type).
func (l *IPRListener) openCaptureFile() error {
	if l.cfg.CaptureFile == "" || l.captureFile != nil {
		return nil
	}
	l.cfg.CaptureFile = strings.Split(l.cfg.CaptureFile, ".")[0]
	l.cfg.CaptureFile = l.cfg.CaptureFile + ".pcap"
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
	return nil
}

func (l *IPRListener) closeCaptureFile() {
	if l.captureFile != nil {
		l.captureFile.Close()
		l.captureFile = nil
	}
}

func (l *IPRListener) closeHandle() {
	if l.handle != nil {
		l.handle.Close()
		l.handle = nil
	}
}

// Activate sets a new active pcap handle on iface. This must be called once before Listen().
func (l *IPRListener) Activate() error {
	if err := l.setupHandle(); err != nil {
		return err
	}
	l.logStartupModes()
	return l.openCaptureFile()
}

// Run supervises capture on the interface: it activates a handle, captures until the
// handle errors (e.g. the interface goes down/away) or ctx is cancelled, and on error
// re-resolves the interface and re-activates with exponential backoff. It returns when
// ctx is cancelled. The broadcast channel and any downstream consumers stay intact
// across reconnects. Run is the resilient alternative to Activate()+Listen().
func (l *IPRListener) Run(ctx context.Context) error {
	l.logStartupModes()
	defer l.closeCaptureFile()
	defer l.closeHandle()

	backoff := reconnectMinBackoff
	for {
		if err := l.activateForRun(); err != nil {
			l.log.Warn(fmt.Sprintf("failed to activate capture: %v; retrying in %s", err, backoff))
			if !sleepCtx(ctx, backoff) {
				return nil
			}
			backoff = nextBackoff(backoff)
			continue
		}
		// a bad capture-file path is a hard configuration error, not transient.
		if err := l.openCaptureFile(); err != nil {
			l.closeHandle()
			return err
		}
		backoff = reconnectMinBackoff

		capErr := l.capture(ctx)
		l.closeHandle()
		if ctx.Err() != nil {
			return nil
		}
		if capErr != nil {
			l.log.Warn(fmt.Sprintf("capture stopped: %v; reconnecting in %s", capErr, backoff))
		} else {
			l.log.Warn(fmt.Sprintf("capture ended; reconnecting in %s", backoff))
		}
		if !sleepCtx(ctx, backoff) {
			return nil
		}
		backoff = nextBackoff(backoff)
	}
}

// activateForRun re-resolves the interface (unless pinned at construction) so a changed
// index or LAN re-detection is picked up, then opens a fresh handle.
func (l *IPRListener) activateForRun() error {
	if !l.ifacePinned {
		l.iface = nil
	}
	return l.setupHandle()
}

// Listen will start reading packets from the active handle and sends the marshalled IPReportPacket to Broadcast().
// It blocks until the handle errors. For a resilient, self-reconnecting listener use Run().
func (l *IPRListener) Listen() {
	defer l.closeHandle()
	defer l.closeCaptureFile()
	l.log.Info("start listen...")
	if err := l.capture(context.Background()); err != nil {
		l.log.Error(fmt.Errorf("capture stopped: %w", err))
	}
}

// capture reads packets from the active handle until ctx is cancelled (returns nil) or
// a read error occurs (returns the error, so the caller can decide to reconnect).
func (l *IPRListener) capture(ctx context.Context) error {
	linkType := l.handle.LinkType()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		data, ci, err := l.handle.ReadPacketData()
		if err != nil {
			// timeout just means no packet arrived within captureTimeout; loop.
			if errors.Is(err, pcap.NextErrorTimeoutExpired) {
				continue
			}
			return err
		}

		if l.captureW != nil {
			if werr := l.captureW.WritePacket(ci, data); werr != nil {
				l.log.Error(fmt.Errorf("failed to write packet to capture file: %w", werr))
			} else {
				l.captureBytes += pcapRecordHeader + int64(len(data))
				if l.captureBytes >= maxCaptureFileSize {
					if ferr := l.flushCaptureFile(); ferr != nil {
						l.log.Error(fmt.Errorf("failed to flush capture file: %w", ferr))
					}
				}
			}
		}

		packet := gopacket.NewPacket(data, linkType, gopacket.Default)
		packet.Metadata().CaptureInfo = ci

		// try and initialize as IPReportPacket.
		r, _ := NewIPReportPacket(packet)
		if r == nil {
			// invalid layer or empty UDP paylaod.
			continue
		}
		// parse IPReportPacket to validate that it is an IP Report packet.
		if err := ParseIPReportPacket(r); err != nil {
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
		if l.cfg.ForwardKnown {
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
		select {
		case l.ch <- msg:
		case <-ctx.Done():
			return nil
		}
	}
}

// sleepCtx waits for d or until ctx is cancelled. Returns false if ctx was cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// nextBackoff doubles cur, capped at reconnectMaxBackoff.
func nextBackoff(cur time.Duration) time.Duration {
	next := cur * 2
	if next > reconnectMaxBackoff {
		return reconnectMaxBackoff
	}
	return next
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
// returns error if fails to find.
//
// Once an interface has been resolved via an explicit -i selection, subsequent calls
// re-resolve by the cached interface name rather than the original selector: interface
// indexes are ephemeral (a removed/recreated interface gets a new index), so re-resolving
// by index would never recover on reconnect. Auto mode always re-detects via the LAN
// description match.
func (l *IPRListener) setInterface() error {
	var iface *IPRInterface
	var err error
	switch {
	case l.cfg.Auto:
		iface, err = FindLANInterface()
	case l.resolvedName != "":
		iface, err = GetInterfaceByName(l.resolvedName)
	default:
		// find interface by name or index from config
		if index, aerr := strconv.Atoi(l.cfg.ListenInterface); aerr == nil {
			iface, err = GetInterfaceByIndex(index)
		} else {
			iface, err = GetInterfaceByName(l.cfg.ListenInterface)
		}
	}
	if err != nil {
		return err
	}
	// sanity check to make sure that interface has UP flag
	if !iface.IsUp() {
		return fmt.Errorf("interface %s is not marked at UP", iface.FriendlyName)
	}
	l.iface = iface
	if !l.cfg.Auto {
		l.resolvedName = iface.Name
	}
	return nil
}
