package iprd

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gopacket/gopacket/pcap"
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
	cfg          *ListenerConfig
	log          Logger
	iface        *IPRInterface
	ifacePinned  bool
	resolvedName string
	inactive     *pcap.InactiveHandle
	handle       *pcap.Handle
	packets      chan CapturedPacket
}

// NewListener returns a new IPRListener configured by ListenerConfig. If logger is nil, a new IPRLogger is created.
// If iface is supplied it is pinned and reused; otherwise the interface is resolved from cfg (and re-resolved on each reconnect).
func NewListener(cfg *ListenerConfig, logger Logger, iface *IPRInterface) *IPRListener {
	if cfg == nil {
		cfg = DefaultListenerConfig()
	}
	if logger == nil {
		logger = NewLogger()
	}

	return &IPRListener{
		cfg:         cfg,
		log:         logger,
		iface:       iface,
		ifacePinned: iface != nil,
		packets:     make(chan CapturedPacket),
	}
}

// Packets returns the listener's stream of raw captured packets.
func (l *IPRListener) Packets() <-chan CapturedPacket {
	return l.packets
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

func (l *IPRListener) closeHandle() {
	if l.handle != nil {
		l.handle.Close()
		l.handle = nil
	}
}

// Activate sets a new active pcap handle on iface. This must be called once before Listen().
func (l *IPRListener) Activate() error {
	return l.setupHandle()
}

// Run supervises capture on the interface: it activates a handle, captures until the
// handle errors (e.g. the interface goes down/away) or ctx is cancelled, and on error
// re-resolves the interface and re-activates with exponential backoff. It returns when
// ctx is cancelled. The packet channel and any downstream consumers stay intact
// across reconnects. Run is the resilient alternative to Activate()+Listen().
func (l *IPRListener) Run(ctx context.Context) error {
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

// Listen starts reading packets from the active handle and sends raw capture
// events to Packets(). It blocks until the handle errors. For a resilient,
// self-reconnecting listener use Run().
func (l *IPRListener) Listen() {
	defer l.closeHandle()
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

		eventCI := ci
		eventCI.InterfaceIndex = l.iface.Index
		captured := CapturedPacket{
			Data:        data,
			CaptureInfo: eventCI,
			LinkType:    linkType,
			Interface:   *l.iface,
		}
		select {
		case l.packets <- captured:
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
