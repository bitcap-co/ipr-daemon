package iprd

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/gopacket/gopacket"
)

var ErrListenerManagerAlreadyStarted = errors.New("listener manager may only be run once")

// ListenerManager coordinates interface listeners, capture writing, packet
// processing, and a single combined IP report stream.
type ListenerManager struct {
	cfg       *ListenerConfig
	log       Logger
	listeners []*IPRListener
	processor *PacketProcessor
	capture   *CaptureWriter
	reports   chan *IPReportPacket
	runOnce   sync.Once
}

// NewListenerManager returns a manager with one listener per configured
// interface. Auto mode creates one listener and ignores explicit selectors.
func NewListenerManager(cfg *ListenerConfig, logger Logger) (*ListenerManager, error) {
	if cfg == nil {
		cfg = DefaultListenerConfig()
	}
	if logger == nil {
		logger = NewLogger()
	}
	managerCfg := *cfg
	managerCfg.normalizeListenInterfaces()

	if err := managerCfg.Validate(); err != nil {
		return nil, fmt.Errorf("listener config: %w", err)
	}
	capture := NewCaptureWriter(managerCfg.CaptureFile, managerCfg.RotateCaptureFiles, logger)
	managerCfg.CaptureFile = capture.Path()
	cfg = &managerCfg
	return &ListenerManager{
		cfg:       cfg,
		log:       logger,
		listeners: newManagedListeners(cfg, logger),
		processor: NewPacketProcessor(nil),
		capture:   capture,
		reports:   make(chan *IPReportPacket, 256),
	}, nil
}

// Reports returns the manager's combined stream of validated IP reports.
// The stream is buffered; if the consumer falls behind and the buffer fills,
// packet processing applies backpressure until reports are consumed.
func (m *ListenerManager) Reports() <-chan *IPReportPacket {
	return m.reports
}

// Run processes captured packets while supervising every listener. Each
// listener reconnects independently; an unexpected listener termination stops
// the manager. Run returns when ctx is cancelled or a fatal error occurs.
// A manager may only be run once; Reports is closed before the first call returns.
func (m *ListenerManager) Run(ctx context.Context) error {
	started := false
	m.runOnce.Do(func() {
		started = true
	})
	if !started {
		return ErrListenerManagerAlreadyStarted
	}
	defer close(m.reports)

	if len(m.listeners) == 0 {
		return fmt.Errorf("no interfaces configured")
	}
	if err := m.capture.Open(); err != nil {
		return err
	}
	if m.cfg.Debug {
		m.log.Debug("--- DEBUG OUTPUT ON ---")
	}
	if m.cfg.ForwardKnown {
		m.log.Info("forwarding known ports only")
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	captures := make(chan CapturedPacket)
	results := make(chan error, len(m.listeners))
	var listenersDone sync.WaitGroup
	for _, listener := range m.listeners {
		listenersDone.Add(2)
		go func() {
			defer listenersDone.Done()
			results <- listener.Run(runCtx)
		}()
		go func() {
			defer listenersDone.Done()
			forwardCapturedPackets(runCtx, listener.Packets(), captures)
		}()
	}

	processingDone := make(chan struct{})
	go func() {
		defer close(processingDone)
		m.processPackets(runCtx, captures)
	}()
	m.log.Info(fmt.Sprintf("supervising %d interface listener(s)", len(m.listeners)))

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-results:
		if ctx.Err() == nil {
			if err == nil {
				runErr = fmt.Errorf("interface listener stopped unexpectedly")
			} else {
				runErr = fmt.Errorf("interface listener stopped: %w", err)
			}
		}
	}
	cancel()
	listenersDone.Wait()
	<-processingDone
	return errors.Join(runErr, m.capture.Close())
}

func newManagedListeners(cfg *ListenerConfig, logger Logger) []*IPRListener {
	selectors := cfg.ListenInterfaces
	if cfg.Auto && len(selectors) > 1 {
		selectors = selectors[:1]
	}
	listeners := make([]*IPRListener, 0, len(selectors))
	for _, selector := range selectors {
		listenerCfg := *cfg
		listenerCfg.ListenInterfaces = []string{selector}
		listenerCfg.ListenInterface = selector
		bpfCfg := cfg.interfaceConfig(selector)
		listenerCfg.NoRootNetwork = bpfCfg.NoRootNetwork
		listenerCfg.IgnoredDevices = bpfCfg.IgnoredDevices
		listenerCfg.NetworkInclusions = bpfCfg.NetworkInclusions
		listenerCfg.NetworkExclusions = bpfCfg.NetworkExclusions
		listeners = append(listeners, NewListener(&listenerCfg, logger, nil))
	}
	return listeners
}

func forwardCapturedPackets(ctx context.Context, packets <-chan CapturedPacket, captures chan<- CapturedPacket) {
	for {
		select {
		case captured := <-packets:
			select {
			case captures <- captured:
			case <-ctx.Done():
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (m *ListenerManager) processPackets(ctx context.Context, captures <-chan CapturedPacket) {
	for {
		select {
		case captured := <-captures:
			if err := m.capture.Write(captured); err != nil {
				m.log.Error(fmt.Errorf("failed to write packet to capture file: %w", err))
			}
			if report := m.processCapturedPacket(captured); report != nil {
				select {
				case m.reports <- report:
				case <-ctx.Done():
					return
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func (m *ListenerManager) processCapturedPacket(captured CapturedPacket) *IPReportPacket {
	packet := gopacket.NewPacket(captured.Data, captured.LinkType, gopacket.Default)
	packet.Metadata().CaptureInfo = captured.CaptureInfo

	ipr, err := NewIPReportPacket(packet)
	if err != nil {
		return nil
	}
	ipr.InterfaceName = captured.Interface.Name
	if ipr.InterfaceName == "" {
		ipr.InterfaceName = captured.Interface.FriendlyName
	}
	if ipr.InterfaceName == "" {
		ipr.InterfaceName = fmt.Sprintf("#%d", captured.Interface.Index)
	}
	if err := m.processor.ParseIPReportPacket(ipr); err != nil {
		if errors.Is(err, ErrDuplicatePacket) {
			m.log.Warn(fmt.Sprintf("%s - %s", ipr.String(), err))
		}
		if m.cfg.Debug {
			m.log.Error(fmt.Errorf("%s - not valid: %w", ipr.String(), err))
			m.log.Debug("--- PACKET DUMP ---")
			m.log.Debug(fmt.Sprintf("%s\n", packet.Dump()))
		}
		return nil
	}
	if m.cfg.ForwardKnown && ipr.MinerHint == UnknownType {
		m.log.Warn(fmt.Sprintf("received unknown IP Report %s", ipr.String()))
		return nil
	}

	m.log.Info(fmt.Sprintf("received IP Report %s", ipr.String()))
	if m.cfg.Debug {
		m.log.Debug(fmt.Sprintf("UDP Payload (%d) -> %s", ipr.CaptureLength, ipr.Payload))
	}
	return ipr
}
