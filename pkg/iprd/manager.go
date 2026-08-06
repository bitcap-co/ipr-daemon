package iprd

import (
	"context"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

// ListenerManager coordinates capture and packet processing. It currently
// supervises the first configured interface; additional listeners will be
// added after capture-file ownership moves out of IPRListener.
type ListenerManager struct {
	cfg       *IPRDConfig
	log       *IPRLogger
	listener  *IPRListener
	processor *PacketProcessor
	capture   *CaptureWriter
	broadcast chan []byte
}

// NewListenerManager returns a manager for the first configured interface.
func NewListenerManager(cfg *IPRDConfig, logger *IPRLogger) *ListenerManager {
	if cfg == nil {
		cfg = DefaultIPRDConfig()
	}
	if logger == nil {
		logger = NewLogger()
	}
	managerCfg := *cfg
	managerCfg.normalizeListenInterfaces()
	capture := NewCaptureWriter(managerCfg.CaptureFile, managerCfg.RotateCaptureFiles, logger)
	managerCfg.CaptureFile = capture.Path()
	cfg = &managerCfg
	return &ListenerManager{
		cfg:       cfg,
		log:       logger,
		listener:  NewListener(cfg, logger, nil),
		processor: NewPacketProcessor(nil),
		capture:   capture,
		broadcast: make(chan []byte),
	}
}

// Broadcast returns the manager's combined stream of marshalled IP reports.
func (m *ListenerManager) Broadcast() <-chan []byte {
	return m.broadcast
}

// Run processes captured packets while supervising the listener. It returns
// when ctx is cancelled or the listener encounters a fatal configuration error.
func (m *ListenerManager) Run(ctx context.Context) error {
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
	processingDone := make(chan struct{})
	go func() {
		defer close(processingDone)
		m.processPackets(runCtx)
	}()

	err := m.listener.Run(runCtx)
	cancel()
	<-processingDone
	return errors.Join(err, m.capture.Close())
}

func (m *ListenerManager) processPackets(ctx context.Context) {
	for {
		select {
		case captured := <-m.listener.Packets():
			if err := m.capture.Write(captured); err != nil {
				m.log.Error(fmt.Errorf("failed to write packet to capture file: %w", err))
			}
			if msg := m.processCapturedPacket(captured); msg != nil {
				select {
				case m.broadcast <- msg:
				case <-ctx.Done():
					return
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func (m *ListenerManager) processCapturedPacket(captured CapturedPacket) []byte {
	packet := gopacket.NewPacket(captured.Data, captured.LinkType, gopacket.Default)
	packet.Metadata().CaptureInfo = captured.CaptureInfo

	ipr, err := NewIPReportPacket(packet)
	if err != nil {
		return nil
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
	msg, err := ipr.Marshal()
	if err != nil {
		m.log.Error(fmt.Errorf("failed to marshal packet: %w", err))
		return nil
	}
	return msg
}
