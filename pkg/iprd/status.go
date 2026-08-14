package iprd

import (
	"sync"
	"sync/atomic"
	"time"
)

// ManagerState describes the current ListenerManager lifecycle state.
type ManagerState string

const (
	ManagerStateIdle     ManagerState = "idle"
	ManagerStateStarting ManagerState = "starting"
	ManagerStateHealthy  ManagerState = "healthy"
	ManagerStateDegraded ManagerState = "degraded"
	ManagerStateFailed   ManagerState = "failed"
	ManagerStateStopped  ManagerState = "stopped"
)

// ListenerState describes the current lifecycle state of an interface listener.
type ListenerState string

const (
	ListenerStateIdle         ListenerState = "idle"
	ListenerStateStarting     ListenerState = "starting"
	ListenerStateActive       ListenerState = "active"
	ListenerStateReconnecting ListenerState = "reconnecting"
	ListenerStateStopped      ListenerState = "stopped"
)

// PacketCounters contains cumulative packet outcomes for the lifetime of a manager.
// Reports counts validated reports produced by manager packet processing.
type PacketCounters struct {
	Processed       uint64 `json:"processed"`
	Reports         uint64 `json:"reports"`
	Invalid         uint64 `json:"invalid"`
	Duplicates      uint64 `json:"duplicates"`
	UnknownFiltered uint64 `json:"unknownFiltered"`
}

// ListenerStatus is a concurrency-safe snapshot of one interface listener.
type ListenerStatus struct {
	Interface          string        `json:"interface"`
	State              ListenerState `json:"state"`
	ActivationFailures uint64        `json:"activationFailures"`
	CaptureErrors      uint64        `json:"captureErrors"`
	Reconnects         uint64        `json:"reconnects"`
	LastError          string        `json:"lastError,omitempty"`
	LastErrorAt        time.Time     `json:"lastErrorAt,omitempty"`
}

// ManagerStatus is a concurrency-safe snapshot of a ListenerManager. Degraded
// means at least one listener is unavailable while the manager is still retrying;
// it can therefore have zero active listeners. Failed means Run has terminated
// with an error.
type ManagerStatus struct {
	State               ManagerState     `json:"state"`
	ListenersConfigured int              `json:"listenersConfigured"`
	ListenersActive     int              `json:"listenersActive"`
	ActivationFailures  uint64           `json:"activationFailures"`
	CaptureErrors       uint64           `json:"captureErrors"`
	Reconnects          uint64           `json:"reconnects"`
	CaptureWriteErrors  uint64           `json:"captureWriteErrors"`
	Packets             PacketCounters   `json:"packets"`
	Listeners           []ListenerStatus `json:"listeners"`
	LastPacketAt        time.Time        `json:"lastPacketAt,omitempty"`
	LastReportAt        time.Time        `json:"lastReportAt,omitempty"`
	LastError           string           `json:"lastError,omitempty"`
	LastErrorAt         time.Time        `json:"lastErrorAt,omitempty"`
}

type managerTelemetry struct {
	mu           sync.RWMutex
	state        ManagerState
	lastError    string
	lastErrorAt  time.Time
	lastPacketAt time.Time
	lastReportAt time.Time

	processed          atomic.Uint64
	reports            atomic.Uint64
	invalid            atomic.Uint64
	duplicates         atomic.Uint64
	unknownFiltered    atomic.Uint64
	captureWriteErrors atomic.Uint64
}

func newManagerTelemetry() managerTelemetry {
	return managerTelemetry{state: ManagerStateIdle}
}

func (t *managerTelemetry) setState(state ManagerState, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state = state
	if err != nil {
		t.lastError = err.Error()
		t.lastErrorAt = time.Now()
	}
}

func (t *managerTelemetry) recordPacket(at time.Time) {
	t.mu.Lock()
	if t.lastPacketAt.IsZero() || at.After(t.lastPacketAt) {
		t.lastPacketAt = at
	}
	t.mu.Unlock()
}

func (t *managerTelemetry) recordReport(at time.Time) {
	t.mu.Lock()
	if t.lastReportAt.IsZero() || at.After(t.lastReportAt) {
		t.lastReportAt = at
	}
	t.mu.Unlock()
	t.reports.Add(1)
}

func (t *managerTelemetry) snapshot() ManagerStatus {
	t.mu.RLock()
	status := ManagerStatus{
		State:              t.state,
		CaptureWriteErrors: t.captureWriteErrors.Load(),
		LastPacketAt:       t.lastPacketAt,
		LastReportAt:       t.lastReportAt,
		LastError:          t.lastError,
		LastErrorAt:        t.lastErrorAt,
	}
	t.mu.RUnlock()
	status.Packets = PacketCounters{
		Processed:       t.processed.Load(),
		Reports:         t.reports.Load(),
		Invalid:         t.invalid.Load(),
		Duplicates:      t.duplicates.Load(),
		UnknownFiltered: t.unknownFiltered.Load(),
	}
	return status
}

type listenerTelemetry struct {
	mu            sync.RWMutex
	interfaceName string
	state         ListenerState
	lastError     string
	lastErrorAt   time.Time

	activationFailures atomic.Uint64
	captureErrors      atomic.Uint64
	reconnects         atomic.Uint64
}

func newListenerTelemetry(interfaceName string) listenerTelemetry {
	return listenerTelemetry{
		interfaceName: interfaceName,
		state:         ListenerStateIdle,
	}
}

func (t *listenerTelemetry) setInterface(interfaceName string) {
	if interfaceName == "" {
		return
	}
	t.mu.Lock()
	t.interfaceName = interfaceName
	t.mu.Unlock()
}

func (t *listenerTelemetry) setState(state ListenerState, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.state = state
	if err != nil {
		t.lastError = err.Error()
		t.lastErrorAt = time.Now()
	}
}

func (t *listenerTelemetry) snapshot() ListenerStatus {
	t.mu.RLock()
	status := ListenerStatus{
		Interface:   t.interfaceName,
		State:       t.state,
		LastError:   t.lastError,
		LastErrorAt: t.lastErrorAt,
	}
	t.mu.RUnlock()
	status.ActivationFailures = t.activationFailures.Load()
	status.CaptureErrors = t.captureErrors.Load()
	status.Reconnects = t.reconnects.Load()
	return status
}
