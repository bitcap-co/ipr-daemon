package iprd

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/goccy/go-json"
)

type staticStatusProvider struct {
	status ManagerStatus
}

func (p staticStatusProvider) Status() ManagerStatus {
	return p.status
}

func newTestBroadcaster() *IPRBroadcast {
	return &IPRBroadcast{
		logger:  NewLogger(),
		clients: make(map[uint64]net.Conn),
		Msgs:    make(chan []byte),
		Errs:    make(chan error, 1),
	}
}

func exchangeTCPCommand(t *testing.T, broadcaster *IPRBroadcast, command TCPCommand) TCPResponse {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		broadcaster.handleConnection(server)
	}()
	defer client.Close()

	if err := json.NewEncoder(client).Encode(command); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(client).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var response TCPResponse
	if err := json.Unmarshal(line, &response); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection handler did not close after command response")
	}
	return response
}

func TestIPRBroadcastStatusCommand(t *testing.T) {
	broadcaster := newTestBroadcaster()
	want := ManagerStatus{
		State:               ManagerStateHealthy,
		ListenersConfigured: 2,
		ListenersActive:     2,
		Packets: PacketCounters{
			Processed:  9,
			Reports:    6,
			Invalid:    1,
			Duplicates: 2,
		},
	}
	broadcaster.SetStatusProvider(staticStatusProvider{status: want})

	response := exchangeTCPCommand(t, broadcaster, TCPCommand{
		Command:   TCPCommandStatus,
		RequestID: "status-1",
	})
	if response.Type != TCPCommandStatus {
		t.Fatalf("response type = %q, want %q", response.Type, TCPCommandStatus)
	}
	if response.RequestID != "status-1" {
		t.Fatalf("request ID = %q, want status-1", response.RequestID)
	}
	if response.Timestamp == 0 {
		t.Fatal("response timestamp was not populated")
	}
	if response.Error != "" {
		t.Fatalf("response error = %q", response.Error)
	}
	if response.Status == nil || response.Status.State != want.State || response.Status.Packets != want.Packets {
		t.Fatalf("response status = %+v, want %+v", response.Status, want)
	}
}

func TestIPRBroadcastStatusUnavailable(t *testing.T) {
	response := exchangeTCPCommand(t, newTestBroadcaster(), TCPCommand{Command: TCPCommandStatus})
	if response.Type != TCPCommandStatus || response.Error != "status unavailable" || response.Status != nil {
		t.Fatalf("response = %+v", response)
	}
}

func TestIPRBroadcastSubscribeStillRegistersClient(t *testing.T) {
	broadcaster := newTestBroadcaster()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		broadcaster.handleConnection(server)
	}()

	if _, err := client.Write([]byte("not-json\n")); err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(client).Encode(TCPCommand{Command: "unknown_command"}); err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(client).Encode(TCPCommand{Command: TCPCommandSubscribe}); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(time.Second)
	for {
		broadcaster.mu.RLock()
		count := len(broadcaster.clients)
		broadcaster.mu.RUnlock()
		if count == 1 {
			break
		}
		select {
		case <-deadline:
			client.Close()
			t.Fatal("subscriber was not registered")
		case <-time.After(time.Millisecond):
		}
	}

	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("subscriber connection handler did not stop")
	}
	broadcaster.mu.RLock()
	count := len(broadcaster.clients)
	broadcaster.mu.RUnlock()
	if count != 0 {
		t.Fatalf("subscribers after disconnect = %d, want 0", count)
	}
}
