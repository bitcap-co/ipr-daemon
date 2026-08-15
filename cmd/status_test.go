package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-json"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

func TestStatusHost(t *testing.T) {
	tests := []struct {
		bind string
		want string
	}{
		{"", "127.0.0.1"},
		{"0.0.0.0", "127.0.0.1"},
		{"::", "::1"},
		{"192.168.1.10", "192.168.1.10"},
		{"hostname", "hostname"},
	}
	for _, test := range tests {
		if got := statusHost(test.bind); got != test.want {
			t.Errorf("statusHost(%q) = %q, want %q", test.bind, got, test.want)
		}
	}
}

func TestRequestStatus(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		var command iprd.TCPCommand
		if err := json.NewDecoder(conn).Decode(&command); err != nil {
			serverErr <- err
			return
		}
		if command.Command != iprd.TCPCommandStatus {
			serverErr <- &unexpectedCommandError{command: command.Command}
			return
		}
		serverErr <- json.NewEncoder(conn).Encode(iprd.TCPResponse{
			Type:      iprd.TCPCommandStatus,
			Timestamp: time.Now().Unix(),
			Status:    &iprd.ManagerStatus{State: iprd.ManagerStateHealthy},
		})
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	response, err := requestStatus("127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status == nil || response.Status.State != iprd.ManagerStateHealthy {
		t.Fatalf("response = %+v", response)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

type unexpectedCommandError struct {
	command string
}

func (e *unexpectedCommandError) Error() string {
	return "unexpected command: " + e.command
}

func TestWriteStatus(t *testing.T) {
	response := iprd.TCPResponse{
		Type:      iprd.TCPCommandStatus,
		Timestamp: time.Now().Unix(),
		Status: &iprd.ManagerStatus{
			State:               iprd.ManagerStateDegraded,
			ListenersConfigured: 2,
			ListenersActive:     1,
			ActivationFailures:  1,
			Reconnects:          1,
			Packets: iprd.PacketCounters{
				Processed:       10,
				Reports:         6,
				Invalid:         1,
				Duplicates:      2,
				UnknownFiltered: 1,
			},
			Listeners: []iprd.ListenerStatus{
				{Interface: "eth0", State: iprd.ListenerStateActive},
				{Interface: "eth1", State: iprd.ListenerStateReconnecting, LastError: "interface unavailable"},
			},
		},
	}

	var human bytes.Buffer
	if err := writeStatus(&human, response, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"IP Report status: degraded",
		"Listeners: 1/2 active",
		"Packets: 10 processed, 6 reports, 2 duplicates, 1 invalid, 1 filtered",
		"eth1: reconnecting",
	} {
		if !strings.Contains(human.String(), want) {
			t.Errorf("human status missing %q:\n%s", want, human.String())
		}
	}

	var output bytes.Buffer
	if err := writeStatus(&output, response, true); err != nil {
		t.Fatal(err)
	}
	var decoded iprd.TCPResponse
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Status == nil || decoded.Status.Packets.Processed != 10 {
		t.Fatalf("JSON status = %+v", decoded.Status)
	}
}
