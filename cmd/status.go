package main

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/goccy/go-json"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

const statusRequestTimeout = 5 * time.Second

func statusHost(bind string) string {
	if bind == "" {
		return "127.0.0.1"
	}
	ip := net.ParseIP(bind)
	if ip == nil || !ip.IsUnspecified() {
		return bind
	}
	if ip.To4() == nil {
		return "::1"
	}
	return "127.0.0.1"
}

func requestStatus(bind string, port int) (iprd.TCPResponse, error) {
	address := net.JoinHostPort(statusHost(bind), strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, statusRequestTimeout)
	if err != nil {
		return iprd.TCPResponse{}, fmt.Errorf("connect to %s: %w", address, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(statusRequestTimeout)); err != nil {
		return iprd.TCPResponse{}, err
	}

	request := iprd.TCPCommand{Command: iprd.TCPCommandStatus}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return iprd.TCPResponse{}, fmt.Errorf("send status request: %w", err)
	}

	var response iprd.TCPResponse
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return iprd.TCPResponse{}, fmt.Errorf("read status response: %w", err)
	}
	if response.Error != "" {
		return iprd.TCPResponse{}, fmt.Errorf("status request: %s", response.Error)
	}
	if response.Type != iprd.TCPCommandStatus || response.Status == nil {
		return iprd.TCPResponse{}, fmt.Errorf("invalid status response")
	}
	return response, nil
}

func writeStatus(w io.Writer, response iprd.TCPResponse, asJSON bool) error {
	if asJSON {
		data, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(data))
		return err
	}

	status := response.Status
	if status == nil {
		return fmt.Errorf("status response is empty")
	}
	if _, err := fmt.Fprintf(w, "IP Report status: %s\n", status.State); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Listeners: %d/%d active\n", status.ListenersActive, status.ListenersConfigured); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Packets: %d processed, %d reports, %d duplicates, %d invalid, %d filtered\n",
		status.Packets.Processed, status.Packets.Reports, status.Packets.Duplicates,
		status.Packets.Invalid, status.Packets.UnknownFiltered); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Errors: %d activation, %d capture, %d capture-write; %d reconnects\n",
		status.ActivationFailures, status.CaptureErrors, status.CaptureWriteErrors, status.Reconnects); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Last packet: %s\n", formatStatusTime(status.LastPacketAt)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Last report: %s\n", formatStatusTime(status.LastReportAt)); err != nil {
		return err
	}
	if status.LastError != "" {
		if _, err := fmt.Fprintf(w, "Last error: %s (%s)\n", status.LastError, formatStatusTime(status.LastErrorAt)); err != nil {
			return err
		}
	}
	for _, listener := range status.Listeners {
		if _, err := fmt.Fprintf(w, "\n%s: %s", listener.Interface, listener.State); err != nil {
			return err
		}
		if listener.LastError != "" {
			if _, err := fmt.Fprintf(w, " — %s", listener.LastError); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}
	return nil
}

func formatStatusTime(value time.Time) string {
	if value.IsZero() {
		return "never"
	}
	return value.Local().Format(time.RFC3339)
}
