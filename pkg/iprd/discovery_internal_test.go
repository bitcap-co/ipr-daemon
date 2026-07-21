package iprd

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestNewMDNSService(t *testing.T) {
	service, err := newMDNSService("iprd-host.local", 7788, "0.4.6")
	if err != nil {
		t.Fatalf("newMDNSService() error = %v", err)
	}
	if got, want := service.Type.String(), "_iprd._tcp.local"; got != want {
		t.Errorf("service type = %q, want %q", got, want)
	}
	if got, want := service.Name, "IPR Daemon on iprd-host-local (7788)"; got != want {
		t.Errorf("service name = %q, want %q", got, want)
	}
	if got, want := service.Port, uint16(7788); got != want {
		t.Errorf("service port = %d, want %d", got, want)
	}
	if got, want := service.Hostname, "iprd-host-local.local"; got != want {
		t.Errorf("service hostname = %q, want %q", got, want)
	}
	wantText := []string{
		"txtvers=1",
		"protocol=iprd",
		"subscribe=iprd_subscribe",
		"version=0.4.6",
	}
	if !reflect.DeepEqual(service.Text, wantText) {
		t.Errorf("service text = %#v, want %#v", service.Text, wantText)
	}
}

func TestNewMDNSServiceOmitsUnknownVersion(t *testing.T) {
	service, err := newMDNSService("iprd-host", 7788, "unknown")
	if err != nil {
		t.Fatalf("newMDNSService() error = %v", err)
	}
	want := []string{"txtvers=1", "protocol=iprd", "subscribe=iprd_subscribe"}
	if !reflect.DeepEqual(service.Text, want) {
		t.Errorf("service text = %#v, want %#v", service.Text, want)
	}
}

func TestSanitizeMDNSInstanceHost(t *testing.T) {
	if got, want := sanitizeMDNSInstanceHost(" miner.example.local. "), "miner-example-local"; got != want {
		t.Errorf("sanitizeMDNSInstanceHost() = %q, want %q", got, want)
	}
	if got, want := sanitizeMDNSInstanceHost("矿机"), "unknown-host"; got != want {
		t.Errorf("sanitizeMDNSInstanceHost() = %q, want %q", got, want)
	}
	got := sanitizeMDNSInstanceHost("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	if len(got) != 40 {
		t.Errorf("sanitized hostname length = %d, want 40", len(got))
	}
}

func TestNewMDNSServiceRejectsInvalidPort(t *testing.T) {
	for _, port := range []int{0, -1, 65536} {
		if _, err := newMDNSService("iprd-host", port, ""); err == nil {
			t.Errorf("newMDNSService(port=%d) returned nil error", port)
		}
	}
}

func TestParseMDNSBind(t *testing.T) {
	tests := []struct {
		name         string
		bind         string
		want         netip.Addr
		wantExplicit bool
		wantErr      bool
	}{
		{name: "empty wildcard"},
		{name: "IPv4 wildcard", bind: "0.0.0.0"},
		{name: "IPv6 wildcard", bind: "::"},
		{name: "private IPv4", bind: "192.168.1.20", want: netip.MustParseAddr("192.168.1.20"), wantExplicit: true},
		{name: "IPv4 mapped", bind: "::ffff:192.168.1.20", want: netip.MustParseAddr("192.168.1.20"), wantExplicit: true},
		{name: "loopback", bind: "127.0.0.1", wantErr: true},
		{name: "multicast", bind: "224.0.0.251", wantErr: true},
		{name: "invalid", bind: "not-an-ip", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, explicit, err := parseMDNSBind(tt.bind)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseMDNSBind(%q) error = %v, wantErr %v", tt.bind, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got != tt.want || explicit != tt.wantExplicit {
				t.Errorf("parseMDNSBind(%q) = (%v, %v), want (%v, %v)", tt.bind, got, explicit, tt.want, tt.wantExplicit)
			}
		})
	}
}
