package iprd

import (
	"net"
	"net/netip"
	"reflect"
	"testing"
)

func TestIsOperationalMulticastInterface(t *testing.T) {
	required := net.FlagUp | net.FlagRunning | net.FlagMulticast
	tests := []struct {
		name  string
		flags net.Flags
		want  bool
	}{
		{name: "all required flags", flags: required, want: true},
		{name: "additional flags", flags: required | net.FlagBroadcast, want: true},
		{name: "not administratively up", flags: net.FlagRunning | net.FlagMulticast},
		{name: "not running", flags: net.FlagUp | net.FlagMulticast},
		{name: "no multicast", flags: net.FlagUp | net.FlagRunning},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iface := net.Interface{Flags: tt.flags}
			if got := isOperationalMulticast(iface); got != tt.want {
				t.Errorf("isOperationalMulticast() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterOperationalMulticastInterfaces(t *testing.T) {
	required := net.FlagUp | net.FlagRunning | net.FlagMulticast
	ifaces := []net.Interface{
		{Index: 1, Name: "eth0", Flags: required},
		{Index: 2, Name: "virbr0", Flags: net.FlagUp | net.FlagMulticast},
		{Index: 3, Name: "down0", Flags: net.FlagRunning | net.FlagMulticast},
		{Index: 4, Name: "wlan0", Flags: required | net.FlagBroadcast},
	}

	got := filterOperationalMulticastInterfaces(ifaces)
	want := []net.Interface{ifaces[0], ifaces[3]}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("filterOperationalMulticastInterfaces() = %#v, want %#v", got, want)
	}
}

func TestReloadOnMDNSInterfaceChange(t *testing.T) {
	previous := []mdnsInterfaceState{{
		Index:     2,
		Name:      "eth0",
		Flags:     net.FlagUp | net.FlagRunning | net.FlagMulticast,
		Addresses: []string{"192.168.1.107/24"},
	}}
	reloads := 0
	reload := func() { reloads++ }

	got := reloadOnMDNSInterfaceChange(previous, previous, reload)
	if reloads != 0 {
		t.Fatalf("unchanged state triggered %d reload(s), want 0", reloads)
	}
	if !reflect.DeepEqual(got, previous) {
		t.Fatalf("unchanged state returned %#v, want %#v", got, previous)
	}

	addressChanged := []mdnsInterfaceState{{
		Index:     2,
		Name:      "eth0",
		Flags:     net.FlagUp | net.FlagRunning | net.FlagMulticast,
		Addresses: []string{"192.168.1.108/24"},
	}}
	got = reloadOnMDNSInterfaceChange(got, addressChanged, reload)
	if reloads != 1 {
		t.Fatalf("address change triggered %d reload(s), want 1", reloads)
	}
	if !reflect.DeepEqual(got, addressChanged) {
		t.Fatalf("changed state returned %#v, want %#v", got, addressChanged)
	}

	got = reloadOnMDNSInterfaceChange(got, nil, reload)
	if reloads != 2 {
		t.Fatalf("interface removal triggered %d reload(s), want 2", reloads)
	}
	if got != nil {
		t.Fatalf("interface removal returned %#v, want nil", got)
	}
}

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
		"status=iprd_status",
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
	want := []string{"txtvers=1", "protocol=iprd", "subscribe=iprd_subscribe", "status=iprd_status"}
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
