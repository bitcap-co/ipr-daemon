package iprd_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

func TestFlagSliceSupportsChainingAndCommaSeparatedValues(t *testing.T) {
	var values iprd.FlagSlice
	for _, value := range []string{"eth0", "eth1, wlan0", "  4  ", ""} {
		if err := values.Set(value); err != nil {
			t.Fatalf("Set(%q): %v", value, err)
		}
	}

	want := iprd.FlagSlice{"eth0", "eth1", "wlan0", "4"}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("got %v, want %v", values, want)
	}
	if got := values.String(); got != "eth0,eth1,wlan0,4" {
		t.Fatalf("String() = %q, want %q", got, "eth0,eth1,wlan0,4")
	}
}

func TestFlagInterfaceSupportsPerInterfaceBPFOptions(t *testing.T) {
	var interfaces iprd.FlagInterface
	for _, value := range []string{
		"eth1,eth0",
		"eth0:no-root-network,ignore=aa:bb:cc:dd:ee:ff,add-network=192.168.1,exclude=10",
		"eth0:add-network=172.16",
	} {
		if err := interfaces.Set(value); err != nil {
			t.Fatalf("Set(%q): %v", value, err)
		}
	}

	if want := []string{"eth0", "eth1"}; !reflect.DeepEqual(interfaces.Selectors(), want) {
		t.Fatalf("selectors = %v, want %v", interfaces.Selectors(), want)
	}
	eth0 := interfaces["eth0"]
	if !eth0.NoRootNetwork {
		t.Fatal("eth0 NoRootNetwork = false, want true")
	}
	if want := []string{"192.168.1", "172.16"}; !reflect.DeepEqual(eth0.NetworkInclusions, want) {
		t.Fatalf("eth0 inclusions = %v, want %v", eth0.NetworkInclusions, want)
	}
	if want := []string{"aa:bb:cc:dd:ee:ff"}; !reflect.DeepEqual(eth0.IgnoredDevices, want) {
		t.Fatalf("eth0 ignored devices = %v, want %v", eth0.IgnoredDevices, want)
	}
	if want := []string{"10"}; !reflect.DeepEqual(eth0.NetworkExclusions, want) {
		t.Fatalf("eth0 exclusions = %v, want %v", eth0.NetworkExclusions, want)
	}
}

func TestFlagInterfaceRejectsInvalidOptions(t *testing.T) {
	for _, value := range []string{"eth0:unknown", "eth0:add-network=", "eth0,eth1:no-root-network"} {
		var interfaces iprd.FlagInterface
		if err := interfaces.Set(value); err == nil {
			t.Fatalf("Set(%q) returned no error", value)
		}
	}
}

func TestInterfaceOptionsRoundTrip(t *testing.T) {
	cfg, err := iprd.NewIPRDConfigFromBytes([]byte(`
[interfaces.eth1]
no_root_network = true
network_inclusions = ["192.168.50"]
ignored_devices = ["aa:bb:cc:dd:ee:ff"]
`))
	if err != nil {
		t.Fatalf("got error %v, want no error", err)
	}
	if want := []string{"eth1"}; !reflect.DeepEqual(cfg.ListenInterfaces, want) {
		t.Fatalf("interfaces = %v, want %v", cfg.ListenInterfaces, want)
	}
	if override := cfg.Interfaces["eth1"]; override == nil || !override.NoRootNetwork {
		t.Fatalf("eth1 override = %#v, want no-root-network enabled", override)
	}
}

func TestValidateRejectsInterfaceWithoutAnyIncludedNetwork(t *testing.T) {
	cfg := iprd.DefaultIPRDConfig()
	cfg.Interfaces = iprd.FlagInterface{"eth0": {NoRootNetwork: true}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() returned no error")
	}
}

func TestValidateForwardBind(t *testing.T) {
	tests := []struct {
		name    string
		bind    string
		wantErr bool
	}{
		{"empty binds all interfaces", "", false},
		{"valid IPv4", "192.168.1.10", false},
		{"valid loopback", "127.0.0.1", false},
		{"valid IPv6", "::1", false},
		{"garbage string", "not-an-ip", true},
		{"trailing junk", "192.168.1.10x", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := iprd.DefaultIPRDConfig()
			cfg.ForwardBind = tt.bind
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() with bind %q: got err=%v, wantErr=%v", tt.bind, err, tt.wantErr)
			}
		})
	}
}

func TestListenInterfacesRoundTrip(t *testing.T) {
	cfg, err := iprd.NewIPRDConfigFromBytes([]byte(`listen_interfaces = ["eth0", "eth1, wlan0", "eth0"]`))
	if err != nil {
		t.Fatalf("got error %v, want no error", err)
	}
	want := []string{"eth0", "eth1", "wlan0"}
	if !reflect.DeepEqual(cfg.ListenInterfaces, want) {
		t.Fatalf("got interfaces %v, want %v", cfg.ListenInterfaces, want)
	}
	if cfg.ListenInterface != "eth0" {
		t.Fatalf("got compatibility interface %q, want %q", cfg.ListenInterface, "eth0")
	}
}

func TestLegacyListenInterface(t *testing.T) {
	cfg, err := iprd.NewIPRDConfigFromBytes([]byte(`listen_interface = "eth1"`))
	if err != nil {
		t.Fatalf("got error %v, want no error", err)
	}
	want := []string{"eth1"}
	if !reflect.DeepEqual(cfg.ListenInterfaces, want) {
		t.Fatalf("got interfaces %v, want %v", cfg.ListenInterfaces, want)
	}
	if cfg.ListenInterface != "eth1" {
		t.Fatalf("got compatibility interface %q, want %q", cfg.ListenInterface, "eth1")
	}
}

func TestPluralListenInterfacesTakePrecedence(t *testing.T) {
	cfg, err := iprd.NewIPRDConfigFromBytes([]byte(`
listen_interface = "legacy0"
listen_interfaces = ["eth0", "eth1"]
`))
	if err != nil {
		t.Fatalf("got error %v, want no error", err)
	}
	want := []string{"eth0", "eth1"}
	if !reflect.DeepEqual(cfg.ListenInterfaces, want) {
		t.Fatalf("got interfaces %v, want %v", cfg.ListenInterfaces, want)
	}
}

func TestWriteConfigUsesPluralListenInterfaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "iprd.toml")
	cfg := iprd.DefaultIPRDConfig()
	cfg.ListenInterfaces = []string{"eth0", "eth1"}
	if err := iprd.WriteIPRDConfigToFile(cfg, path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `listen_interfaces = ["eth0", "eth1"]`) {
		t.Fatalf("written config is missing plural interfaces:\n%s", text)
	}
	if strings.Contains(text, "listen_interface =") {
		t.Fatalf("written config contains deprecated singular interface:\n%s", text)
	}
}

func TestMDNSRoundTrip(t *testing.T) {
	cfg, err := iprd.NewIPRDConfigFromBytes([]byte(`mdns = true`))
	if err != nil {
		t.Fatalf("got error %v, want no error", err)
	}
	if !cfg.MDNS {
		t.Fatal("got MDNS false, want true")
	}
}

func TestRotateCaptureFilesRoundTrip(t *testing.T) {
	cfg, err := iprd.NewIPRDConfigFromBytes([]byte(`rotate_capture_files = true`))
	if err != nil {
		t.Fatalf("got error %v, want no error", err)
	}
	if !cfg.RotateCaptureFiles {
		t.Fatal("got RotateCaptureFiles false, want true")
	}
}

func TestForwardBindRoundTrip(t *testing.T) {
	cfg, err := iprd.NewIPRDConfigFromBytes([]byte(`forward_bind = "127.0.0.1"`))
	if err != nil {
		t.Fatalf("got error %v, want no error", err)
	}
	if cfg.ForwardBind != "127.0.0.1" {
		t.Fatalf("got ForwardBind %q, want %q", cfg.ForwardBind, "127.0.0.1")
	}
}
