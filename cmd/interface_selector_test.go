package main

import (
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	iprdconfig "github.com/bitcap-co/ipr-daemon/pkg/iprd/config"
)

func TestResolveCaptureInterfaceSelectorsAlignsAndMerges(t *testing.T) {
	cfg := &iprdconfig.ListenerConfig{
		ListenInterfaces: []string{"7", "pcap-seven", "8", "09", "7"},
		ListenInterface:  "stale-legacy-value",
		Interfaces: []iprdconfig.InterfaceConfig{
			{
				Selector:          "7",
				NoRootNetwork:     true,
				IgnoredDevices:    []string{"mac-a", "mac-b"},
				NetworkInclusions: []string{"10"},
			},
			{
				Selector:          "pcap-seven",
				FilterKnownPorts:  true,
				IgnoredDevices:    []string{"mac-b", "mac-c"},
				NetworkInclusions: []string{"10", "192.168"},
				NetworkExclusions: []string{"172.16"},
			},
			{Selector: "8", IgnoredDevices: []string{"mac-d"}},
			{Selector: "09", NetworkExclusions: []string{"192.0.2"}},
		},
	}
	interfaces := []iprd.IPRInterface{
		{Index: 7, Name: "pcap-seven", FriendlyName: "friendly-seven"},
		{Index: 9, Name: "pcap-nine", FriendlyName: "friendly-nine"},
	}

	resolveCaptureInterfaceSelectors(cfg, func() ([]iprd.IPRInterface, error) {
		return interfaces, nil
	})

	if want := []string{"pcap-seven", "8", "pcap-nine"}; !reflect.DeepEqual(cfg.ListenInterfaces, want) {
		t.Fatalf("listen interfaces = %v, want %v", cfg.ListenInterfaces, want)
	}
	if cfg.ListenInterface != "pcap-seven" {
		t.Fatalf("legacy listen interface = %q, want %q", cfg.ListenInterface, "pcap-seven")
	}
	wantConfigs := []iprdconfig.InterfaceConfig{
		{
			Selector:          "pcap-seven",
			NoRootNetwork:     true,
			FilterKnownPorts:  true,
			IgnoredDevices:    []string{"mac-a", "mac-b", "mac-c"},
			NetworkInclusions: []string{"10", "192.168"},
			NetworkExclusions: []string{"172.16"},
		},
		{Selector: "8", IgnoredDevices: []string{"mac-d"}},
		{Selector: "pcap-nine", NetworkExclusions: []string{"192.0.2"}},
	}
	if !reflect.DeepEqual(cfg.Interfaces, wantConfigs) {
		t.Fatalf("interface configs = %#v, want %#v", cfg.Interfaces, wantConfigs)
	}
}

func TestResolveCaptureInterfaceSelectorsPreservesUnresolvedIndexes(t *testing.T) {
	cfg := &iprdconfig.ListenerConfig{
		ListenInterface: " 12 ",
		Interfaces: []iprdconfig.InterfaceConfig{
			{Selector: "12", IgnoredDevices: []string{"mac-a"}},
			{Selector: " 12 ", IgnoredDevices: []string{"mac-a", "mac-b"}},
		},
	}

	resolveCaptureInterfaceSelectors(cfg, func() ([]iprd.IPRInterface, error) {
		return nil, nil
	})

	if want := []string{"12"}; !reflect.DeepEqual(cfg.ListenInterfaces, want) {
		t.Fatalf("listen interfaces = %v, want %v", cfg.ListenInterfaces, want)
	}
	if cfg.ListenInterface != "12" {
		t.Fatalf("legacy listen interface = %q, want %q", cfg.ListenInterface, "12")
	}
	wantConfigs := []iprdconfig.InterfaceConfig{{Selector: "12", IgnoredDevices: []string{"mac-a", "mac-b"}}}
	if !reflect.DeepEqual(cfg.Interfaces, wantConfigs) {
		t.Fatalf("interface configs = %#v, want %#v", cfg.Interfaces, wantConfigs)
	}
}

func TestResolveMDNSInterfaceSelectors(t *testing.T) {
	tests := []struct {
		name        string
		selectors   []string
		interfaces  []net.Interface
		providerErr error
		want        []string
	}{
		{
			name:       "matched index becomes OS interface name",
			selectors:  []string{" 7 "},
			interfaces: []net.Interface{{Index: 7, Name: "eth0"}},
			want:       []string{"eth0"},
		},
		{
			name:       "unresolved index remains unchanged",
			selectors:  []string{"12"},
			interfaces: []net.Interface{{Index: 7, Name: "eth0"}},
			want:       []string{"12"},
		},
		{
			name:        "provider failure preserves selectors",
			selectors:   []string{" 7 ", "eth0"},
			interfaces:  []net.Interface{{Index: 7, Name: "other"}},
			providerErr: errors.New("interface discovery failed"),
			want:        []string{"7", "eth0"},
		},
		{
			name:       "resolved collision is deduplicated",
			selectors:  []string{"7, eth0", "8", "eth0"},
			interfaces: []net.Interface{{Index: 7, Name: "eth0"}, {Index: 8, Name: "eth1"}},
			want:       []string{"eth0", "eth1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &iprdconfig.ForwardConfig{MDNSInterfaces: tt.selectors}
			calls := 0
			resolveMDNSInterfaceSelectors(cfg, func() ([]net.Interface, error) {
				calls++
				return tt.interfaces, tt.providerErr
			})
			if calls != 1 {
				t.Fatalf("provider calls = %d, want 1", calls)
			}
			if !reflect.DeepEqual(cfg.MDNSInterfaces, tt.want) {
				t.Fatalf("mDNS interfaces = %v, want %v", cfg.MDNSInterfaces, tt.want)
			}
		})
	}
}

func TestResolveMDNSInterfaceSelectorsSkipsDiscoveryWithoutSelectors(t *testing.T) {
	cfg := &iprdconfig.ForwardConfig{}
	resolveMDNSInterfaceSelectors(cfg, func() ([]net.Interface, error) {
		t.Fatal("provider called without explicit mDNS interfaces")
		return nil, nil
	})
}

func TestResolveCaptureInterfaceSelectorsPreservesIndexesOnProviderError(t *testing.T) {
	cfg := &iprdconfig.ListenerConfig{
		ListenInterfaces: []string{" 12 ", "12"},
		Interfaces: []iprdconfig.InterfaceConfig{
			{Selector: "12", NetworkInclusions: []string{"10"}},
		},
	}
	calls := 0

	resolveCaptureInterfaceSelectors(cfg, func() ([]iprd.IPRInterface, error) {
		calls++
		return nil, errors.New("interface discovery failed")
	})

	if calls != 1 {
		t.Fatalf("provider calls = %d, want 1", calls)
	}
	if want := []string{"12"}; !reflect.DeepEqual(cfg.ListenInterfaces, want) {
		t.Fatalf("listen interfaces = %v, want %v", cfg.ListenInterfaces, want)
	}
	if cfg.ListenInterface != "12" {
		t.Fatalf("legacy listen interface = %q, want %q", cfg.ListenInterface, "12")
	}
	if cfg.Interfaces[0].Selector != "12" {
		t.Fatalf("interface config selector = %q, want %q", cfg.Interfaces[0].Selector, "12")
	}
}
