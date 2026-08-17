package main

import (
	"reflect"
	"testing"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

func TestUpdateExistingConfigUpdatesOnlyMatchingInterface(t *testing.T) {
	curr := &iprd.IPRDConfig{ListenerConfig: iprd.ListenerConfig{
		ListenInterfaces: []string{"eth0", "eth1"},
		Interfaces: []iprd.InterfaceConfig{
			{
				Selector:          "eth0",
				IgnoredDevices:    []string{"00:00:00:00:00:01"},
				NetworkExclusions: []string{"10"},
			},
			{
				Selector:          "eth1",
				NetworkInclusions: []string{"192.168.1"},
			},
		},
	}}
	target := &iprd.IPRDConfig{ListenerConfig: iprd.ListenerConfig{
		ListenInterfaces: []string{"eth1"},
		Interfaces: []iprd.InterfaceConfig{
			{
				Selector:          "eth1",
				NoRootNetwork:     true,
				IgnoredDevices:    []string{"00:00:00:00:00:02"},
				NetworkInclusions: []string{"172.16"},
			},
		},
	}}

	got := updateExistingConfig(curr, target)

	if want := []string{"eth0", "eth1"}; !reflect.DeepEqual(got.ListenInterfaces, want) {
		t.Fatalf("listen interfaces = %v, want %v", got.ListenInterfaces, want)
	}
	if !reflect.DeepEqual(got.Interfaces[0], curr.Interfaces[0]) {
		t.Fatalf("untargeted eth0 config changed: got %#v, want %#v", got.Interfaces[0], curr.Interfaces[0])
	}
	wantEth1 := iprd.InterfaceConfig{
		Selector:          "eth1",
		NoRootNetwork:     true,
		IgnoredDevices:    []string{"00:00:00:00:00:02"},
		NetworkInclusions: []string{"172.16", "192.168.1"},
	}
	if !reflect.DeepEqual(got.Interfaces[1], wantEth1) {
		t.Fatalf("eth1 config = %#v, want %#v", got.Interfaces[1], wantEth1)
	}
}

func TestUpdateExistingConfigAddsMultipleTargetInterfaces(t *testing.T) {
	curr := &iprd.IPRDConfig{ListenerConfig: iprd.ListenerConfig{
		ListenInterfaces: []string{"eth0"},
		Interfaces: []iprd.InterfaceConfig{
			{Selector: "eth0", NetworkInclusions: []string{"10"}},
		},
	}}
	target := &iprd.IPRDConfig{ListenerConfig: iprd.ListenerConfig{
		ListenInterfaces: []string{"eth0", "eth1", "eth2"},
		Interfaces: []iprd.InterfaceConfig{
			{Selector: "eth2", NetworkExclusions: []string{"172.16"}},
			{Selector: "eth1", IgnoredDevices: []string{"00:00:00:00:00:01"}},
			{Selector: "eth0", NetworkInclusions: []string{"192.168"}},
		},
	}}

	got := updateExistingConfig(curr, target)

	if want := []string{"eth0", "eth1", "eth2"}; !reflect.DeepEqual(got.ListenInterfaces, want) {
		t.Fatalf("listen interfaces = %v, want %v", got.ListenInterfaces, want)
	}
	if len(got.Interfaces) != 3 {
		t.Fatalf("interface config count = %d, want 3", len(got.Interfaces))
	}
	if want := []string{"10", "192.168"}; !reflect.DeepEqual(got.Interfaces[0].NetworkInclusions, want) {
		t.Fatalf("eth0 inclusions = %v, want %v", got.Interfaces[0].NetworkInclusions, want)
	}
	if got.Interfaces[1].Selector != "eth2" || got.Interfaces[2].Selector != "eth1" {
		t.Fatalf("new interface config order = %#v, want existing order followed by target order", got.Interfaces)
	}
}
