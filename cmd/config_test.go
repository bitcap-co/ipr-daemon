package main

import (
	"reflect"
	"testing"

	iprdconfig "github.com/bitcap-co/ipr-daemon/pkg/iprd/config"
)

func TestUpdateExistingConfigUpdatesOnlyMatchingInterface(t *testing.T) {
	curr := &iprdconfig.IPRDConfig{ListenerConfig: iprdconfig.ListenerConfig{
		ListenInterfaces: []string{"eth0", "eth1"},
		Interfaces: []iprdconfig.InterfaceConfig{
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
	target := &iprdconfig.IPRDConfig{ListenerConfig: iprdconfig.ListenerConfig{
		ListenInterfaces: []string{"eth1"},
		Interfaces: []iprdconfig.InterfaceConfig{
			{
				Selector:          "eth1",
				NoRootNetwork:     true,
				IgnoredDevices:    []string{"00:00:00:00:00:02"},
				NetworkInclusions: []string{"172.16"},
			},
		},
	}}

	got, err := updateExistingConfig(curr, target)
	if err != nil {
		t.Fatalf("updateExistingConfig: %v", err)
	}

	if want := []string{"eth0", "eth1"}; !reflect.DeepEqual(got.ListenInterfaces, want) {
		t.Fatalf("listen interfaces = %v, want %v", got.ListenInterfaces, want)
	}
	if !reflect.DeepEqual(got.Interfaces[0], curr.Interfaces[0]) {
		t.Fatalf("untargeted eth0 config changed: got %#v, want %#v", got.Interfaces[0], curr.Interfaces[0])
	}
	wantEth1 := iprdconfig.InterfaceConfig{
		Selector:          "eth1",
		NoRootNetwork:     true,
		IgnoredDevices:    []string{"00:00:00:00:00:02"},
		NetworkInclusions: []string{"172.16", "192.168.1"},
	}
	if !reflect.DeepEqual(got.Interfaces[1], wantEth1) {
		t.Fatalf("eth1 config = %#v, want %#v", got.Interfaces[1], wantEth1)
	}
}

func TestUpdateExistingConfigAutoModeDoesNotRequireInterface(t *testing.T) {
	curr := iprdconfig.DefaultIPRDConfig()
	target := &iprdconfig.IPRDConfig{ListenerConfig: iprdconfig.ListenerConfig{Auto: true}}

	got, err := updateExistingConfig(curr, target)
	if err != nil {
		t.Fatalf("updateExistingConfig: %v", err)
	}
	if !got.Auto {
		t.Fatal("update config did not enable auto mode")
	}
	if len(got.ListenInterfaces) != 0 {
		t.Fatalf("auto config interfaces = %v, want none", got.ListenInterfaces)
	}
}

func TestUpdateExistingConfigValidatesGlobalListenerConfig(t *testing.T) {
	curr := iprdconfig.DefaultIPRDConfig()
	curr.ListenInterfaces = []string{"eth0"}
	target := &iprdconfig.IPRDConfig{ListenerConfig: iprdconfig.ListenerConfig{NoRootNetwork: true}}

	if _, err := updateExistingConfig(curr, target); err == nil {
		t.Fatal("updateExistingConfig accepted no_root_network without network inclusions")
	}
}

func TestUpdateExistingConfigAutoModeIgnoresExplicitInterfaceValidation(t *testing.T) {
	curr := iprdconfig.DefaultIPRDConfig()
	target := &iprdconfig.IPRDConfig{ListenerConfig: iprdconfig.ListenerConfig{
		Auto:             true,
		ListenInterfaces: []string{"eth0"},
		Interfaces: []iprdconfig.InterfaceConfig{{
			Selector:      "eth0",
			NoRootNetwork: true,
		}},
	}}

	got, err := updateExistingConfig(curr, target)
	if err != nil {
		t.Fatalf("updateExistingConfig: %v", err)
	}
	if !got.Auto {
		t.Fatalf("updated config did not enable auto mode")
	}
}

func TestUpdateExistingConfigDisablingAutoValidatesExplicitInterfaces(t *testing.T) {
	curr := iprdconfig.DefaultIPRDConfig()
	curr.Auto = true
	curr.ListenInterfaces = []string{"eth0"}
	curr.Interfaces = []iprdconfig.InterfaceConfig{{Selector: "eth0", NoRootNetwork: true}}
	target := &iprdconfig.IPRDConfig{ListenerConfig: iprdconfig.ListenerConfig{Auto: true}}

	if _, err := updateExistingConfig(curr, target); err == nil {
		t.Fatalf("updateExistingConfig accepted invalid explicit interface after disabling auto")
	}
}

func TestUpdateExistingConfigAddsMultipleTargetInterfaces(t *testing.T) {
	curr := &iprdconfig.IPRDConfig{ListenerConfig: iprdconfig.ListenerConfig{
		ListenInterfaces: []string{"eth0"},
		Interfaces: []iprdconfig.InterfaceConfig{
			{Selector: "eth0", NetworkInclusions: []string{"10"}},
		},
	}}
	target := &iprdconfig.IPRDConfig{ListenerConfig: iprdconfig.ListenerConfig{
		ListenInterfaces: []string{"eth0", "eth1", "eth2"},
		Interfaces: []iprdconfig.InterfaceConfig{
			{Selector: "eth2", NetworkExclusions: []string{"172.16"}},
			{Selector: "eth1", IgnoredDevices: []string{"00:00:00:00:00:01"}},
			{Selector: "eth0", NetworkInclusions: []string{"192.168"}},
		},
	}}

	got, err := updateExistingConfig(curr, target)
	if err != nil {
		t.Fatalf("updateExistingConfig: %v", err)
	}

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
