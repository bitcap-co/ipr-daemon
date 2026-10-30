package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	iprdconfig "github.com/bitcap-co/ipr-daemon/pkg/iprd/config"
)

func TestRunSetupCreatesConfiguration(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "iprd.toml")
	input := strings.Join([]string{
		"1",
		"1",
		"",
		"",
		"y",
		"",
		"y",
		"/tmp/iprd-capture.pcapng",
		"y",
		"y",
		"y",
		"n",
		destination,
	}, "\n") + "\n"
	interfaces := []iprd.IPRInterface{{
		Index:        7,
		Name:         "eth0",
		FriendlyName: "eth0",
		IPv4:         net.ParseIP("192.168.1.20"),
		HardwareAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}}
	var output bytes.Buffer

	err := runSetup(strings.NewReader(input), &output, "", func() ([]iprd.IPRInterface, error) {
		return interfaces, nil
	})
	if err != nil {
		t.Fatalf("runSetup: %v\noutput:\n%s", err, output.String())
	}

	cfg, err := iprdconfig.NewIPRDConfigFromFile(destination)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	if cfg.Auto {
		t.Fatal("generated config unexpectedly enabled auto mode")
	}
	if len(cfg.ListenInterfaces) != 1 || cfg.ListenInterfaces[0] != "eth0" {
		t.Fatalf("listen interfaces = %v, want [eth0]", cfg.ListenInterfaces)
	}
	if !cfg.MDNS || len(cfg.MDNSInterfaces) != 0 {
		t.Fatalf("mDNS config = enabled %v, interfaces %v; want enabled on all", cfg.MDNS, cfg.MDNSInterfaces)
	}
	if cfg.CaptureFile != "/tmp/iprd-capture.pcapng" || !cfg.RotateCaptureFiles {
		t.Fatalf("capture config = %q, rotation %v", cfg.CaptureFile, cfg.RotateCaptureFiles)
	}
	if !cfg.ForwardKnown || !cfg.FilterKnownPorts {
		t.Fatalf("known filtering = forward %v, ports %v; want both enabled", cfg.ForwardKnown, cfg.FilterKnownPorts)
	}
	if !strings.Contains(output.String(), "Configuration written to "+destination) {
		t.Fatalf("setup output did not confirm destination:\n%s", output.String())
	}
	interfacePosition := strings.Index(output.String(), "Available capture interfaces:")
	modePosition := strings.Index(output.String(), "Capture interface mode:")
	if interfacePosition < 0 || modePosition < 0 || interfacePosition > modePosition {
		t.Fatalf("available interfaces were not shown before capture mode:\n%s", output.String())
	}
}

func TestRunSetupEditsExistingConfigurationWithExplicitFalseValues(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "iprd.toml")
	cfg := iprdconfig.DefaultIPRDConfig()
	cfg.Auto = true
	cfg.MDNS = true
	cfg.CaptureFile = "/tmp/old.pcapng"
	cfg.RotateCaptureFiles = true
	cfg.ForwardKnown = true
	cfg.FilterKnownPorts = true
	cfg.NoRootNetwork = true
	cfg.NetworkInclusions = []string{"192.168.1"}
	if err := iprdconfig.WriteIPRDConfigToFile(cfg, destination); err != nil {
		t.Fatalf("write existing config: %v", err)
	}

	input := strings.Join([]string{
		"",
		"",
		"",
		"n",
		"n",
		"n",
		"n",
		"n",
		"",
	}, "\n") + "\n"
	var output bytes.Buffer
	err := runSetup(strings.NewReader(input), &output, destination, func() ([]iprd.IPRInterface, error) {
		return nil, fmt.Errorf("interface provider should not be called in auto mode")
	})
	if err != nil {
		t.Fatalf("runSetup: %v\noutput:\n%s", err, output.String())
	}

	updated, err := iprdconfig.NewIPRDConfigFromFile(destination)
	if err != nil {
		t.Fatalf("read updated config: %v", err)
	}
	if !updated.Auto {
		t.Fatal("updated config disabled auto mode")
	}
	if updated.MDNS || updated.CaptureFile != "" || updated.RotateCaptureFiles {
		t.Fatalf("optional services were not disabled: %#v", updated)
	}
	if updated.ForwardKnown || updated.FilterKnownPorts {
		t.Fatalf("known filtering was not disabled: forward %v, ports %v", updated.ForwardKnown, updated.FilterKnownPorts)
	}
	if updated.NoRootNetwork || len(updated.NetworkInclusions) > 0 {
		t.Fatalf("advanced BPF config was not cleared: no root %v, inclusions %v", updated.NoRootNetwork, updated.NetworkInclusions)
	}
}

func TestWriteDestinationRepromptsForMissingDirectory(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing", "iprd.toml")
	valid := filepath.Join(root, "iprd.toml")
	var output bytes.Buffer
	prompter := &setupPrompter{
		reader: bufio.NewReader(strings.NewReader(missing + "\n" + valid + "\n")),
		out:    &output,
	}

	got, write, err := prompter.writeDestination(defaultSetupPath)
	if err != nil {
		t.Fatalf("writeDestination: %v", err)
	}
	if !write || got != valid {
		t.Fatalf("write destination = %q, %v; want %q, true", got, write, valid)
	}
	if !strings.Contains(output.String(), "does not exist") {
		t.Fatalf("prompt did not explain missing directory:\n%s", output.String())
	}
}

func TestRunSetupCanCancelWithoutWriting(t *testing.T) {
	input := strings.Join([]string{
		"2",
		"",
		"",
		"n",
		"n",
		"n",
		"n",
		"n",
		"n",
	}, "\n") + "\n"
	var output bytes.Buffer

	err := runSetup(strings.NewReader(input), &output, "", func() ([]iprd.IPRInterface, error) {
		return nil, fmt.Errorf("interface provider should not be called in auto mode")
	})
	if err != nil {
		t.Fatalf("runSetup: %v\noutput:\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "Configuration was not written.") {
		t.Fatalf("setup output did not report cancellation:\n%s", output.String())
	}
}

func TestExpandHomeDirectory(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	got := expandHomeDirectory(filepath.Join("~", "captures", "iprd.pcapng"))
	want := filepath.Join(home, "captures", "iprd.pcapng")
	if got != want {
		t.Fatalf("expanded path = %q, want %q", got, want)
	}
}

func TestPathCompleterCompletesFilesAndDirectories(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "alpha"), 0o755); err != nil {
		t.Fatalf("create completion directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "alpine.toml"), nil, 0o644); err != nil {
		t.Fatalf("create completion file: %v", err)
	}

	typed := filepath.Join(root, "al")
	got, offset := (pathCompleter{}).Do([]rune(typed), len([]rune(typed)))
	if offset != 2 {
		t.Fatalf("completion offset = %d, want 2", offset)
	}
	if len(got) != 2 || string(got[0]) != "pha"+string(os.PathSeparator) || string(got[1]) != "pine.toml" {
		t.Fatalf("completion candidates = %q, want alpha directory and alpine.toml", got)
	}
}

func TestSelectedInterfaceConfigsPreservesIndexBasedOverrides(t *testing.T) {
	interfaces := []iprd.IPRInterface{{Index: 7, Name: "eth0", FriendlyName: "eth0"}}
	configs := []iprdconfig.InterfaceConfig{{
		Selector:          "7",
		NetworkInclusions: []string{"192.168.1"},
	}}

	got := selectedInterfaceConfigs(configs, []string{"eth0"}, interfaces)
	if len(got) != 1 {
		t.Fatalf("selected configs = %v, want one config", got)
	}
	if got[0].Selector != "eth0" || len(got[0].NetworkInclusions) != 1 {
		t.Fatalf("selected config = %#v, want canonical eth0 override", got[0])
	}
}

func TestParseInterfaceSelectionAcceptsMenuNumbersNamesAndIndexes(t *testing.T) {
	interfaces := []iprd.IPRInterface{
		{Index: 7, Name: "eth0", FriendlyName: "eth0"},
		{Index: 11, Name: "eth1", FriendlyName: "LAN"},
	}

	got, err := parseInterfaceSelection(interfaces, "1,LAN,11,eth0")
	if err != nil {
		t.Fatalf("parseInterfaceSelection: %v", err)
	}
	want := []string{"eth0", "eth1"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("selectors = %v, want %v", got, want)
	}
}
