package config

import (
	"fmt"
	"net"
	"slices"
	"strings"
)

// InterfaceConfig describes BPF configuration for a specific interface.
type InterfaceConfig struct {
	Selector          string   `toml:"selector" json:"selector"`
	NoRootNetwork     bool     `toml:"no_root_network" json:"no_root_network"`
	FilterKnownPorts  bool     `toml:"filter_known_ports" json:"filter_known_ports"`
	IgnoredDevices    []string `toml:"ignored_devices" json:"ignored_devices"`
	NetworkInclusions []string `toml:"network_inclusions" json:"network_inclusions"`
	NetworkExclusions []string `toml:"network_exclusions" json:"network_exclusions"`
}

// DefaultInterfaceConfig returns a default InterfaceConfig
func DefaultInterfaceConfig() *InterfaceConfig {
	return &InterfaceConfig{
		Selector:          "",
		NoRootNetwork:     false,
		FilterKnownPorts:  false,
		IgnoredDevices:    []string{},
		NetworkInclusions: []string{},
		NetworkExclusions: []string{},
	}
}

func cloneInterfaceConfig(cfg InterfaceConfig) InterfaceConfig {
	cfg.IgnoredDevices = slices.Clone(cfg.IgnoredDevices)
	cfg.NetworkInclusions = slices.Clone(cfg.NetworkInclusions)
	cfg.NetworkExclusions = slices.Clone(cfg.NetworkExclusions)
	return cfg
}

func cloneInterfaceConfigs(configs []InterfaceConfig) []InterfaceConfig {
	cloned := make([]InterfaceConfig, len(configs))
	for i, cfg := range configs {
		cloned[i] = cloneInterfaceConfig(cfg)
	}
	return cloned
}

func interfaceConfigSelectors(configs []InterfaceConfig) []string {
	selectors := make([]string, 0, len(configs))
	for _, cfg := range configs {
		selectors = append(selectors, cfg.Selector)
	}
	return normalizeInterfaceSelectors(selectors)
}

// ListenerConfig describes packet capture and IP report processing behavior.
type ListenerConfig struct {
	Debug              bool              `toml:"debug" json:"debug"`
	Auto               bool              `toml:"auto" json:"auto"`
	ListenInterfaces   []string          `toml:"listen_interfaces,omitempty" json:"listen_interfaces,omitempty"`
	ListenInterface    string            `toml:"listen_interface,omitempty" json:"listen_interface,omitempty"` // Deprecated: use ListenInterfaces.
	Interfaces         []InterfaceConfig `toml:"interfaces,omitempty" json:"interfaces,omitempty"`
	ForwardKnown       bool              `toml:"forward_known" json:"forward_known"`
	NoRootNetwork      bool              `toml:"no_root_network" json:"no_root_network"`
	FilterKnownPorts   bool              `toml:"filter_known_ports" json:"filter_known_ports"`
	IgnoredDevices     []string          `toml:"ignored_devices" json:"ignored_devices"`
	NetworkInclusions  []string          `toml:"network_inclusions" json:"network_inclusions"`
	NetworkExclusions  []string          `toml:"network_exclusions" json:"network_exclusions"`
	CaptureFile        string            `toml:"capture_file" json:"capture_file"`
	RotateCaptureFiles bool              `toml:"rotate_capture_files" json:"rotate_capture_files"`
}

// Validate returns an error if ListenerConfig contains invalid values.
// An empty interface list is valid for partial configuration and config-file
// updates; ListenerManager.Run requires at least one interface at runtime.
func (cfg *ListenerConfig) Validate() error {
	seen := make(map[string]struct{}, len(cfg.Interfaces))
	for i, interfaceCfg := range cfg.Interfaces {
		selector := strings.TrimSpace(interfaceCfg.Selector)
		if selector == "" {
			return fmt.Errorf("interface config %d has an empty selector", i)
		}
		if _, exists := seen[selector]; exists {
			return fmt.Errorf("duplicate interface config selector %q", selector)
		}
		seen[selector] = struct{}{}
	}
	if cfg.Auto {
		if cfg.NoRootNetwork && len(cfg.NetworkInclusions) == 0 {
			return fmt.Errorf("auto mode requires network inclusions when no_root_network is enabled")
		}
		return nil
	}
	for _, selector := range cfg.effectiveListenInterfaces() {
		interfaceCfg := cfg.interfaceConfig(selector)
		if interfaceCfg.NoRootNetwork && len(interfaceCfg.NetworkInclusions) == 0 {
			return fmt.Errorf("interface %q excludes its root network but has no network inclusions", selector)
		}
	}
	return nil
}

// Merge returns a new ListenerConfig with non-zero values from target applied.
func (cfg *ListenerConfig) Merge(target *ListenerConfig) *ListenerConfig {
	result := *cfg
	if target == nil {
		return &result
	}

	if target.Debug {
		result.Debug = true
	}
	if target.Auto {
		result.Auto = true
	}
	if target.ForwardKnown {
		result.ForwardKnown = true
	}
	if len(target.ListenInterfaces) > 0 {
		result.ListenInterfaces = slices.Clone(target.ListenInterfaces)
	} else if target.ListenInterface != "" {
		// A supplied legacy value must override the default plural value.
		result.ListenInterfaces = nil
		result.ListenInterface = target.ListenInterface
	} else if len(target.Interfaces) > 0 {
		result.ListenInterfaces = interfaceConfigSelectors(target.Interfaces)
		result.ListenInterface = ""
	}
	if len(target.Interfaces) > 0 {
		result.Interfaces = cloneInterfaceConfigs(target.Interfaces)
	}
	if target.FilterKnownPorts {
		result.FilterKnownPorts = true
	}
	if len(target.IgnoredDevices) > 0 {
		result.IgnoredDevices = slices.Clone(target.IgnoredDevices)
	}
	if len(target.NetworkInclusions) > 0 {
		result.NetworkInclusions = slices.Clone(target.NetworkInclusions)
	}
	if len(target.NetworkExclusions) > 0 {
		result.NetworkExclusions = slices.Clone(target.NetworkExclusions)
	}
	if target.CaptureFile != "" {
		result.CaptureFile = target.CaptureFile
	}
	if target.RotateCaptureFiles {
		result.RotateCaptureFiles = true
	}
	if target.NoRootNetwork {
		result.NoRootNetwork = true
	}
	return &result
}

// effectiveListenInterfaces returns normalized interface selectors, preferring
// the plural configuration while retaining support for listen_interface.
func (cfg *ListenerConfig) effectiveListenInterfaces() []string {
	if len(cfg.ListenInterfaces) > 0 {
		return normalizeInterfaceSelectors(cfg.ListenInterfaces)
	}
	if cfg.ListenInterface != "" {
		return normalizeInterfaceSelectors([]string{cfg.ListenInterface})
	}
	return interfaceConfigSelectors(cfg.Interfaces)
}

// normalizeListenInterfaces stores the canonical plural selectors and keeps the
// first selector in ListenInterface for legacy callers.
func (cfg *ListenerConfig) normalizeListenInterfaces() {
	cfg.ListenInterfaces = cfg.effectiveListenInterfaces()
	if len(cfg.ListenInterfaces) > 0 {
		cfg.ListenInterface = cfg.ListenInterfaces[0]
	} else {
		cfg.ListenInterface = ""
	}
}

// InterfaceConfigFor combines the global BPF configuration with overrides for a selector.
// The returned configuration owns its slice fields and may be modified by the caller.
func (cfg *ListenerConfig) InterfaceConfigFor(selector string) InterfaceConfig {
	return cloneInterfaceConfig(*cfg.interfaceConfig(selector))
}

func (cfg *ListenerConfig) interfaceConfig(selector string) *InterfaceConfig {
	combined := &InterfaceConfig{
		NoRootNetwork:     cfg.NoRootNetwork,
		FilterKnownPorts:  cfg.FilterKnownPorts,
		IgnoredDevices:    slices.Clone(cfg.IgnoredDevices),
		NetworkInclusions: slices.Clone(cfg.NetworkInclusions),
		NetworkExclusions: slices.Clone(cfg.NetworkExclusions),
	}
	for _, override := range cfg.Interfaces {
		if strings.TrimSpace(override.Selector) != selector {
			continue
		}
		combined.NoRootNetwork = combined.NoRootNetwork || override.NoRootNetwork
		combined.FilterKnownPorts = combined.FilterKnownPorts || override.FilterKnownPorts
		combined.IgnoredDevices = append(combined.IgnoredDevices, override.IgnoredDevices...)
		combined.NetworkInclusions = append(combined.NetworkInclusions, override.NetworkInclusions...)
		combined.NetworkExclusions = append(combined.NetworkExclusions, override.NetworkExclusions...)
		break
	}
	return combined
}

// DefaultListenerConfig returns the default packet listener configuration.
func DefaultListenerConfig() *ListenerConfig {
	return &ListenerConfig{
		Debug:              false,
		Auto:               false,
		ListenInterfaces:   []string{},
		ListenInterface:    "",
		Interfaces:         []InterfaceConfig{},
		ForwardKnown:       false,
		NoRootNetwork:      false,
		FilterKnownPorts:   false,
		IgnoredDevices:     []string{},
		NetworkInclusions:  []string{},
		NetworkExclusions:  []string{},
		CaptureFile:        "",
		RotateCaptureFiles: false,
	}
}

// ParseListenerConfig applies listener defaults, normalizes interface selectors,
// and validates the resulting configuration.
func ParseListenerConfig(supplied *ListenerConfig) (*ListenerConfig, error) {
	cfg := DefaultListenerConfig().Merge(supplied)
	cfg.normalizeListenInterfaces()
	return cfg, cfg.Validate()
}

// ForwardConfig describes the daemon's TCP forwarding endpoint and service advertisement.
type ForwardConfig struct {
	Bind string `toml:"forward_bind" json:"forward_bind"`
	Port int    `toml:"forward_port" json:"forward_port"`
	MDNS bool   `toml:"mdns" json:"mdns"`
}

// Validate returns an error if ForwardConfig contains invalid endpoint values.
func (cfg *ForwardConfig) Validate() error {
	if cfg.Bind != "" && net.ParseIP(cfg.Bind) == nil {
		return fmt.Errorf("bind must be a valid IP address")
	}
	if cfg.Port <= 0 {
		return fmt.Errorf("port must be positive")
	}
	return nil
}

// Merge returns a new ForwardConfig with non-zero values from target applied.
func (cfg *ForwardConfig) Merge(target *ForwardConfig) *ForwardConfig {
	result := *cfg
	if target == nil {
		return &result
	}
	if target.Bind != "" {
		result.Bind = target.Bind
	}
	if target.Port != 0 {
		result.Port = target.Port
	}
	if target.MDNS {
		result.MDNS = target.MDNS
	}
	return &result
}

// DefaultForwardConfig returns the default daemon forwarding configuration.
func DefaultForwardConfig() *ForwardConfig {
	return &ForwardConfig{
		Bind: "",
		Port: 7788,
		MDNS: false,
	}
}

// IPRDConfig combines reusable listener settings with daemon forwarding settings.
// ListenerConfig is embedded so existing flat TOML and JSON formats are preserved.
type IPRDConfig struct {
	ListenerConfig
	ForwardConfig
}

// Validate returns an error if IPRDConfig contains invalid listener or forwarding values.
func (cfg *IPRDConfig) Validate() error {
	if err := cfg.ListenerConfig.Validate(); err != nil {
		return err
	}
	if err := cfg.ForwardConfig.Validate(); err != nil {
		return err
	}
	return nil
}

// Merge returns a new IPRDConfig with non-zero values from target applied.
func (cfg *IPRDConfig) Merge(target *IPRDConfig) *IPRDConfig {
	result := *cfg
	if target == nil {
		return &result
	}

	result.ListenerConfig = *cfg.ListenerConfig.Merge(&target.ListenerConfig)
	result.ForwardConfig = *cfg.ForwardConfig.Merge(&target.ForwardConfig)
	return &result
}

// DefaultIPRDConfig returns the default daemon configuration.
func DefaultIPRDConfig() *IPRDConfig {
	return &IPRDConfig{
		ListenerConfig: *DefaultListenerConfig(),
		ForwardConfig:  *DefaultForwardConfig(),
	}
}

// ParseConfig applies daemon defaults, normalizes interface selectors, and validates the result.
func ParseConfig(supplied *IPRDConfig) (*IPRDConfig, error) {
	cfg := DefaultIPRDConfig().Merge(supplied)
	cfg.normalizeListenInterfaces()
	return cfg, cfg.Validate()
}

func normalizeInterfaceSelectors(values []string) []string {
	selectors := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		for selector := range strings.SplitSeq(value, ",") {
			selector = strings.TrimSpace(selector)
			if selector == "" {
				continue
			}
			if _, exists := seen[selector]; exists {
				continue
			}
			seen[selector] = struct{}{}
			selectors = append(selectors, selector)
		}
	}
	return selectors
}
