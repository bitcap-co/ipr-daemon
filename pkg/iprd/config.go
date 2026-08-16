package iprd

import (
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

// FlagSlice is a flag value that supports multiple comma-separated values and chaining.
type FlagSlice []string

func (f *FlagSlice) String() string {
	return strings.Join(*f, ",")
}

func (f *FlagSlice) Set(value string) error {
	for v := range strings.SplitSeq(value, ",") {
		if v = strings.TrimSpace(v); v != "" {
			*f = append(*f, v)
		}
	}
	return nil
}

// InterfaceConfig describes BPF configuration for a specific interface.
type InterfaceConfig struct {
	Selector          string   `toml:"selector" json:"selector"`
	NoRootNetwork     bool     `toml:"no_root_network" json:"no_root_network"`
	IgnoredDevices    []string `toml:"ignored_devices" json:"ignored_devices"`
	NetworkInclusions []string `toml:"network_inclusions" json:"network_inclusions"`
	NetworkExclusions []string `toml:"network_exclusions" json:"network_exclusions"`
}

// DefaultInterfaceConfig returns a default InterfaceConfig
func DefaultInterfaceConfig() *InterfaceConfig {
	return &InterfaceConfig{
		Selector:          "",
		NoRootNetwork:     false,
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

// FlagInterface is a flag value representing a interface configuration.
// Each key is an interface selector (e.g. "eth0" or 1), with attached InterfaceConfig representing supplied options.
// Options are specified after ":" separated by commas (e.g., "eth0:no-root-network,add-network=172.16").
type FlagInterface map[string]*InterfaceConfig

func (f *FlagInterface) String() string {
	return fmt.Sprintf("%v", map[string]*InterfaceConfig(*f))
}

func (f *FlagInterface) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if *f == nil {
		*f = make(FlagInterface)
	}

	var ifaceID, options string
	if strings.Contains(value, ":") {
		parts := strings.SplitN(value, ":", 2)
		ifaceID = strings.TrimSpace(parts[0])
		options = parts[1]
	} else {
		for _, selector := range normalizeInterfaceSelectors([]string{value}) {
			if (*f)[selector] == nil {
				(*f)[selector] = DefaultInterfaceConfig()
			}
		}
		return nil
	}
	if ifaceID == "" {
		return fmt.Errorf("interface ID cannot be empty")
	}
	if strings.Contains(ifaceID, ",") {
		return fmt.Errorf("interface options must be specified separately for each interface")
	}

	if (*f)[ifaceID] == nil {
		(*f)[ifaceID] = DefaultInterfaceConfig()
	}
	cfg := (*f)[ifaceID]

	if options == "" {
		return nil
	}
	opts := strings.SplitSeq(options, ",")
	for opt := range opts {
		opt = strings.TrimSpace(opt)
		if opt == "" {
			continue
		}
		switch {
		case opt == "no-root-network":
			cfg.NoRootNetwork = true
		case strings.HasPrefix(opt, "ignore="):
			if value := strings.TrimSpace(strings.TrimPrefix(opt, "ignore=")); value != "" {
				cfg.IgnoredDevices = append(cfg.IgnoredDevices, value)
			} else {
				return fmt.Errorf("ignore option cannot be empty")
			}
		case strings.HasPrefix(opt, "add-network="):
			if value := strings.TrimSpace(strings.TrimPrefix(opt, "add-network=")); value != "" {
				cfg.NetworkInclusions = append(cfg.NetworkInclusions, value)
			} else {
				return fmt.Errorf("add-network option cannot be empty")
			}
		case strings.HasPrefix(opt, "exclude="):
			if value := strings.TrimSpace(strings.TrimPrefix(opt, "exclude=")); value != "" {
				cfg.NetworkExclusions = append(cfg.NetworkExclusions, value)
			} else {
				return fmt.Errorf("exclude option cannot be empty")
			}
		default:
			return fmt.Errorf("unknown option: %q", opt)
		}
	}
	return nil
}

// Selectors returns the configured interface selectors in deterministic order.
func (f FlagInterface) Selectors() []string {
	selectors := make([]string, 0, len(f))
	for selector := range f {
		selectors = append(selectors, selector)
	}
	slices.Sort(selectors)
	return selectors
}

// Configs returns the flag values as a deterministic list of interface configurations.
func (f FlagInterface) Configs() []InterfaceConfig {
	selectors := f.Selectors()
	configs := make([]InterfaceConfig, 0, len(selectors))
	for _, selector := range selectors {
		cfg := f[selector]
		if cfg == nil {
			cfg = DefaultInterfaceConfig()
		}
		copyCfg := cloneInterfaceConfig(*cfg)
		copyCfg.Selector = selector
		configs = append(configs, copyCfg)
	}
	return configs
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

// interfaceConfig combines the global BPF configuration with overrides for a selector.
func (cfg *ListenerConfig) interfaceConfig(selector string) *InterfaceConfig {
	combined := &InterfaceConfig{
		NoRootNetwork:     cfg.NoRootNetwork,
		IgnoredDevices:    slices.Clone(cfg.IgnoredDevices),
		NetworkInclusions: slices.Clone(cfg.NetworkInclusions),
		NetworkExclusions: slices.Clone(cfg.NetworkExclusions),
	}
	for _, override := range cfg.Interfaces {
		if strings.TrimSpace(override.Selector) != selector {
			continue
		}
		combined.NoRootNetwork = combined.NoRootNetwork || override.NoRootNetwork
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

// NewIPRDConfigFromBytes unmarshals TOML data into IPRDConfig
func NewIPRDConfigFromBytes(data []byte) (*IPRDConfig, error) {
	var cfg *IPRDConfig
	err := toml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	return ParseConfig(cfg)
}

// NewIPRDConfigFromFile reads a TOML configuration file at filePath into IPRDConfig
func NewIPRDConfigFromFile(filePath string) (*IPRDConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return NewIPRDConfigFromBytes(data)
}

// WriteIPRDConfigToFile write TOML configuration of supplied to filePath
func WriteIPRDConfigToFile(supplied *IPRDConfig, filePath string) error {
	cfg, err := ParseConfig(supplied)
	if err != nil {
		return err
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	// New files use the plural key. ListenInterface remains populated in memory
	// only as a compatibility bridge for legacy callers.
	output := *cfg
	output.ListenInterface = ""
	encoder := toml.NewEncoder(file)
	err = encoder.Encode(&output)
	if err != nil {
		return err
	}
	return nil
}
