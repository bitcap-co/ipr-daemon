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

// IPRDInterfaceConfig describes BPF configuration for a specific interface.
type IPRDInterfaceConfig struct {
	NoRootNetwork     bool     `toml:"no_root_network" json:"no_root_network"`
	IgnoredDevices    []string `toml:"ignored_devices" json:"ignored_devices"`
	NetworkInclusions []string `toml:"network_inclusions" json:"network_inclusions"`
	NetworkExclusions []string `toml:"network_exclusions" json:"network_exclusions"`
}

// DefaultIPRDInterfaceConfig returns a default IPRDInterfaceConfig
func DefaultIPRDInterfaceConfig() *IPRDInterfaceConfig {
	return &IPRDInterfaceConfig{
		NoRootNetwork:     false,
		IgnoredDevices:    []string{},
		NetworkInclusions: []string{},
		NetworkExclusions: []string{},
	}
}

// FlagInterface is a flag value representing a interface configuration.
// Each key is an interface selector (e.g. "eth0" or 1), with attached IPRDInterfaceConfig representing supplied options.
// Options are specified after ":" separated by commas (e.g., "eth0:no-root-network,add-network=172.16").
type FlagInterface map[string]*IPRDInterfaceConfig

func (f *FlagInterface) String() string {
	return fmt.Sprintf("%v", map[string]*IPRDInterfaceConfig(*f))
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
				(*f)[selector] = DefaultIPRDInterfaceConfig()
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
		(*f)[ifaceID] = DefaultIPRDInterfaceConfig()
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

func (f FlagInterface) clone() FlagInterface {
	cloned := make(FlagInterface, len(f))
	for selector, cfg := range f {
		if cfg == nil {
			cloned[selector] = DefaultIPRDInterfaceConfig()
			continue
		}
		copyCfg := *cfg
		copyCfg.IgnoredDevices = slices.Clone(cfg.IgnoredDevices)
		copyCfg.NetworkInclusions = slices.Clone(cfg.NetworkInclusions)
		copyCfg.NetworkExclusions = slices.Clone(cfg.NetworkExclusions)
		cloned[selector] = &copyCfg
	}
	return cloned
}

// IPRDConfig describes a new IPR Daemon configuration
type IPRDConfig struct {
	Debug              bool          `toml:"debug" json:"debug"`
	Auto               bool          `toml:"auto" json:"auto"`
	ListenInterfaces   []string      `toml:"listen_interfaces,omitempty" json:"listen_interfaces,omitempty"`
	ListenInterface    string        `toml:"listen_interface,omitempty" json:"listen_interface,omitempty"` // Deprecated: use ListenInterfaces.
	Interfaces         FlagInterface `toml:"interfaces,omitempty" json:"interfaces,omitempty"`
	ForwardBind        string        `toml:"forward_bind" json:"forward_bind"`
	ForwardPort        int           `toml:"forward_port" json:"forward_port"`
	ForwardKnown       bool          `toml:"forward_known" json:"forward_known"`
	MDNS               bool          `toml:"mdns" json:"mdns"`
	NoRootNetwork      bool          `toml:"no_root_network" json:"no_root_network"`
	IgnoredDevices     []string      `toml:"ignored_devices" json:"ignored_devices"`
	NetworkInclusions  []string      `toml:"network_inclusions" json:"network_inclusions"`
	NetworkExclusions  []string      `toml:"network_exclusions" json:"network_exclusions"`
	CaptureFile        string        `toml:"capture_file" json:"capture_file"`
	RotateCaptureFiles bool          `toml:"rotate_capture_files" json:"rotate_capture_files"`
}

// Validate returns error if IPRDConfig contains invalid values
func (cfg *IPRDConfig) Validate() error {
	if len(cfg.effectiveListenInterfaces()) == 0 {
		return fmt.Errorf("at least one listen interface must be present")
	}
	if cfg.ForwardPort <= 0 {
		return fmt.Errorf("ForwardPort must be positive")
	}
	if cfg.ForwardBind != "" && net.ParseIP(cfg.ForwardBind) == nil {
		return fmt.Errorf("ForwardBind must be a valid IP address")
	}
	for _, selector := range cfg.effectiveListenInterfaces() {
		interfaceCfg := cfg.interfaceConfig(selector)
		if interfaceCfg.NoRootNetwork && len(interfaceCfg.NetworkInclusions) == 0 {
			return fmt.Errorf("interface %q excludes its root network but has no network inclusions", selector)
		}
	}
	return nil
}

// Merge returns a new IPRDConfig from target config
func (cfg *IPRDConfig) Merge(target *IPRDConfig) *IPRDConfig {
	result := *cfg
	if target == nil {
		return &result
	}

	if target.Debug {
		result.Debug = target.Debug
	}
	if target.Auto {
		result.Auto = target.Auto
	}
	if target.ForwardKnown {
		result.ForwardKnown = target.ForwardKnown
	}
	if target.MDNS {
		result.MDNS = target.MDNS
	}
	if len(target.ListenInterfaces) > 0 {
		result.ListenInterfaces = slices.Clone(target.ListenInterfaces)
	} else if target.ListenInterface != "" {
		// A supplied legacy value must override the default plural value.
		result.ListenInterfaces = nil
		result.ListenInterface = target.ListenInterface
	} else if len(target.Interfaces) > 0 {
		result.ListenInterfaces = target.Interfaces.Selectors()
		result.ListenInterface = ""
	}
	if len(target.Interfaces) > 0 {
		result.Interfaces = target.Interfaces.clone()
	}
	if target.ForwardBind != "" {
		result.ForwardBind = target.ForwardBind
	}
	if target.ForwardPort > 0 {
		result.ForwardPort = target.ForwardPort
	}
	if len(target.IgnoredDevices) > 0 {
		result.IgnoredDevices = target.IgnoredDevices
	}
	if len(target.NetworkInclusions) > 0 {
		result.NetworkInclusions = target.NetworkInclusions
	}
	if len(target.NetworkExclusions) > 0 {
		result.NetworkExclusions = target.NetworkExclusions
	}
	if target.CaptureFile != "" {
		result.CaptureFile = target.CaptureFile
	}
	if target.RotateCaptureFiles {
		result.RotateCaptureFiles = target.RotateCaptureFiles
	}
	if target.NoRootNetwork {
		result.NoRootNetwork = target.NoRootNetwork
	}
	return &result
}

// DefaultIPRDConfig returns a default IPRDConfig
func DefaultIPRDConfig() *IPRDConfig {
	return &IPRDConfig{
		Debug:              false,
		Auto:               false,
		ListenInterfaces:   []string{"eth0"},
		ListenInterface:    "eth0",
		Interfaces:         FlagInterface{},
		ForwardBind:        "",
		ForwardPort:        7788,
		ForwardKnown:       false,
		MDNS:               false,
		NoRootNetwork:      false,
		IgnoredDevices:     []string{},
		NetworkInclusions:  []string{},
		NetworkExclusions:  []string{},
		CaptureFile:        "",
		RotateCaptureFiles: false,
	}
}

// ParseConfig returns a IPRDConfig along with error from Validate
func ParseConfig(supplied *IPRDConfig) (*IPRDConfig, error) {
	cfg := DefaultIPRDConfig().Merge(supplied)
	cfg.normalizeListenInterfaces()
	return cfg, cfg.Validate()
}

// effectiveListenInterfaces returns normalized interface selectors, preferring
// the plural configuration while retaining support for listen_interface.
func (cfg *IPRDConfig) effectiveListenInterfaces() []string {
	if len(cfg.ListenInterfaces) > 0 {
		return normalizeInterfaceSelectors(cfg.ListenInterfaces)
	}
	return normalizeInterfaceSelectors([]string{cfg.ListenInterface})
}

// normalizeListenInterfaces stores the canonical plural selectors and keeps the
// first selector in ListenInterface for legacy callers.
func (cfg *IPRDConfig) normalizeListenInterfaces() {
	cfg.ListenInterfaces = cfg.effectiveListenInterfaces()
	if len(cfg.ListenInterfaces) > 0 {
		cfg.ListenInterface = cfg.ListenInterfaces[0]
	} else {
		cfg.ListenInterface = ""
	}
}

// interfaceConfig combines the global BPF configuration with overrides for a selector.
func (cfg *IPRDConfig) interfaceConfig(selector string) *IPRDInterfaceConfig {
	combined := &IPRDInterfaceConfig{
		NoRootNetwork:     cfg.NoRootNetwork,
		IgnoredDevices:    slices.Clone(cfg.IgnoredDevices),
		NetworkInclusions: slices.Clone(cfg.NetworkInclusions),
		NetworkExclusions: slices.Clone(cfg.NetworkExclusions),
	}
	if override := cfg.Interfaces[selector]; override != nil {
		combined.NoRootNetwork = combined.NoRootNetwork || override.NoRootNetwork
		combined.IgnoredDevices = append(combined.IgnoredDevices, override.IgnoredDevices...)
		combined.NetworkInclusions = append(combined.NetworkInclusions, override.NetworkInclusions...)
		combined.NetworkExclusions = append(combined.NetworkExclusions, override.NetworkExclusions...)
	}
	return combined
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
