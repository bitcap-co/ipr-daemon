package iprd

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// FlagSlice defines a slice flag value that supports chaining and comma-separated values.
type FlagSlice []string

func (f *FlagSlice) String() string {
	return strings.Join(*f, ",")
}

func (f *FlagSlice) Set(value string) error {
	for _, v := range strings.Split(value, ",") {
		if v = strings.TrimSpace(v); v != "" {
			*f = append(*f, v)
		}
	}
	return nil
}

// IPRDConfig describes a new IPR Daemon configuration
type IPRDConfig struct {
	Debug              bool     `toml:"debug"`
	Auto               bool     `toml:"auto"`
	ListenInterfaces   []string `toml:"listen_interfaces,omitempty"`
	ListenInterface    string   `toml:"listen_interface,omitempty"` // Deprecated: use ListenInterfaces.
	ForwardBind        string   `toml:"forward_bind"`
	ForwardPort        int      `toml:"forward_port"`
	ForwardKnown       bool     `toml:"forward_known"`
	MDNS               bool     `toml:"mdns"`
	NoRootNetwork      bool     `toml:"no_root_network"`
	IgnoredDevices     []string `toml:"ignored_devices"`
	NetworkInclusions  []string `toml:"network_inclusions"`
	NetworkExclusions  []string `toml:"network_exclusions"`
	CaptureFile        string   `toml:"capture_file"`
	RotateCaptureFiles bool     `toml:"rotate_capture_files"`
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
		result.ListenInterfaces = append([]string(nil), target.ListenInterfaces...)
	} else if target.ListenInterface != "" {
		// A supplied legacy value must override the default plural value.
		result.ListenInterfaces = nil
		result.ListenInterface = target.ListenInterface
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
// first selector in ListenInterface until the single-listener runtime is removed.
func (cfg *IPRDConfig) normalizeListenInterfaces() {
	cfg.ListenInterfaces = cfg.effectiveListenInterfaces()
	if len(cfg.ListenInterfaces) > 0 {
		cfg.ListenInterface = cfg.ListenInterfaces[0]
	} else {
		cfg.ListenInterface = ""
	}
}

func normalizeInterfaceSelectors(values []string) []string {
	selectors := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		for _, selector := range strings.Split(value, ",") {
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
	// only as a compatibility bridge for the current single-listener runtime.
	output := *cfg
	output.ListenInterface = ""
	encoder := toml.NewEncoder(file)
	err = encoder.Encode(&output)
	if err != nil {
		return err
	}
	return nil
}
