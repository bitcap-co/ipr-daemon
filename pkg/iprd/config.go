package iprd

import (
	"fmt"
	"io"
	"os"

	"github.com/BurntSushi/toml"
)

// IPRDConfig describes a new IPR Daemon configuration
type IPRDConfig struct {
	Debug             bool     `toml:"debug"`
	Auto              bool     `toml:"auto"`
	ListenInterface   string   `toml:"listen_interface"`
	ForwardPort       int      `toml:"forward_port"`
	ForwardKnown      bool     `toml:"forward_known"`
	NoRootNetwork     bool     `toml:"no_root_network"`
	IgnoredDevices    []string `toml:"ignored_devices"`
	NetworkInclusions []string `toml:"network_inclusions"`
	NetworkExclusions []string `toml:"network_exclusions"`
	CaptureFile       string   `toml:"capture_file"`
}

// Validate returns error if IPRDConfig contains invalid values
func (cfg *IPRDConfig) Validate() error {
	if cfg.ListenInterface == "" {
		return fmt.Errorf("ListenInterface must be present")
	}
	if cfg.ForwardPort <= 0 {
		return fmt.Errorf("ForwardPort must be positive")
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
	if target.ListenInterface != "" {
		result.ListenInterface = target.ListenInterface
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
	if target.NoRootNetwork {
		result.NoRootNetwork = target.NoRootNetwork
	}
	return &result
}

// DefaultIPRDConfig returns a default IPRDConfig
func DefaultIPRDConfig() *IPRDConfig {
	return &IPRDConfig{
		Debug:             false,
		Auto:              false,
		ListenInterface:   "eth0",
		ForwardPort:       7788,
		ForwardKnown:      false,
		NoRootNetwork:     false,
		IgnoredDevices:    []string{},
		NetworkInclusions: []string{},
		NetworkExclusions: []string{},
		CaptureFile:       "",
	}
}

// ParseConfig returns a IPRDConfig along with error from Validate
func ParseConfig(supplied *IPRDConfig) (*IPRDConfig, error) {
	cfg := DefaultIPRDConfig().Merge(supplied)
	return cfg, cfg.Validate()
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
	encoder := toml.NewEncoder(file)
	err = encoder.Encode(cfg)
	if err != nil {
		return err
	}
	return nil
}
