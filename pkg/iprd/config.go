package iprd

import (
	"fmt"
	"io"
	"os"

	"github.com/BurntSushi/toml"
)

// IPRDConfig describes a new IPR Daemon configuration
type IPRDConfig struct {
	Debug           bool     `toml:"debug"`
	Auto            bool     `toml:"auto"`
	Filter          bool     `toml:"filter"`
	ListenInterface string   `toml:"listen_interface"`
	ForwardPort     int      `toml:"forward_port"`
	IgnoreAddresses []string `toml:"ignore_addrs"`
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
	if target.Filter {
		result.Filter = target.Filter
	}
	if target.ListenInterface != "" {
		result.ListenInterface = target.ListenInterface
	}
	if target.ForwardPort > 0 {
		result.ForwardPort = target.ForwardPort
	}
	if len(target.IgnoreAddresses) > 0 {
		result.IgnoreAddresses = target.IgnoreAddresses
	}
	return &result
}

// DefaultIPRDConfig returns a default IPRDConfig
func DefaultIPRDConfig() *IPRDConfig {
	return &IPRDConfig{
		Debug:           false,
		Auto:            false,
		Filter:          false,
		ListenInterface: "eth0",
		ForwardPort:     7788,
		IgnoreAddresses: []string{},
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
