package iprd

import (
	"fmt"
	"io"
	"os"

	"github.com/BurntSushi/toml"
)

type IPRDConfig struct {
	Debug           bool     `toml:"debug"`
	Auto            bool     `toml:"auto"`
	Filter          bool     `toml:"filter"`
	ListenInterface string   `toml:"listen_interface"`
	ForwardPort     int      `toml:"forward_port"`
	IgnoreAddresses []string `toml:"ignore_addrs"`
}

func (cfg *IPRDConfig) Validate() error {
	if cfg.ListenInterface == "" {
		return fmt.Errorf("ListenInterface must be present")
	}
	if cfg.ForwardPort <= 0 {
		return fmt.Errorf("ForwardPort must be positive")
	}
	return nil
}

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

func ParseConfig(supplied *IPRDConfig) (*IPRDConfig, error) {
	cfg := DefaultIPRDConfig().Merge(supplied)
	return cfg, cfg.Validate()
}

func NewIPRDConfigFromBytes(data []byte) (*IPRDConfig, error) {
	var cfg *IPRDConfig
	err := toml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	return ParseConfig(cfg)
}

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
