package config

import (
	"io"
	"os"

	"github.com/BurntSushi/toml"
)

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
