package config

import (
	"fmt"
	"slices"
	"strings"
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
		case opt == "known-ports":
			cfg.FilterKnownPorts = true
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
