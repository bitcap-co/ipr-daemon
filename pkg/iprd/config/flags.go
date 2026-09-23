package config

import (
	"fmt"
	"slices"
	"strconv"
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
		selectors, err := expandInterfaceSelectors(value)
		if err != nil {
			return err
		}
		for _, selector := range selectors {
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

	selectors, err := expandInterfaceSelectors(ifaceID)
	if err != nil {
		return err
	}
	for _, selector := range selectors {
		if (*f)[selector] == nil {
			(*f)[selector] = DefaultInterfaceConfig()
		}
		if err := applyInterfaceOptions((*f)[selector], options); err != nil {
			return err
		}
	}
	return nil
}

func expandInterfaceSelectors(value string) ([]string, error) {
	selectors := make([]string, 0)
	for _, selector := range normalizeInterfaceSelectors([]string{value}) {
		startText, endText, hasHyphen := strings.Cut(selector, "-")
		if !hasHyphen || strings.Contains(endText, "-") {
			selectors = append(selectors, selector)
			continue
		}

		start, startErr := strconv.Atoi(startText)
		end, endErr := strconv.Atoi(endText)
		if startErr != nil || endErr != nil {
			selectors = append(selectors, selector)
			continue
		}
		if start <= 0 || end <= 0 {
			return nil, fmt.Errorf("interface index range %q must contain positive indexes", selector)
		}
		if start > end {
			return nil, fmt.Errorf("interface index range %q is descending", selector)
		}
		for index := start; ; index++ {
			selectors = append(selectors, strconv.Itoa(index))
			if index == end {
				break
			}
		}
	}
	return normalizeInterfaceSelectors(selectors), nil
}

func applyInterfaceOptions(cfg *InterfaceConfig, options string) error {
	for opt := range strings.SplitSeq(options, ",") {
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
