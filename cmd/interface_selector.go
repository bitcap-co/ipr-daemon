package main

import (
	"net"
	"strconv"
	"strings"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	iprdconfig "github.com/bitcap-co/ipr-daemon/pkg/iprd/config"
)

type captureInterfaceProvider func() ([]iprd.IPRInterface, error)
type mdnsInterfaceProvider func() ([]net.Interface, error)

func normalizeDaemonConfig(
	cfg *iprdconfig.IPRDConfig,
	captureProvider captureInterfaceProvider,
	mdnsProvider mdnsInterfaceProvider,
) {
	if cfg == nil {
		return
	}
	resolveCaptureInterfaceSelectors(&cfg.ListenerConfig, captureProvider)
	resolveMDNSInterfaceSelectors(&cfg.ForwardConfig, mdnsProvider)
}

// resolveCaptureInterfaceSelectors replaces numeric capture-interface selectors
// with stable interface names when the corresponding interface is currently
// available. Unresolved indexes and non-numeric selectors are preserved.
func resolveCaptureInterfaceSelectors(cfg *iprdconfig.ListenerConfig, provider captureInterfaceProvider) {
	if cfg == nil {
		return
	}

	var interfaces []iprd.IPRInterface
	if provider != nil {
		interfaces, _ = provider()
	}

	namesByIndex := make(map[int]string, len(interfaces))
	for _, iface := range interfaces {
		if iface.Index <= 0 || iface.Name == "" {
			continue
		}
		if _, exists := namesByIndex[iface.Index]; !exists {
			namesByIndex[iface.Index] = iface.Name
		}
	}
	resolve := func(selector string) string {
		selector = strings.TrimSpace(selector)
		index, err := strconv.Atoi(selector)
		if err != nil || index <= 0 {
			return selector
		}
		if name := namesByIndex[index]; name != "" {
			return name
		}
		return selector
	}

	selectors := cfg.ListenInterfaces
	if len(selectors) == 0 && cfg.ListenInterface != "" {
		selectors = []string{cfg.ListenInterface}
	}
	if len(selectors) == 0 {
		selectors = make([]string, 0, len(cfg.Interfaces))
		for _, interfaceCfg := range cfg.Interfaces {
			selectors = append(selectors, interfaceCfg.Selector)
		}
	}
	cfg.ListenInterfaces = resolveUniqueSelectors(selectors, resolve)
	if len(cfg.ListenInterfaces) > 0 {
		cfg.ListenInterface = cfg.ListenInterfaces[0]
	} else {
		cfg.ListenInterface = ""
	}

	merged := make([]iprdconfig.InterfaceConfig, 0, len(cfg.Interfaces))
	indexes := make(map[string]int, len(cfg.Interfaces))
	for _, interfaceCfg := range cfg.Interfaces {
		interfaceCfg.Selector = resolve(interfaceCfg.Selector)
		if index, exists := indexes[interfaceCfg.Selector]; exists {
			merged[index] = mergeResolvedInterfaceConfig(merged[index], interfaceCfg)
			continue
		}
		interfaceCfg.IgnoredDevices = append([]string(nil), interfaceCfg.IgnoredDevices...)
		interfaceCfg.NetworkInclusions = append([]string(nil), interfaceCfg.NetworkInclusions...)
		interfaceCfg.NetworkExclusions = append([]string(nil), interfaceCfg.NetworkExclusions...)
		indexes[interfaceCfg.Selector] = len(merged)
		merged = append(merged, interfaceCfg)
	}
	cfg.Interfaces = merged
}

func resolveMDNSInterfaceSelectors(cfg *iprdconfig.ForwardConfig, provider mdnsInterfaceProvider) {
	if cfg == nil || len(cfg.MDNSInterfaces) == 0 {
		return
	}

	selectors := resolveUniqueSelectors(cfg.MDNSInterfaces, strings.TrimSpace)
	if len(selectors) == 0 {
		cfg.MDNSInterfaces = selectors
		return
	}

	var interfaces []net.Interface
	if provider != nil {
		if discovered, err := provider(); err == nil {
			interfaces = discovered
		}
	}
	namesByIndex := make(map[int]string, len(interfaces))
	for _, iface := range interfaces {
		if iface.Index <= 0 || iface.Name == "" {
			continue
		}
		if _, exists := namesByIndex[iface.Index]; !exists {
			namesByIndex[iface.Index] = iface.Name
		}
	}
	resolve := func(selector string) string {
		index, err := strconv.Atoi(selector)
		if err != nil || index <= 0 {
			return selector
		}
		if name := namesByIndex[index]; name != "" {
			return name
		}
		return selector
	}
	cfg.MDNSInterfaces = resolveUniqueSelectors(selectors, resolve)
}

func resolveUniqueSelectors(selectors []string, resolve func(string) string) []string {
	resolved := make([]string, 0, len(selectors))
	seen := make(map[string]struct{}, len(selectors))
	for _, value := range selectors {
		for selector := range strings.SplitSeq(value, ",") {
			selector = resolve(selector)
			if selector == "" {
				continue
			}
			if _, exists := seen[selector]; exists {
				continue
			}
			seen[selector] = struct{}{}
			resolved = append(resolved, selector)
		}
	}
	return resolved
}

func mergeResolvedInterfaceConfig(current, next iprdconfig.InterfaceConfig) iprdconfig.InterfaceConfig {
	current.NoRootNetwork = current.NoRootNetwork || next.NoRootNetwork
	current.FilterKnownPorts = current.FilterKnownPorts || next.FilterKnownPorts
	current.IgnoredDevices = appendUnique(current.IgnoredDevices, next.IgnoredDevices...)
	current.NetworkInclusions = appendUnique(current.NetworkInclusions, next.NetworkInclusions...)
	current.NetworkExclusions = appendUnique(current.NetworkExclusions, next.NetworkExclusions...)
	return current
}

func appendUnique(current []string, values ...string) []string {
	if len(current) == 0 && len(values) == 0 {
		return append([]string(nil), current...)
	}
	result := make([]string, 0, len(current)+len(values))
	seen := make(map[string]struct{}, len(current)+len(values))
	appendValues := func(source []string) {
		for _, value := range source {
			if _, exists := seen[value]; exists {
				continue
			}
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	appendValues(current)
	appendValues(values)
	return result
}
