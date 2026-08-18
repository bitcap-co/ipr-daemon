package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

func updateExistingConfig(curr, target *iprd.IPRDConfig) *iprd.IPRDConfig {
	newCfg := curr.Merge(target)
	if len(target.ListenInterfaces) > 0 {
		newCfg.ListenInterfaces = mergeUnique(curr.ListenInterfaces, target.ListenInterfaces)
	}
	newCfg.Interfaces = mergeInterfaceConfigs(curr.Interfaces, target.Interfaces)
	if len(target.IgnoredDevices) > 0 && !slices.Equal(target.IgnoredDevices, curr.IgnoredDevices) {
		newCfg.IgnoredDevices = mergeSortedUnique(curr.IgnoredDevices, target.IgnoredDevices)
		log.Info(fmt.Sprintf("updated ignored_devices: %v -> %v", curr.IgnoredDevices, newCfg.IgnoredDevices))
	}
	if len(target.NetworkInclusions) > 0 && !slices.Equal(target.NetworkInclusions, curr.NetworkInclusions) {
		newCfg.NetworkInclusions = mergeSortedUnique(curr.NetworkInclusions, target.NetworkInclusions)
		log.Info(fmt.Sprintf("updated network_inclusions: %v -> %v", curr.NetworkInclusions, newCfg.NetworkInclusions))
	}
	if target.NoRootNetwork && len(newCfg.NetworkInclusions) > 0 {
		newCfg.NoRootNetwork = !curr.NoRootNetwork || !target.NoRootNetwork
		log.Info(fmt.Sprintf("toggled no_root_network: %v -> %v", curr.NoRootNetwork, newCfg.NoRootNetwork))
	} else if target.NoRootNetwork {
		log.Error(fmt.Errorf("no_root_network set to true but network_inclusions is empty, ignored"))
		newCfg.NoRootNetwork = false
	}
	if len(target.NetworkExclusions) > 0 && !slices.Equal(target.NetworkExclusions, curr.NetworkExclusions) {
		newCfg.NetworkExclusions = mergeSortedUnique(curr.NetworkExclusions, target.NetworkExclusions)
		log.Info(fmt.Sprintf("updated network_exclusions: %v -> %v", curr.NetworkExclusions, newCfg.NetworkExclusions))
	}
	if target.Bind != "" && target.Bind != curr.Bind {
		log.Info(fmt.Sprintf("updated forward_bind: %s -> %s", curr.Bind, newCfg.Bind))
	}
	if target.Port != 0 && target.Port != curr.Port {
		log.Info(fmt.Sprintf("updated forward_port: %d -> %d", curr.Port, newCfg.Port))
	}
	if target.CaptureFile != "" && target.CaptureFile != curr.CaptureFile {
		log.Info(fmt.Sprintf("updated capture_file: %s -> %s", curr.CaptureFile, newCfg.CaptureFile))
	}
	// toggle boolean flags
	if target.Auto {
		newCfg.Auto = !target.Auto || !curr.Auto
		log.Info(fmt.Sprintf("toggled auto: %v -> %v", curr.Auto, newCfg.Auto))
	}
	if target.Debug {
		newCfg.Debug = !target.Debug || !curr.Debug
		log.Info(fmt.Sprintf("toggled debug: %v -> %v", curr.Debug, newCfg.Debug))
	}
	if target.ForwardKnown {
		newCfg.ForwardKnown = !target.ForwardKnown || !curr.ForwardKnown
		log.Info(fmt.Sprintf("toggled forward_known: %v -> %v", curr.ForwardKnown, newCfg.ForwardKnown))
	}
	if target.MDNS {
		newCfg.MDNS = !target.MDNS || !curr.MDNS
		log.Info(fmt.Sprintf("toggled mdns: %v -> %v", curr.MDNS, newCfg.MDNS))
	}
	if target.NoRootNetwork {
		newCfg.NoRootNetwork = !target.NoRootNetwork || !curr.NoRootNetwork
		log.Info(fmt.Sprintf("toggled no_root_network: %v -> %v", curr.NoRootNetwork, newCfg.NoRootNetwork))
	}
	if target.FilterKnownPorts {
		newCfg.FilterKnownPorts = !target.FilterKnownPorts || !curr.FilterKnownPorts
		log.Info(fmt.Sprintf("toggled filter_known_ports: %v -> %v", curr.FilterKnownPorts, newCfg.FilterKnownPorts))
	}
	if target.RotateCaptureFiles {
		newCfg.RotateCaptureFiles = !target.RotateCaptureFiles || !curr.RotateCaptureFiles
		log.Info(fmt.Sprintf("toggled rotate_capture_files: %v -> %v", curr.RotateCaptureFiles, newCfg.RotateCaptureFiles))
	}
	return newCfg
}

func mergeInterfaceConfigs(curr, target []iprd.InterfaceConfig) []iprd.InterfaceConfig {
	merged := make([]iprd.InterfaceConfig, len(curr))
	indexes := make(map[string]int, len(curr)+len(target))
	for i, interfaceCfg := range curr {
		merged[i] = cloneInterfaceConfig(interfaceCfg)
		indexes[strings.TrimSpace(interfaceCfg.Selector)] = i
	}

	for _, targetCfg := range target {
		selector := strings.TrimSpace(targetCfg.Selector)
		if i, ok := indexes[selector]; ok {
			currentCfg := merged[i]
			updatedCfg := mergeInterfaceConfig(currentCfg, targetCfg)
			logInterfaceConfigChanges(selector, currentCfg, updatedCfg)
			merged[i] = updatedCfg
			continue
		}

		indexes[selector] = len(merged)
		merged = append(merged, cloneInterfaceConfig(targetCfg))
	}
	return merged
}

func mergeInterfaceConfig(curr, target iprd.InterfaceConfig) iprd.InterfaceConfig {
	merged := cloneInterfaceConfig(curr)
	if target.FilterKnownPorts {
		merged.FilterKnownPorts = !curr.FilterKnownPorts || !target.FilterKnownPorts
	}
	merged.NetworkInclusions = mergeSortedUnique(curr.NetworkInclusions, target.NetworkInclusions)
	if target.NoRootNetwork && len(merged.NetworkInclusions) > 0 {
		merged.NoRootNetwork = !curr.NoRootNetwork || !target.NoRootNetwork
	} else if target.NoRootNetwork {
		log.Error(fmt.Errorf("[%s] no_root_network set to true but network_inclusions is empty, ignored", merged.Selector))
		merged.NoRootNetwork = false
	}
	merged.IgnoredDevices = mergeSortedUnique(curr.IgnoredDevices, target.IgnoredDevices)
	merged.NetworkExclusions = mergeSortedUnique(curr.NetworkExclusions, target.NetworkExclusions)
	return merged
}

func logInterfaceConfigChanges(selector string, curr, target iprd.InterfaceConfig) {
	if curr.NoRootNetwork != target.NoRootNetwork {
		log.Info(fmt.Sprintf("[%s] toggled no_root_network: %v -> %v", selector, curr.NoRootNetwork, target.NoRootNetwork))
	}
	if curr.FilterKnownPorts != target.FilterKnownPorts {
		log.Info(fmt.Sprintf("[%s] toggled filter_known_ports: %v -> %v", selector, curr.FilterKnownPorts, target.FilterKnownPorts))
	}
	if !slices.Equal(curr.IgnoredDevices, target.IgnoredDevices) {
		log.Info(fmt.Sprintf("[%s] updated ignored_devices: %v -> %v", selector, curr.IgnoredDevices, target.IgnoredDevices))
	}
	if !slices.Equal(curr.NetworkInclusions, target.NetworkInclusions) {
		log.Info(fmt.Sprintf("[%s] updated network_inclusions: %v -> %v", selector, curr.NetworkInclusions, target.NetworkInclusions))
	}
	if !slices.Equal(curr.NetworkExclusions, target.NetworkExclusions) {
		log.Info(fmt.Sprintf("[%s] updated network_exclusions: %v -> %v", selector, curr.NetworkExclusions, target.NetworkExclusions))
	}
}

func cloneInterfaceConfig(cfg iprd.InterfaceConfig) iprd.InterfaceConfig {
	cfg.IgnoredDevices = slices.Clone(cfg.IgnoredDevices)
	cfg.NetworkInclusions = slices.Clone(cfg.NetworkInclusions)
	cfg.NetworkExclusions = slices.Clone(cfg.NetworkExclusions)
	return cfg
}

func mergeSortedUnique(curr, target []string) []string {
	if len(target) == 0 {
		return slices.Clone(curr)
	}
	merged := slices.Concat(curr, target)
	slices.Sort(merged)
	return unique(merged)
}

func mergeUnique(curr, target []string) []string {
	return unique(slices.Concat(curr, target))
}

func unique(s []string) []string {
	var unique []string
	m := make(map[string]bool)
	for _, item := range s {
		if !m[item] {
			m[item] = true
			unique = append(unique, item)
		}
	}
	return unique
}
