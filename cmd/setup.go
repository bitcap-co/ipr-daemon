package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	iprdconfig "github.com/bitcap-co/ipr-daemon/pkg/iprd/config"
	"github.com/ergochat/readline"
)

const (
	defaultSetupPath   = "/etc/iprd.toml"
	defaultCapturePath = "/var/log/iprd/capture.pcapng"
)

type setupPrompter struct {
	reader   *bufio.Reader
	out      io.Writer
	terminal *readline.Instance
}

type setupInterfaceProvider func() ([]iprd.IPRInterface, error)

func newSetupPrompter(in io.Reader, out io.Writer) (*setupPrompter, error) {
	prompter := &setupPrompter{reader: bufio.NewReader(in), out: out}
	if !isInteractiveTerminal(in, out) {
		return prompter, nil
	}

	terminal, err := readline.NewFromConfig(&readline.Config{
		Stdin:                  in,
		Stdout:                 out,
		Stderr:                 out,
		HistoryLimit:           -1,
		DisableAutoSaveHistory: true,
		InterruptPrompt:        "^C",
		EOFPrompt:              "^D",
	})
	if err != nil {
		return nil, err
	}
	prompter.terminal = terminal
	return prompter, nil
}

func isInteractiveTerminal(in io.Reader, out io.Writer) bool {
	input, inputOK := in.(*os.File)
	output, outputOK := out.(*os.File)
	if !inputOK || !outputOK {
		return false
	}
	inputInfo, inputErr := input.Stat()
	outputInfo, outputErr := output.Stat()
	return inputErr == nil && outputErr == nil && inputInfo.Mode()&os.ModeCharDevice != 0 && outputInfo.Mode()&os.ModeCharDevice != 0
}

func (p *setupPrompter) close() {
	if p.terminal != nil {
		_ = p.terminal.Close()
	}
}

func runSetup(in io.Reader, out io.Writer, configPath string, getInterfaces setupInterfaceProvider) error {
	cfg := iprdconfig.DefaultIPRDConfig()
	if configPath != "" {
		loaded, err := iprdconfig.NewIPRDConfigFromFile(configPath)
		if err != nil {
			return fmt.Errorf("load setup configuration %q: %w", configPath, err)
		}
		cfg = loaded
	}

	prompter, err := newSetupPrompter(in, out)
	if err != nil {
		return fmt.Errorf("initialize interactive input: %w", err)
	}
	defer prompter.close()

	fmt.Fprintln(out, "IPR Daemon interactive setup")
	if configPath == "" {
		fmt.Fprintln(out, "Creating a new configuration from defaults.")
	} else {
		fmt.Fprintf(out, "Editing configuration: %s\n", configPath)
	}
	fmt.Fprintln(out)

	if err := prompter.configure(cfg, getInterfaces); err != nil {
		return err
	}
	parsed, err := iprdconfig.ParseConfig(cfg)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	prompter.printSummary(parsed)

	defaultPath := configPath
	if defaultPath == "" {
		defaultPath = defaultSetupPath
	}
	destination, write, err := prompter.writeDestination(defaultPath)
	if err != nil {
		return err
	}
	if !write {
		fmt.Fprintln(out, "Configuration was not written.")
		return nil
	}

	if destination != configPath {
		if _, err := os.Stat(destination); err == nil {
			overwrite, err := prompter.yesNo(fmt.Sprintf("%s already exists. Overwrite it?", destination), false)
			if err != nil {
				return err
			}
			if !overwrite {
				fmt.Fprintln(out, "Configuration was not written.")
				return nil
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect destination %q: %w", destination, err)
		}
	}

	if err := writeSetupConfig(parsed, destination); err != nil {
		return fmt.Errorf("write configuration %q: %w", destination, err)
	}
	fmt.Fprintf(out, "Configuration written to %s\n", destination)
	fmt.Fprintf(out, "Run iprd with: iprd -c %s\n", destination)
	return nil
}

func (p *setupPrompter) configure(cfg *iprdconfig.IPRDConfig, getInterfaces setupInterfaceProvider) error {
	interfaces, interfaceErr := getInterfaces()
	if interfaceErr != nil {
		fmt.Fprintf(p.out, "Available capture interfaces could not be listed: %v\n\n", interfaceErr)
	} else {
		p.printInterfaces(interfaces)
	}

	modeDefault := 1
	if cfg.Auto {
		modeDefault = 2
	}
	fmt.Fprintln(p.out, "Capture interface mode:")
	fmt.Fprintln(p.out, "  1) Choose one or more interfaces")
	fmt.Fprintln(p.out, "  2) Automatically find the LAN interface (OPNsense/pfSense)")
	mode, err := p.choice("Choice", modeDefault, 1, 2)
	if err != nil {
		return err
	}

	if mode == 2 {
		cfg.Auto = true
		cfg.ListenInterfaces = nil
		cfg.ListenInterface = ""
		cfg.Interfaces = nil
	} else {
		if interfaceErr != nil {
			return fmt.Errorf("list capture interfaces: %w", interfaceErr)
		}
		selectors, err := p.selectInterfaces(interfaces, cfg.ListenInterfaces)
		if err != nil {
			return err
		}
		cfg.Auto = false
		cfg.ListenInterfaces = selectors
		cfg.ListenInterface = selectors[0]
		cfg.Interfaces = selectedInterfaceConfigs(cfg.Interfaces, selectors, interfaces)
	}

	bindDefault := cfg.Bind
	if bindDefault == "" {
		bindDefault = "all"
	}
	for {
		bind, err := p.text("TCP bind address (use 'all' for all local addresses)", bindDefault)
		if err != nil {
			return err
		}
		if strings.EqualFold(bind, "all") || bind == "*" {
			cfg.Bind = ""
			break
		}
		if net.ParseIP(bind) != nil {
			cfg.Bind = bind
			break
		}
		fmt.Fprintln(p.out, "Please enter a valid IP address or 'all'.")
	}

	for {
		port, err := p.integer("TCP forwarding port", cfg.Port)
		if err != nil {
			return err
		}
		if port > 0 && port <= 65535 {
			cfg.Port = port
			break
		}
		fmt.Fprintln(p.out, "Port must be between 1 and 65535.")
	}

	cfg.MDNS, err = p.yesNo("Advertise this daemon using mDNS/DNS-SD?", cfg.MDNS)
	if err != nil {
		return err
	}
	if cfg.MDNS {
		advertiseDefault := strings.Join(cfg.MDNSInterfaces, ",")
		if advertiseDefault == "" {
			advertiseDefault = "all"
		}
		advertise, err := p.text("mDNS interfaces, comma-separated (use 'all' for all suitable interfaces)", advertiseDefault)
		if err != nil {
			return err
		}
		if strings.EqualFold(advertise, "all") || advertise == "*" {
			cfg.MDNSInterfaces = nil
		} else {
			cfg.MDNSInterfaces = splitValues(advertise)
		}
	} else {
		cfg.MDNSInterfaces = nil
	}

	captureEnabled, err := p.yesNo("Write received packets to a PCAP-NG file?", cfg.CaptureFile != "")
	if err != nil {
		return err
	}
	if captureEnabled {
		captureDefault := cfg.CaptureFile
		if captureDefault == "" {
			captureDefault = defaultCapturePath
		}
		for {
			cfg.CaptureFile, err = p.path("Capture file path", captureDefault)
			if err != nil {
				return err
			}
			if cfg.CaptureFile != "" {
				break
			}
			fmt.Fprintln(p.out, "Capture file path cannot be empty.")
		}
		cfg.RotateCaptureFiles, err = p.yesNo("Keep rotated capture history?", cfg.RotateCaptureFiles)
		if err != nil {
			return err
		}
	} else {
		cfg.CaptureFile = ""
		cfg.RotateCaptureFiles = false
	}

	cfg.ForwardKnown, err = p.yesNo("Forward only reports recognized as supported miner types?", cfg.ForwardKnown)
	if err != nil {
		return err
	}
	cfg.FilterKnownPorts, err = p.yesNo("Restrict packet capture to known miner ports?", cfg.FilterKnownPorts)
	if err != nil {
		return err
	}

	advancedDefault := cfg.NoRootNetwork || len(cfg.NetworkInclusions) > 0 || len(cfg.NetworkExclusions) > 0 || len(cfg.IgnoredDevices) > 0
	advanced, err := p.yesNo("Configure global advanced BPF filters?", advancedDefault)
	if err != nil {
		return err
	}
	if advanced {
		inclusions, err := p.text("Additional networks to include, comma-separated", strings.Join(cfg.NetworkInclusions, ","))
		if err != nil {
			return err
		}
		cfg.NetworkInclusions = splitValues(inclusions)

		exclusions, err := p.text("Networks to exclude, comma-separated", strings.Join(cfg.NetworkExclusions, ","))
		if err != nil {
			return err
		}
		cfg.NetworkExclusions = splitValues(exclusions)

		ignored, err := p.text("MAC addresses to ignore, comma-separated", strings.Join(cfg.IgnoredDevices, ","))
		if err != nil {
			return err
		}
		cfg.IgnoredDevices = splitValues(ignored)

		cfg.NoRootNetwork, err = p.yesNo("Exclude each selected interface's own network?", cfg.NoRootNetwork)
		if err != nil {
			return err
		}
		if cfg.NoRootNetwork && len(cfg.NetworkInclusions) == 0 {
			fmt.Fprintln(p.out, "The root network cannot be excluded without at least one included network.")
			cfg.NoRootNetwork = false
		}
	} else {
		cfg.NoRootNetwork = false
		cfg.NetworkInclusions = nil
		cfg.NetworkExclusions = nil
		cfg.IgnoredDevices = nil
	}

	return nil
}

func (p *setupPrompter) printInterfaces(interfaces []iprd.IPRInterface) {
	fmt.Fprintln(p.out, "Available capture interfaces:")
	for i, iface := range interfaces {
		if iface.Description != "" {
			fmt.Fprintln(p.out, fmt.Sprintf("  %d) (%s) %-12s %-15s %s", i+1, iface.Description, iface.FriendlyName, iface.IPAddr(), iface.MACAddr()))
		} else {
			fmt.Fprintln(p.out, fmt.Sprintf("  %d) %-12s %-15s %s", i+1, iface.FriendlyName, iface.IPAddr(), iface.MACAddr()))
		}
	}
	fmt.Fprintln(p.out)
}

func (p *setupPrompter) selectInterfaces(interfaces []iprd.IPRInterface, current []string) ([]string, error) {
	current = interfaceNames(interfaces, current)
	for {
		selection, err := p.text("Select interfaces by number or name, comma-separated", strings.Join(current, ","))
		if err != nil {
			return nil, err
		}
		selectors, err := parseInterfaceSelection(interfaces, selection)
		if err == nil && len(selectors) > 0 {
			return selectors, nil
		}
		if err != nil {
			fmt.Fprintf(p.out, "%v\n", err)
		} else {
			fmt.Fprintln(p.out, "Select at least one interface.")
		}
	}
}

func (p *setupPrompter) printSummary(cfg *iprdconfig.IPRDConfig) {
	fmt.Fprintln(p.out)
	fmt.Fprintln(p.out, "Configuration summary")
	if cfg.Auto {
		fmt.Fprintln(p.out, "  Capture mode:       Automatic LAN interface")
	} else {
		fmt.Fprintf(p.out, "  Interfaces:         %s\n", strings.Join(cfg.ListenInterfaces, ", "))
	}
	bind := cfg.Bind
	if bind == "" {
		bind = "all addresses"
	}
	fmt.Fprintf(p.out, "  Forward endpoint:   %s, port %d\n", bind, cfg.Port)
	fmt.Fprintf(p.out, "  mDNS:               %s\n", enabledText(cfg.MDNS))
	if cfg.MDNS && len(cfg.MDNSInterfaces) > 0 {
		fmt.Fprintf(p.out, "  mDNS interfaces:    %s\n", strings.Join(cfg.MDNSInterfaces, ", "))
	}
	if cfg.CaptureFile == "" {
		fmt.Fprintln(p.out, "  Packet capture:     Disabled")
	} else {
		fmt.Fprintf(p.out, "  Packet capture:     %s (rotation: %s)\n", cfg.CaptureFile, enabledText(cfg.RotateCaptureFiles))
	}
	fmt.Fprintf(p.out, "  Known miners only:  %s\n", enabledText(cfg.ForwardKnown))
	fmt.Fprintf(p.out, "  Known ports only:   %s\n", enabledText(cfg.FilterKnownPorts))
	advanced := cfg.NoRootNetwork || len(cfg.NetworkInclusions) > 0 || len(cfg.NetworkExclusions) > 0 || len(cfg.IgnoredDevices) > 0
	fmt.Fprintf(p.out, "  Advanced BPF:       %s\n", enabledText(advanced))
	fmt.Fprintln(p.out)
}

func (p *setupPrompter) writeDestination(defaultPath string) (string, bool, error) {
	for {
		prompt := fmt.Sprintf("Write configuration to %s? [Y/n/path]: ", defaultPath)
		answer, err := p.promptLine(prompt, pathCompleter{})
		if err != nil {
			return "", false, err
		}
		if strings.EqualFold(answer, "n") || strings.EqualFold(answer, "no") {
			return "", false, nil
		}

		destination := defaultPath
		if answer != "" && !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
			destination = answer
		}
		destination = filepath.Clean(expandHomeDirectory(destination))
		if err := validateSetupDestination(destination); err != nil {
			fmt.Fprintf(p.out, "%v\n", err)
			continue
		}
		return destination, true, nil
	}
}

func validateSetupDestination(destination string) error {
	if info, err := os.Stat(destination); err == nil && info.IsDir() {
		return fmt.Errorf("destination %q is a directory; enter a file path", destination)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect destination %q: %w", destination, err)
	}

	directory := filepath.Dir(destination)
	info, err := os.Stat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("destination directory %q does not exist; enter a path in an existing directory", directory)
	}
	if err != nil {
		return fmt.Errorf("inspect destination directory %q: %w", directory, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("destination parent %q is not a directory", directory)
	}
	return nil
}

func (p *setupPrompter) yesNo(question string, defaultValue bool) (bool, error) {
	suffix := "[y/N]"
	if defaultValue {
		suffix = "[Y/n]"
	}
	for {
		answer, err := p.promptLine(fmt.Sprintf("%s %s: ", question, suffix), nil)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(answer) {
		case "":
			return defaultValue, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Fprintln(p.out, "Please answer yes or no.")
		}
	}
}

func (p *setupPrompter) choice(question string, defaultValue, minValue, maxValue int) (int, error) {
	for {
		value, err := p.integer(question, defaultValue)
		if err != nil {
			return 0, err
		}
		if value >= minValue && value <= maxValue {
			return value, nil
		}
		fmt.Fprintf(p.out, "Please enter a number from %d to %d.\n", minValue, maxValue)
	}
}

func (p *setupPrompter) integer(question string, defaultValue int) (int, error) {
	for {
		answer, err := p.text(question, strconv.Itoa(defaultValue))
		if err != nil {
			return 0, err
		}
		value, err := strconv.Atoi(answer)
		if err == nil {
			return value, nil
		}
		fmt.Fprintln(p.out, "Please enter a number.")
	}
}

func (p *setupPrompter) text(question, defaultValue string) (string, error) {
	return p.textWithCompleter(question, defaultValue, nil)
}

func (p *setupPrompter) path(question, defaultValue string) (string, error) {
	path, err := p.textWithCompleter(question, defaultValue, pathCompleter{})
	if err != nil {
		return "", err
	}
	return expandHomeDirectory(path), nil
}

func (p *setupPrompter) textWithCompleter(question, defaultValue string, completer readline.AutoCompleter) (string, error) {
	answer, err := p.promptLine(fmt.Sprintf("%s [%s]: ", question, defaultValue), completer)
	if err != nil {
		return "", err
	}
	if answer == "" {
		return defaultValue, nil
	}
	return answer, nil
}

func (p *setupPrompter) promptLine(prompt string, completer readline.AutoCompleter) (string, error) {
	if p.terminal == nil {
		fmt.Fprint(p.out, prompt)
		return p.line()
	}

	config := p.terminal.GetConfig()
	config.Prompt = prompt
	config.AutoComplete = completer
	if err := p.terminal.SetConfig(config); err != nil {
		return "", fmt.Errorf("configure interactive prompt: %w", err)
	}
	line, err := p.terminal.ReadLine()
	if errors.Is(err, readline.ErrInterrupt) {
		return "", fmt.Errorf("setup cancelled")
	}
	if errors.Is(err, io.EOF) {
		return "", fmt.Errorf("setup input closed")
	}
	if err != nil {
		return "", fmt.Errorf("read setup input: %w", err)
	}
	return strings.TrimSpace(line), nil
}

func (p *setupPrompter) line() (string, error) {
	line, err := p.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read setup input: %w", err)
	}
	line = strings.TrimSpace(line)
	if errors.Is(err, io.EOF) && line == "" {
		return "", fmt.Errorf("setup input closed")
	}
	return line, nil
}

type pathCompleter struct{}

func (pathCompleter) Do(line []rune, position int) ([][]rune, int) {
	if position < 0 || position > len(line) {
		return nil, 0
	}
	typed := string(line[:position])
	expanded := expandHomeDirectory(typed)
	if expanded != "" && !strings.HasSuffix(typed, string(os.PathSeparator)) {
		if info, err := os.Stat(expanded); err == nil && info.IsDir() {
			return [][]rune{[]rune(string(os.PathSeparator))}, 0
		}
	}

	directory := "."
	base := ""
	if expanded != "" {
		if strings.HasSuffix(typed, string(os.PathSeparator)) {
			directory = strings.TrimSuffix(expanded, string(os.PathSeparator))
			if directory == "" {
				directory = string(os.PathSeparator)
			}
		} else {
			directory = filepath.Dir(expanded)
			base = filepath.Base(expanded)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, len([]rune(base))
	}

	candidates := make([][]rune, 0)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, base) || (base == "" && strings.HasPrefix(name, ".")) {
			continue
		}
		suffix := strings.TrimPrefix(name, base)
		if entry.IsDir() {
			suffix += string(os.PathSeparator)
		}
		candidates = append(candidates, []rune(suffix))
	}
	return candidates, len([]rune(base))
}

func expandHomeDirectory(path string) string {
	if path != "~" && !strings.HasPrefix(path, "~"+string(os.PathSeparator)) {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~"+string(os.PathSeparator)))
}

func parseInterfaceSelection(interfaces []iprd.IPRInterface, selection string) ([]string, error) {
	selectors := make([]string, 0)
	for _, value := range splitValues(selection) {
		matched := ""
		for _, iface := range interfaces {
			if value == iface.Name || value == iface.FriendlyName {
				matched = iface.Name
				break
			}
		}
		if matched == "" {
			if number, err := strconv.Atoi(value); err == nil {
				if number >= 1 && number <= len(interfaces) {
					matched = interfaces[number-1].Name
				} else {
					for _, iface := range interfaces {
						if number == iface.Index {
							matched = iface.Name
							break
						}
					}
				}
			}
		}
		if matched == "" {
			return nil, fmt.Errorf("interface %q is not available", value)
		}
		if !slices.Contains(selectors, matched) {
			selectors = append(selectors, matched)
		}
	}
	return selectors, nil
}

func interfaceNames(interfaces []iprd.IPRInterface, selectors []string) []string {
	names := make([]string, 0, len(selectors))
	for _, selector := range selectors {
		if name, ok := canonicalInterfaceName(interfaces, selector); ok {
			names = append(names, name)
		} else {
			names = append(names, selector)
		}
	}
	return names
}

func canonicalInterfaceName(interfaces []iprd.IPRInterface, selector string) (string, bool) {
	for _, iface := range interfaces {
		if selector == iface.Name || selector == iface.FriendlyName {
			return iface.Name, true
		}
	}
	if index, err := strconv.Atoi(selector); err == nil {
		for _, iface := range interfaces {
			if iface.Index == index {
				return iface.Name, true
			}
		}
	}
	return "", false
}

func selectedInterfaceConfigs(configs []iprdconfig.InterfaceConfig, selectors []string, interfaces []iprd.IPRInterface) []iprdconfig.InterfaceConfig {
	selected := make([]iprdconfig.InterfaceConfig, 0, len(configs))
	for _, cfg := range configs {
		selector := strings.TrimSpace(cfg.Selector)
		if name, ok := canonicalInterfaceName(interfaces, selector); ok {
			selector = name
		}
		if slices.Contains(selectors, selector) {
			cfg.Selector = selector
			selected = append(selected, cfg)
		}
	}
	return selected
}

func splitValues(value string) []string {
	values := make([]string, 0)
	for part := range strings.SplitSeq(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" && !slices.Contains(values, part) {
			values = append(values, part)
		}
	}
	return values
}

func enabledText(enabled bool) string {
	if enabled {
		return "Enabled"
	}
	return "Disabled"
}

func writeSetupConfig(cfg *iprdconfig.IPRDConfig, destination string) error {
	directory := filepath.Dir(destination)
	temp, err := os.CreateTemp(directory, ".iprd-setup-*.toml")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	if err := temp.Close(); err != nil {
		os.Remove(tempPath)
		return err
	}
	defer os.Remove(tempPath)

	mode := os.FileMode(0o644)
	if info, err := os.Stat(destination); err == nil {
		mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Chmod(tempPath, mode); err != nil {
		return err
	}
	if err := iprdconfig.WriteIPRDConfigToFile(cfg, tempPath); err != nil {
		return err
	}
	return os.Rename(tempPath, destination)
}
