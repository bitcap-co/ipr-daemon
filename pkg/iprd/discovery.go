package iprd

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/betamos/zeroconf"
)

const (
	// MDNSServiceType is the DNS-SD service type advertised by iprd.
	MDNSServiceType = "_iprd._tcp"
	mdnsDomain      = "local."
)

type mdnsInterfaceState struct {
	Index     int
	Name      string
	Flags     net.Flags
	Addresses []string
}

func mdnsInterfaceStates() ([]mdnsInterfaceState, error) {
	ifaces, err := operationalMulticastInterfaces()
	if err != nil {
		return nil, err
	}
	states := make([]mdnsInterfaceState, 0, len(ifaces))
	for i := range ifaces {
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			continue
		}

		addresses := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			addresses = append(addresses, addr.String())
		}
		sort.Strings(addresses)

		states = append(states, mdnsInterfaceState{
			Index:     ifaces[i].Index,
			Name:      ifaces[i].Name,
			Flags:     ifaces[i].Flags,
			Addresses: addresses,
		})
	}

	sort.Slice(states, func(i, j int) bool {
		return states[i].Index < states[j].Index
	})
	return states, nil
}

// MDNSAdvertiser publishes the iprd TCP endpoint over mDNS/DNS-SD.
type MDNSAdvertiser struct {
	client    *zeroconf.Client
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

// NewMDNSAdvertiser advertises the iprd TCP endpoint. Without selectors, a
// wildcard bind publishes on every operational multicast interface and an
// explicit bind publishes on its owning interface. Selectors restrict wildcard
// advertisement; an explicit bind's owning interface is always added.
func NewMDNSAdvertiser(bind string, port int, version string, selectors []string) (*MDNSAdvertiser, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("determine hostname: %w", err)
	}
	service, err := newMDNSService(hostname, port, version)
	if err != nil {
		return nil, err
	}

	addr, explicit, err := parseMDNSBind(bind)
	if err != nil {
		return nil, err
	}
	if _, err := mdnsAdvertisementInterfaces(addr, explicit, selectors); err != nil {
		return nil, err
	}

	client := zeroconf.New().
		Publish(service).
		Interfaces(func() ([]net.Interface, error) {
			return mdnsAdvertisementInterfaces(addr, explicit, selectors)
		})
	if explicit {
		service.Addrs = []netip.Addr{addr}
	}

	opened, err := client.Open()
	if err != nil {
		return nil, fmt.Errorf("publish %s.%s: %w", MDNSServiceType, mdnsDomain, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	advertiser := &MDNSAdvertiser{
		client: opened,
		cancel: cancel,
	}
	advertiser.wg.Add(1)
	go func() {
		defer advertiser.wg.Done()
		advertiser.watchInterfaces(ctx)
	}()
	return advertiser, nil
}

func (a *MDNSAdvertiser) watchInterfaces(ctx context.Context) {
	const interval = 5 * time.Second

	prev, err := mdnsInterfaceStates()
	if err != nil {
		prev = nil
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			curr, err := mdnsInterfaceStates()
			if err != nil {
				continue
			}
			prev = reloadOnMDNSInterfaceChange(prev, curr, a.client.Reload)
		}
	}
}

// Close gracefully withdraws the DNS-SD record. It is safe to call more than once.
func (a *MDNSAdvertiser) Close() error {
	if a == nil || a.client == nil {
		return nil
	}
	a.closeOnce.Do(func() {
		if a.cancel != nil {
			a.cancel()
		}
		a.wg.Wait()
		a.closeErr = a.client.Close()
	})
	return a.closeErr
}

func reloadOnMDNSInterfaceChange(
	previous []mdnsInterfaceState,
	current []mdnsInterfaceState,
	reload func(),
) []mdnsInterfaceState {
	if reflect.DeepEqual(current, previous) {
		return previous
	}
	reload()
	return current
}

func newMDNSService(hostname string, port int, version string) (*zeroconf.Service, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("mDNS port must be between 1 and 65535")
	}
	instanceHost := sanitizeMDNSInstanceHost(hostname)
	instance := fmt.Sprintf("IPR Daemon on %s (%d)", instanceHost, port)
	service := zeroconf.NewService(zeroconf.NewType(MDNSServiceType), instance, uint16(port))
	service.Hostname = instanceHost + ".local"
	service.Text = []string{
		"txtvers=1",
		"protocol=iprd",
		"subscribe=" + TCPCommandSubscribe,
		"status=" + TCPCommandStatus,
	}
	if version = strings.TrimSpace(version); version != "" && !strings.EqualFold(version, "unknown") {
		service.Text = append(service.Text, "version="+version)
	}
	return service, nil
}

func sanitizeMDNSInstanceHost(hostname string) string {
	const maxHostLength = 40

	hostname = strings.TrimSuffix(strings.TrimSpace(hostname), ".")
	var builder strings.Builder
	for _, r := range hostname {
		if builder.Len() >= maxHostLength {
			break
		}
		if isMDNSHostRune(r) {
			builder.WriteRune(r)
		} else {
			builder.WriteByte('-')
		}
	}
	result := strings.Trim(builder.String(), "-")
	if result == "" {
		return "unknown-host"
	}
	return result
}

func isMDNSHostRune(r rune) bool {
	return r <= 127 && ((r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') || r == '-' || r == '_')
}

func isOperationalMulticast(iface net.Interface) bool {
	requiredFlags := net.FlagUp | net.FlagRunning | net.FlagMulticast
	return iface.Flags&requiredFlags == requiredFlags
}

func operationalMulticastInterfaces() ([]net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces for wildcard advertisement: %w", err)
	}
	return filterOperationalMulticastInterfaces(ifaces), nil
}

func filterOperationalMulticastInterfaces(ifaces []net.Interface) []net.Interface {
	filtered := make([]net.Interface, 0, len(ifaces))
	for _, iface := range ifaces {
		if isOperationalMulticast(iface) {
			filtered = append(filtered, iface)
		}
	}
	return filtered
}

func mdnsAdvertisementInterfaces(bind netip.Addr, explicit bool, selectors []string) ([]net.Interface, error) {
	if len(selectors) == 0 && !explicit {
		return operationalMulticastInterfaces()
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces for mDNS advertisement: %w", err)
	}

	selected := make([]net.Interface, 0, len(selectors)+1)
	if len(selectors) > 0 {
		selected, err = resolveMDNSInterfaces(ifaces, selectors)
		if err != nil {
			return nil, err
		}
	}
	if explicit {
		owner, err := interfaceForAddressFrom(bind, ifaces)
		if err != nil {
			return nil, err
		}
		selected = appendUniqueMDNSInterface(selected, *owner)
	}
	return selected, nil
}

func resolveMDNSInterfaces(ifaces []net.Interface, selectors []string) ([]net.Interface, error) {
	selected := make([]net.Interface, 0, len(selectors))
	for _, rawSelector := range selectors {
		selector := strings.TrimSpace(rawSelector)
		if selector == "" {
			return nil, fmt.Errorf("mDNS interface selector cannot be empty")
		}

		var matched *net.Interface
		if index, err := strconv.Atoi(selector); err == nil {
			if index <= 0 {
				return nil, fmt.Errorf("mDNS interface index %q must be positive", selector)
			}
			for i := range ifaces {
				if ifaces[i].Index == index {
					matched = &ifaces[i]
					break
				}
			}
		} else {
			for i := range ifaces {
				if ifaces[i].Name == selector {
					matched = &ifaces[i]
					break
				}
			}
		}
		if matched == nil {
			return nil, fmt.Errorf("mDNS interface %q not found", selector)
		}
		if !isOperationalMulticast(*matched) {
			return nil, fmt.Errorf("mDNS interface %q is not operational and multicast-capable", selector)
		}
		selected = appendUniqueMDNSInterface(selected, *matched)
	}
	return selected, nil
}

func appendUniqueMDNSInterface(ifaces []net.Interface, iface net.Interface) []net.Interface {
	for i := range ifaces {
		if ifaces[i].Index == iface.Index {
			return ifaces
		}
	}
	return append(ifaces, iface)
}

func parseMDNSBind(bind string) (netip.Addr, bool, error) {
	bind = strings.TrimSpace(bind)
	if bind == "" {
		return netip.Addr{}, false, nil
	}
	addr, err := netip.ParseAddr(bind)
	if err != nil {
		return netip.Addr{}, false, fmt.Errorf("parse mDNS bind address %q: %w", bind, err)
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() {
		return netip.Addr{}, false, nil
	}
	if addr.IsLoopback() || addr.IsMulticast() || !addr.IsGlobalUnicast() {
		return netip.Addr{}, false, fmt.Errorf("bind address %s is not LAN-discoverable", addr)
	}
	return addr, true, nil
}

func interfaceForAddressFrom(target netip.Addr, ifaces []net.Interface) (*net.Interface, error) {
	for i := range ifaces {
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			local, ok := netAddressIP(addr)
			if !ok || local.Unmap() != target {
				continue
			}
			if !isOperationalMulticast(ifaces[i]) {
				return nil, fmt.Errorf(
					"interface %s for bind address %s is not a operational multicast interface",
					ifaces[i].Name,
					target,
				)
			}
			return &ifaces[i], nil
		}
	}
	return nil, fmt.Errorf("bind address %s is not assigned to a local multicast interface", target)
}

func netAddressIP(addr net.Addr) (netip.Addr, bool) {
	var ip net.IP
	switch value := addr.(type) {
	case *net.IPNet:
		ip = value.IP
	case *net.IPAddr:
		ip = value.IP
	default:
		return netip.Addr{}, false
	}
	parsed, ok := netip.AddrFromSlice(ip)
	return parsed, ok
}
