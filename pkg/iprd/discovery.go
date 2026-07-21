package iprd

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/betamos/zeroconf"
)

const (
	// MDNSServiceType is the DNS-SD service type advertised by iprd.
	MDNSServiceType = "_iprd._tcp"
	mdnsDomain      = "local."
)

// MDNSAdvertiser publishes the iprd TCP endpoint over mDNS/DNS-SD.
type MDNSAdvertiser struct {
	client    *zeroconf.Client
	closeOnce sync.Once
	closeErr  error
}

// NewMDNSAdvertiser advertises the iprd TCP endpoint. A wildcard bind is
// published on all multicast-capable interfaces; an explicit bind is limited
// to the local interface that owns that address.
func NewMDNSAdvertiser(bind string, port int, version string) (*MDNSAdvertiser, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("determine hostname: %w", err)
	}
	service, err := newMDNSService(hostname, port, version)
	if err != nil {
		return nil, err
	}

	client := zeroconf.New().Publish(service)
	addr, explicit, err := parseMDNSBind(bind)
	if err != nil {
		return nil, err
	}
	if explicit {
		iface, err := interfaceForAddress(addr)
		if err != nil {
			return nil, err
		}
		service.Addrs = []netip.Addr{addr}
		client.Interfaces(func() ([]net.Interface, error) {
			return []net.Interface{*iface}, nil
		})
	}

	opened, err := client.Open()
	if err != nil {
		return nil, fmt.Errorf("publish %s.%s: %w", MDNSServiceType, mdnsDomain, err)
	}
	return &MDNSAdvertiser{client: opened}, nil
}

// Close gracefully withdraws the DNS-SD record. It is safe to call more than once.
func (a *MDNSAdvertiser) Close() error {
	if a == nil || a.client == nil {
		return nil
	}
	a.closeOnce.Do(func() {
		a.closeErr = a.client.Close()
	})
	return a.closeErr
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
		"subscribe=iprd_subscribe",
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

func interfaceForAddress(target netip.Addr) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces for bind address %s: %w", target, err)
	}
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
			if ifaces[i].Flags&net.FlagUp == 0 || ifaces[i].Flags&net.FlagMulticast == 0 {
				return nil, fmt.Errorf("interface %s for bind address %s does not support multicast", ifaces[i].Name, target)
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
