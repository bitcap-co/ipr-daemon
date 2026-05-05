package iprd

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	lanRegex = regexp.MustCompile(`^lan|^LAN`)

	errInvalidInterfaceName = errors.New("invalid interface name")
	errInterfaceNotFound    = errors.New("interface not found")
	errNoValidInterfaces    = errors.New("no valid interfaces to listen on")
)

// IPRInterface describes a network interface supported for IP Report listening.
type IPRInterface struct {
	Index        int
	Name         string
	FriendlyName string
	Description  string
	IPv4         net.IP
	HardwareAddr net.HardwareAddr
	Flags        net.Flags
}

// IPAddr returns IPv4 as string.
func (i *IPRInterface) IPAddr() string {
	return i.IPv4.String()
}

// MACAddr returns HardwareAddr as string.
func (i *IPRInterface) MACAddr() string {
	return i.HardwareAddr.String()
}

// NetworkPrefix returns the network prefix(leading two octets) of IPv4.
func (i *IPRInterface) NetworkPrefix() string {
	return strings.Join(strings.Split(i.IPv4.String(), ".")[0:2], ".")
}

// String returns IPRInterface as string.
func (i IPRInterface) String() string {
	return fmt.Sprintf("%d: %s (%s) Desc:\"%s\"\n   Hardware:%s\n   IPv4:%s",
		i.Index, i.FriendlyName, i.Name, i.Description, i.HardwareAddr, i.IPv4)
}

// IsUp returns bool for if IPRInterface is marked as UP.
func (i *IPRInterface) IsUp() bool {
	return i.Flags&net.FlagUp != 0
}

// IsLAN returns bool for if IPRInterface is marked as LAN interface.
func (i *IPRInterface) IsLAN() bool {
	if i.Description == "" {
		return false
	}
	match := lanRegex.MatchString(i.Description)
	return match
}

// GetInterfaceByName returns the IPRInterface matching name.
func GetInterfaceByName(name string) (*IPRInterface, error) {
	if name == "" {
		return nil, errInvalidInterfaceName
	}
	ifaces, err := GetInterfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if name == iface.Name || name == iface.FriendlyName {
			return &iface, nil
		}
	}
	return nil, errInterfaceNotFound
}

// FindLANInterface returns the first IPRInterface marked as LAN, if any.
func FindLANInterface() (*IPRInterface, error) {
	ifaces, err := GetInterfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.IsLAN() {
			return &iface, nil
		}
	}
	return nil, errInterfaceNotFound
}
