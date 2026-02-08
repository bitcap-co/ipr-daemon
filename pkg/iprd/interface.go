package iprd

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/google/gopacket/pcap"
)

// IPRInterface describes a system network interface.
type IPRInterface struct {
	Index        int
	Name         string
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

// NetworkPrefix returns the network prefix(leading two octets) of IPv4
func (i *IPRInterface) NetworkPrefix() string {
	return strings.Join(strings.Split(i.IPv4.String(), ".")[0:2], ".")
}

// IsUp returns bool for if IPRInterface is marked as UP.
func (i *IPRInterface) IsUp() bool {
	if i.Flags&net.FlagUp != 0 {
		return true
	}
	return false
}

// IsLAN returns bool for if IPRInterface is marked as LAN interface.
func (i *IPRInterface) IsLAN() bool {
	if i.Description == "" {
		return false
	}
	match, _ := regexp.MatchString(`^lan|^LAN`, i.Description)
	return match
}

func getIPv4AddrFromInterface(i pcap.Interface) net.IP {
	for _, addr := range i.Addresses {
		if addr.IP != nil && addr.IP.To4() != nil && addr.IP.IsPrivate() {
			return addr.IP
		}
	}
	return nil
}

func getInterfaces() ([]IPRInterface, error) {
	interfaces := make([]IPRInterface, 0)
	availInterfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var ipv4 net.IP
	for _, iface := range availInterfaces {
		ipv4 = getIPv4AddrFromInterface(iface)
		if ipv4 == nil {
			continue
		}

		// get info from std net
		netInterface, err := net.InterfaceByName(iface.Name)
		if err != nil {
			continue
		}

		// ensure flags RUNNING/LOWER_UP, BROADCAST
		if netInterface.Flags&net.FlagRunning == 0 || netInterface.Flags&net.FlagBroadcast == 0 {
			continue
		}

		interfaces = append(interfaces, IPRInterface{
			Index:        netInterface.Index,
			Name:         iface.Name,
			Description:  iface.Description,
			IPv4:         ipv4,
			HardwareAddr: netInterface.HardwareAddr,
			Flags:        netInterface.Flags,
		})
	}
	return interfaces, nil
}

// GetInterfaceByName returns the IPRInterface matching name.
func GetInterfaceByName(name string) (*IPRInterface, error) {
	if name == "" {
		return nil, errInvalidInterfaceName
	}
	ifaces, err := getInterfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if name == iface.Name {
			return &iface, nil
		}
	}
	return nil, fmt.Errorf("interface not found: %s", name)
}

// FindLANInterface returns the first IPRInterface marked as LAN, if any.
func FindLANInterface() (*IPRInterface, error) {
	ifaces, err := getInterfaces()
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
