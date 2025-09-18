package iprd

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/google/gopacket/pcap"
)

// IPRInterface defines information from a system interface.
type IPRInterface struct {
	Index        int
	Name         string
	Description  string
	Addr         net.IP
	HardwareAddr net.HardwareAddr
	Flags        net.Flags
}

// IsLan checks if IPRInterface is marked as LAN interface.
func (i *IPRInterface) IsLan() bool {
	if i.Description == "" {
		return false
	}
	matched, _ := regexp.MatchString(`lan|LAN`, i.Description)
	return matched
}

// IsUp checks if IPRInterface is marked as up.
func (i *IPRInterface) IsUp() bool {
	if strings.Contains(i.Flags.String(), "up") {
		return true
	}
	return false
}

func getAllInterfaces() ([]IPRInterface, error) {
	interfaces := make([]IPRInterface, 0)
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var addr net.IP
	for _, iface := range ifaces {
		for _, address := range iface.Addresses {
			// Get first IPv4 address
			if address.IP != nil && address.IP.To4() != nil && !address.IP.IsLoopback() {
				addr = address.IP
				break
			}
		}
		netInterface, err := net.InterfaceByName(iface.Name)
		if err != nil {
			continue
		}

		interfaces = append(interfaces, IPRInterface{
			Index:        netInterface.Index,
			Name:         iface.Name,
			Description:  iface.Description,
			Addr:         addr,
			HardwareAddr: netInterface.HardwareAddr,
			Flags:        netInterface.Flags,
		})
	}
	return interfaces, nil
}

// GetInterfaceByName returns IPRInterface matching name.
func GetInterfaceByName(name string) (*IPRInterface, error) {
	ifaces, err := getAllInterfaces()
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
	ifaces, err := getAllInterfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.IsLan() {
			return &iface, nil
		}
	}
	return nil, fmt.Errorf("interface not found: could not find LAN interface")
}
