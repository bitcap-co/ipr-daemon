package iprd

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket/pcap"
)

type IPRInterface struct {
	Index        int
	Name         string
	Description  string
	Addr         net.IP
	HardwareAddr net.HardwareAddr
	Flags        net.Flags
}

func (i *IPRInterface) IsLan() bool {
	if i.Description == "" {
		return false
	}
	if i.Description == "lan" || i.Description == "LAN" {
		return true
	}
	return false
}

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
			if address.IP != nil && address.IP.To4() != nil {
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
