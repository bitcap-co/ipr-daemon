//go:build linux || darwin

package iprd

import (
	"net"

	"github.com/gopacket/gopacket/pcap"
)

// GetInterfaces returns a list of available IPRInterfaces for IP report listening.
// Returns an error if no valid interfaces found.
func GetInterfaces() ([]IPRInterface, error) {
	interfaces := make([]IPRInterface, 0)
	// find all available system interfaces using libpcap
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	for _, dev := range devs {
		// anonymous function that loops through all attached addresses
		// on dev and returns the first valid local/private IPv4 address.
		// returns nil if no valid IPv4 address is found.
		ipv4 := func(i pcap.Interface) net.IP {
			for _, addr := range i.Addresses {
				if addr.IP != nil && addr.IP.To4() != nil && addr.IP.IsPrivate() {
					return addr.IP
				}
			}
			return nil
		}(dev)
		// if no valid IPv4 address is found, skip this interface.
		if ipv4 == nil {
			continue
		}

		// get net device information from net std lib
		netDev, err := net.InterfaceByName(dev.Name)
		if err != nil {
			continue
		}
		// ensure required flags are set (RUNNING/LOWER_UP, BROADCAST)
		if netDev.Flags&net.FlagRunning == 0 || netDev.Flags&net.FlagBroadcast == 0 {
			continue
		}

		interfaces = append(interfaces, IPRInterface{
			Index:        netDev.Index,
			Name:         dev.Name,
			FriendlyName: dev.Name,
			Description:  dev.Description,
			IPv4:         ipv4,
			HardwareAddr: netDev.HardwareAddr,
			Flags:        netDev.Flags,
			Vlan:         VlanConfig{},
		})
	}
	if len(interfaces) == 0 {
		return nil, errNoValidInterfaces
	}
	return interfaces, nil
}
