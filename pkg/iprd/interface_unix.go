//go:build freebsd || linux || darwin

package iprd

import (
	"net"

	"github.com/google/gopacket/pcap"
)

// getInterfaces returns all available IPRInterfaces that we can listen on.
// Returns error if no valid interfaces found.
func getInterfaces() ([]IPRInterface, error) {
	interfaces := make([]IPRInterface, 0)
	// find all available system interfaces using libpcap
	availInterfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	for _, iface := range availInterfaces {
		// anonymous function that loops through all attached addresses
		// looking for valid local/private IPv4
		ipv4 := func(i pcap.Interface) net.IP {
			for _, addr := range i.Addresses {
				if addr.IP != nil && addr.IP.To4() != nil && addr.IP.IsPrivate() {
					return addr.IP
				}
			}
			return nil
		}(iface)
		// if we fail to find an valid IPv4 addresses, skip.
		if ipv4 == nil {
			continue
		}

		// get network interface information from std net
		friendlyName := iface.Name
		netInterface, err := net.InterfaceByName(friendlyName)
		if err != nil {
			continue
		}
		// ensure RUNNING/LOWER_UP and BROADCAST flags are set
		if netInterface.Flags&net.FlagRunning == 0 || netInterface.Flags&net.FlagBroadcast == 0 {
			continue
		}

		interfaces = append(interfaces, IPRInterface{
			Index:        netInterface.Index,
			Name:         iface.Name,
			Description:  iface.Description,
			FriendlyName: friendlyName,
			IPv4:         ipv4,
			HardwareAddr: netInterface.HardwareAddr,
			Flags:        netInterface.Flags,
		})
	}
	if len(interfaces) == 0 {
		return nil, errNoValidInterfaces
	}
	return interfaces, nil
}
