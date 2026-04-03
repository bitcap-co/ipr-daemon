//go:build freebsd || linux || darwin

package iprd

import (
	"net"

	"github.com/google/gopacket/pcap"
)

func getInterfaces() ([]IPRInterface, error) {
	interfaces := make([]IPRInterface, 0)
	availInterfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	for _, iface := range availInterfaces {
		// loop thru interfaces for valid ipv4
		ipv4 := func(i pcap.Interface) net.IP {
			for _, addr := range i.Addresses {
				if addr.IP != nil && addr.IP.To4() != nil && addr.IP.IsPrivate() {
					return addr.IP
				}
			}
			return nil
		}(iface)
		if ipv4 == nil {
			continue
		}

		// get friendly name for std net
		friendlyName := iface.Name

		// get info from std net using friendlyName
		netInterface, err := net.InterfaceByName(friendlyName)
		if err != nil {
			continue
		}
		// ensure flags RUNNING/LOWER_UP, BROADCAST are set
		if netInterface.Flags&net.FlagRunning == 0 || netInterface.Flags&net.FlagBroadcast == 0 {
			continue
		}

		interfaces = append(interfaces, IPRInterface{
			Index:        netInterface.Index,
			Name:         iface.Name,
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
