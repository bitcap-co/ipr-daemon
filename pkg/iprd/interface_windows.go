//go:build windows

package iprd

import (
	"fmt"
	"net"
	"strings"
	"unsafe"

	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/sys/windows"
)

// getWin32FriendlyName resolves a pcap interface name of the form "\Device\NPF_{GUID}" using GetAdaptersAddresses.
// Returns the friendly name of the adapter matching the given GUID or an error if no match is found.
// https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
func getWin32FriendlyName(name string) (string, error) {
	// extract GUID from pcap device name
	guid := strings.TrimPrefix(name, "\\Device\\NPF_")

	// we first call windows.GetAdapterAddresses to determine the required buffer size
	var l uint32
	err := windows.GetAdaptersAddresses(windows.AF_INET, 0, 0, nil, &l)
	if err != windows.ERROR_BUFFER_OVERFLOW {
		return "", fmt.Errorf("getadaptersaddresses: %s\n", err)
	}

	// now that we have the buffer size l, make our final call to get all adapter addresses
	buf := make([]byte, l)
	addrs := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	if err = windows.GetAdaptersAddresses(windows.AF_INET, 0, 0, addrs, &l); err != nil {
		return "", fmt.Errorf("getadaptersaddresses: %s\n", err)
	}

	// loop through our addrs and return the FriendlyName of adapter a matching our extracted GUID
	for a := addrs; a != nil; a = a.Next {
		adapterName := windows.BytePtrToString(a.AdapterName)
		if strings.EqualFold(adapterName, guid) {
			return windows.UTF16PtrToString(a.FriendlyName), nil
		}
	}
	return "", fmt.Errorf("failed to get friendly name for %s", name)
}

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
		// pcap.FindAllDevs() returns the full kernel device path on windows (e.g. "\\Device\\NPF_{GUID}")
		// which std net requires the friendly name to resolve the interface.
		friendlyName, err := getWin32FriendlyName(dev.Name)
		if err != nil {
			continue
		}
		// get net device information from net std lib
		netDev, err := net.InterfaceByName(friendlyName)
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
			FriendlyName: friendlyName,
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
