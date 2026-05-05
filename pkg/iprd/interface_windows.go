package iprd

import (
	"fmt"
	"net"
	"strings"
	"unsafe"

	"github.com/google/gopacket/pcap"
	"golang.org/x/sys/windows"
)

// getWin32FriendlyName resolves the FriendlyName for a pcap
// interface name of the form "\Device\NPF_{GUID}" using GetAdaptersAddresses.
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

// GetInterfaces returns all available IPRInterfaces that can be listened on.
// Returns error if no valid interfaces found.
func GetInterfaces() ([]IPRInterface, error) {
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
		friendlyName, err := getWin32FriendlyName(iface.Name)
		if err != nil {
			continue
		}
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
