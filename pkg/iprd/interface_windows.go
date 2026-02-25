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
	// extract GUID from name
	guid := strings.TrimPrefix(name, "\\Device\\NPF_")

	var l uint32
	// first call to determine the required buffer size
	err := windows.GetAdaptersAddresses(windows.AF_INET, 0, 0, nil, &l)
	if err != windows.ERROR_BUFFER_OVERFLOW {
		return "", fmt.Errorf("getadaptersaddresses: %s\n", err)
	}

	buf := make([]byte, l)
	addrs := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	if err = windows.GetAdaptersAddresses(windows.AF_INET, 0, 0, addrs, &l); err != nil {
		return "", fmt.Errorf("getadaptersaddresses: %s\n", err)
	}

	for a := addrs; a != nil; a = a.Next {
		adapterName := windows.BytePtrToString(a.AdapterName)
		if strings.EqualFold(adapterName, guid) {
			return windows.UTF16PtrToString(a.FriendlyName), nil
		}
	}
	return "", fmt.Errorf("failed to get freindly name for %s", name)
}

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
		friendlyName, err := getWin32FriendlyName(iface.Name)
		if err != nil {
			continue
		}

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
