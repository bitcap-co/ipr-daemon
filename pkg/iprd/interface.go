package iprd

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"unsafe"

	"github.com/google/gopacket/pcap"
	"golang.org/x/sys/windows"
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
	match := lanRegex.MatchString(i.Description)
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

// getWin32FriendlyName resolves the FriendlyName for a pcap
// interface name of the form "\Device\NPF_{GUID}" using GetAdaptersAddresses.
// https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
func getWin32FriendlyName(name string) (string, error) {
	// Extract the GUID portion after "\Device\NPF_"
	guid := strings.TrimPrefix(name, "\\Device\\NPF_")

	var size uint32
	// First call to determine the required buffer size.
	err := windows.GetAdaptersAddresses(windows.AF_INET, 0, 0, nil, &size)
	if err != windows.ERROR_BUFFER_OVERFLOW {
		return "", fmt.Errorf("getadaptersaddresses: %s\n", err)
	}

	buf := make([]byte, size)
	addrs := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	if err = windows.GetAdaptersAddresses(windows.AF_INET, 0, 0, addrs, &size); err != nil {
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

	var ipv4 net.IP
	var friendlyName string
	for _, iface := range availInterfaces {
		friendlyName = iface.Name
		ipv4 = getIPv4AddrFromInterface(iface)
		if ipv4 == nil {
			continue
		}

		// try and get freindly name of win32 interfaces for net
		if strings.HasPrefix(iface.Name, "\\Device\\NPF_") {
			friendlyName, err = getWin32FriendlyName(iface.Name)
			if err != nil {
				continue
			}
		}

		// get info from std net
		netInterface, err := net.InterfaceByName(friendlyName)
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
			FriendlyName: friendlyName,
			Description:  iface.Description,
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
		if name == iface.Name || name == iface.FriendlyName {
			return &iface, nil
		}
	}
	return nil, errInterfaceNotFound
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
