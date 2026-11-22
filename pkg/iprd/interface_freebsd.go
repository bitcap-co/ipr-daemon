//go:build freebsd

package iprd

import (
	"fmt"
	"net"
	"runtime"
	"unsafe"

	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/sys/unix"
)

const ifreqDataSize = 16

/*
struct ifreq {
	char	ifr_name[IFNAMSIZ];
	union {
		...
		caddr_t	ifru_data;
		...
	} ifr_ifru;
*/
// freeBSDIfReq represents the FreeBSD ifreq kernel ABI structure.
// ifeq is 32 bytes, and its data union is 16 bytes.
// Explicit padding is used to ensure it is aligned for 32-bit and 64-bit architectures.
type freeBSDIfReq struct {
	Name [unix.IFNAMSIZ]byte
	Data unsafe.Pointer
	_    [ifreqDataSize - unsafe.Sizeof(uintptr(0))]byte
}

/*
	struct	vlanreq {
		char	vlr_parent[IFNAMSIZ];
		u_short	vlr_tag;
		u_short	vlr_proto;
	};

freeBSDVlanReq represents the FreeBSD vlanreq kernel ABI structure.
*/
type freeBSDVlanReq struct {
	Parent [unix.IFNAMSIZ]byte
	Tag    uint16
	Proto  uint16
}

func getFreeBSDVlanConfig(ifname string) (VlanConfig, error) {
	if ifname == "" {
		return VlanConfig{}, fmt.Errorf("interface name empty")
	}
	if len(ifname) >= unix.IFNAMSIZ {
		return VlanConfig{}, fmt.Errorf("interface name too long")
	}

	// Open AF_INET socket for ioctl calls
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return VlanConfig{}, err
	}
	defer unix.Close(fd)

	var vlanReq freeBSDVlanReq
	var ifreq freeBSDIfReq
	// Create ifreq structure
	copy(ifreq.Name[:], ifname)
	ifreq.Data = unsafe.Pointer(&vlanReq)

	// Get VLAN configuration using SIOCGIFGENERIC (underlying value for SIOCGETVLAN)
	// via ioctl syscall
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFGENERIC),
		uintptr(unsafe.Pointer(&ifreq)),
	)
	// Keep references to vlanReq and ifreq alive until syscall returns
	runtime.KeepAlive(&vlanReq)
	runtime.KeepAlive(&ifreq)

	if errno != 0 {
		return VlanConfig{}, errno
	}

	return VlanConfig{
		Tag:    vlanReq.Tag,
		Parent: unix.ByteSliceToString(vlanReq.Parent[:]),
	}, nil
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

		// get net device information from net std lib
		netDev, err := net.InterfaceByName(dev.Name)
		if err != nil {
			continue
		}
		// ensure required flags are set (RUNNING/LOWER_UP, BROADCAST)
		if netDev.Flags&net.FlagRunning == 0 || netDev.Flags&net.FlagBroadcast == 0 {
			continue
		}

		// get vlan configuration; this is best effort, ignore errors
		vlan, _ := getFreeBSDVlanConfig(dev.Name)

		interfaces = append(interfaces, IPRInterface{
			Index:        netDev.Index,
			Name:         dev.Name,
			FriendlyName: dev.Name,
			Description:  dev.Description,
			IPv4:         ipv4,
			HardwareAddr: netDev.HardwareAddr,
			Flags:        netDev.Flags,
			Vlan:         vlan,
		})
	}
	if len(interfaces) == 0 {
		return nil, errNoValidInterfaces
	}
	return interfaces, nil
}
