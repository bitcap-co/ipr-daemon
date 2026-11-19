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

type freeBSDVlanReq struct {
	Parent [unix.IFNAMSIZ]byte
	Tag    uint16
	Proto  uint16
}

type freeBSDIfReq struct {
	Name [unix.IFNAMSIZ]byte
	Data unsafe.Pointer
	_    [ifreqDataSize - unsafe.Sizeof(uintptr(0))]byte
}

func getFreeBSDVlanConfig(ifname string) (VlanConfig, error) {
	if ifname == "" {
		return VlanConfig{}, fmt.Errorf("interface name empty")
	}
	if len(ifname) >= unix.IFNAMSIZ {
		return VlanConfig{}, fmt.Errorf("interface name too long")
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return VlanConfig{}, err
	}
	defer unix.Close(fd)

	var vlanReq freeBSDVlanReq
	var ifreq freeBSDIfReq
	copy(ifreq.Name[:], ifname)
	ifreq.Data = unsafe.Pointer(&vlanReq)

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFGENERIC),
		uintptr(unsafe.Pointer(&ifreq)),
	)
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

func GetInterfaces() ([]IPRInterface, error) {
	interfaces := make([]IPRInterface, 0)

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

		friendlyName := iface.Name
		netInterface, err := net.InterfaceByName(friendlyName)
		if err != nil {
			continue
		}
		if netInterface.Flags&net.FlagRunning == 0 || netInterface.Flags&net.FlagBroadcast == 0 {
			continue
		}

		// get VLAN config for this interface; this is best effort, ignore errors
		vlan, _ := getFreeBSDVlanConfig(friendlyName)

		interfaces = append(interfaces, IPRInterface{
			Index:        netInterface.Index,
			Name:         iface.Name,
			Description:  iface.Description,
			FriendlyName: friendlyName,
			IPv4:         ipv4,
			HardwareAddr: netInterface.HardwareAddr,
			Flags:        netInterface.Flags,
			Vlan:         vlan,
		})
	}
	if len(interfaces) == 0 {
		return nil, errNoValidInterfaces
	}
	return interfaces, nil
}
