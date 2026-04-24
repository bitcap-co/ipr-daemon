package iprd_test

import (
	"fmt"
	"net"
	"runtime"
	"testing"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	"github.com/google/gopacket/pcap"
)

func makeIPRInterface(name, description, ipAddr, macAddr string, flags net.Flags) (*iprd.IPRInterface, error) {
	if name == "" {
		return nil, fmt.Errorf("invalid name")
	}
	hwAddr, err := net.ParseMAC(macAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MAC")
	}
	ip := net.ParseIP(ipAddr)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("invalid ipv4 IP")
	}
	return &iprd.IPRInterface{
		Index:        0,
		Name:         name,
		Description:  description,
		IPv4:         ip,
		HardwareAddr: hwAddr,
		Flags:        flags,
	}, nil
}

func TestInterfaceIsLAN(t *testing.T) {
	cases := []struct {
		Name      string
		IfaceDesc string
		Want      bool
	}{
		{"iface description to 'lan'", "lan", true},
		{"iface description to 'LAN'", "LAN", true},
		{"iface description to 'Vlan'", "Vlan", false},
		{"iface description to 'WAN'", "WAN", false},
		{"iface description to 'LAN1'", "LAN1", true},
		{"iface description to ''", "", false},
	}

	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			iface, _ := makeIPRInterface("eth0", test.IfaceDesc, "192.168.1.1", "aa:bb:cc:dd:ee:ff", 0)
			got := iface.IsLAN()
			if got != test.Want {
				t.Errorf("got %t, want %t", got, test.Want)
			}
		})
	}
}

type mockInterface struct {
	Name        string
	Description string
	Flags       net.Flags
	Addresses   []pcap.InterfaceAddress
}

var testInterfaces = []mockInterface{
	{Name: "eth0", Description: "LAN", Flags: net.FlagRunning | net.FlagUp | net.FlagBroadcast | net.FlagMulticast, Addresses: []pcap.InterfaceAddress{{IP: net.ParseIP("192.168.5.1"), Netmask: nil, Broadaddr: nil, P2P: nil}}},
	{Name: "re0", Description: "WAN", Flags: net.FlagRunning | net.FlagUp | net.FlagBroadcast, Addresses: []pcap.InterfaceAddress{{IP: net.ParseIP("176.28.126.10"), Netmask: nil, Broadaddr: nil, P2P: nil}}},
	{Name: "lo", Description: "", Flags: net.FlagRunning | net.FlagUp | net.FlagLoopback, Addresses: []pcap.InterfaceAddress{{IP: net.ParseIP("127.0.0.1"), Netmask: nil, Broadaddr: nil, P2P: nil}}},
}

func TestGetInterfaces(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unsupported test.")
	}
	var ifaces = make([]iprd.IPRInterface, 0)
	for n, iface := range testInterfaces {
		ipv4 := func(i mockInterface) net.IP {
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

		if iface.Flags&net.FlagRunning == 0 || iface.Flags&net.FlagBroadcast == 0 {
			continue
		}

		ifaces = append(ifaces, iprd.IPRInterface{
			Index:        n,
			Name:         iface.Name,
			Description:  iface.Description,
			FriendlyName: iface.Name,
			IPv4:         ipv4,
			HardwareAddr: nil,
			Flags:        iface.Flags,
		})
	}
	t.Logf("got %d valid interfaces: %+v", len(ifaces), ifaces)
	want := 1
	got := len(ifaces)
	if got != want {
		t.Fatalf("got %d interface(s), want %d", got, want)
	}
}
