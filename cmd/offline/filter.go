package main

import (
	"fmt"
	"strings"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

type filterConfig struct {
	InterfaceName string
	IPAddress     string
	MACAddress    string
	UDPPort       int
	Limit         int
}

func (fc *filterConfig) Validate() error {
	if fc.IPAddress != "" {
		ip := iprd.ParseIPAddress(fc.IPAddress)
		if ip == "" {
			return fmt.Errorf("invalid IP: %s", fc.IPAddress)
		}
		fc.IPAddress = ip
	}
	if fc.MACAddress != "" {
		mac := iprd.ParseMACAddress(fc.MACAddress)
		if mac == "" {
			return fmt.Errorf("invalid MAC: %s", fc.MACAddress)
		}
		fc.MACAddress = mac
	}
	if fc.UDPPort != 0 {
		if fc.UDPPort < 1 || fc.UDPPort > 65535 {
			return fmt.Errorf("invalid port: %d", fc.UDPPort)
		}
	}
	return nil
}

func (fc filterConfig) String() string {
	var sb strings.Builder
	if fc.InterfaceName != "" {
		fmt.Fprintf(&sb, "Interface=%s", fc.InterfaceName)
	}
	if fc.IPAddress != "" {
		if sb.Len() > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, "IP=%s", fc.IPAddress)
	}
	if fc.MACAddress != "" {
		if sb.Len() > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, "MAC=%s", fc.MACAddress)
	}
	if fc.UDPPort != 0 {
		if sb.Len() > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, "Port=%d", fc.UDPPort)
	}
	if fc.Limit != 0 {
		if sb.Len() > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, "Limit=%d", fc.Limit)
	}
	if sb.Len() == 0 {
		sb.WriteString("None")
	}
	return sb.String()
}

// filterPacket returns true if the packet matches the filter criteria
// If a packet cannot be parsed into an IPReportPacket (report is nil), only interface filtering is applied
func filterPacket(packet iprd.OfflinePacketResult, filter filterConfig) bool {
	if filter.InterfaceName != "" && packet.InterfaceName != filter.InterfaceName {
		return false
	}
	if packet.Report != nil {
		if filter.UDPPort != 0 && packet.Report.DstPort != filter.UDPPort {
			return false
		}
		if filter.IPAddress != "" && packet.Report.SrcIP != filter.IPAddress {
			return false
		}
		if filter.MACAddress != "" && packet.Report.SrcMAC != filter.MACAddress {
			return false
		}
	}
	return true
}
