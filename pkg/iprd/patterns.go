package iprd

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/goccy/go-json"
)

type MinerTypeHint string

const (
	UnknownType MinerTypeHint = "unknown"
	Antminer    MinerTypeHint = "antminer"
	Iceriver    MinerTypeHint = "iceriver"
	Whatsminer  MinerTypeHint = "whatsminer"
	Goldshell   MinerTypeHint = "goldshell"
	Sealminer   MinerTypeHint = "sealminer"
	Elphapex    MinerTypeHint = "elphapex"
	Auradine    MinerTypeHint = "auradine"
	IPollo      MinerTypeHint = "ipollo"
	HiveGPU     MinerTypeHint = "hivegpu"
)

var (
	validIP  = regexp.MustCompile(`\b(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\.){3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))\b`)
	validMAC = regexp.MustCompile(`([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})`)
	// minerPorts is a map of UDP destination ports to MinerTypeHint.
	minerPorts = map[int]MinerTypeHint{
		14235: Antminer, // This is a known common port for multiple miner types (i.e. Volcminer, Hammer)
		11503: Iceriver,
		8888:  Whatsminer,
		1314:  Goldshell,
		18650: Sealminer,
		9999:  Elphapex,
		12345: Auradine,
		54321: IPollo,
		42069: HiveGPU,
	}
	// msgPatterns is a map of MinerTypeHint to regex UDP payload patterns.
	msgPatterns = map[MinerTypeHint]*regexp.Regexp{
		Antminer:   regexp.MustCompile(fmt.Sprintf(`^%s,%s`, validIP, validMAC)),
		Iceriver:   regexp.MustCompile(fmt.Sprintf(`^addr:%s`, validIP)),
		Whatsminer: regexp.MustCompile(fmt.Sprintf(`^IP:%sMAC:%s`, validIP, validMAC)),
		Elphapex:   regexp.MustCompile(`^DG_IPREPORT_ONLY`),
		IPollo:     regexp.MustCompile(fmt.Sprintf(`^IP Addr:\[%s\].*?MAC Addr:\[%s\]`, validIP, validMAC)),
		HiveGPU:    regexp.MustCompile(fmt.Sprintf(`^HiveOS %s`, validIP)),
	}
)

// GoldshellIPReport represents the IP report JSON payload from Goldshell miners.
type GoldshellIPReport struct {
	Version     string          `json:"version"`
	IPAddress   string          `json:"ip"`
	DHCP        string          `json:"dhcp"`
	Model       string          `json:"model"`
	CtrlBoardSN string          `json:"ctrlsn"`
	MACAddress  string          `json:"mac"`
	Netmask     string          `json:"mask"`
	Gateway     string          `json:"gateway"`
	BoardSNs    json.RawMessage `json:"cpbsn"`
	DNS         json.RawMessage `json:"dns"`
	Serial      string          `json:"boxsn"`
	Time        string          `json:"time"`
	LEDStatus   bool            `json:"ledstatus"`
}

// AuradineIPReport represents the IP report JSON payload from Auradine miners.
type AuradineIPReport struct {
	Command      string `json:"command"`
	SerialNo     string `json:"SerialNo"`
	IPAddress    string `json:"ip"`
	MACAddress   string `json:"mac"`
	Model        string `json:"model"`
	Version      string `json:"version"`
	Hostname     string `json:"hostname"`
	InternalType string `json:"InternalType"`
}

type sealminerInfo struct {
	MACAddress       string          `json:"MAC"`
	Type             string          `json:"Type"`
	Firmware         string          `json:"Firmware"`
	CtrlBoardVersion string          `json:"CtrlBoardVersion"`
	NetInterfaceCnt  int             `json:"NetInterfaceCnt"`
	UpgradeStatus    int             `json:"UpgradeStatus"`
	MainBoardSN      string          `json:"MainBoardSN"`
	RatedInputPower  int             `json:"RatedInputPower"`
	InputPowerLimit  int             `json:"InputPowerLimit"`
	BoardSNArray     json.RawMessage `json:"BoardSNArray"`
}

type sealminerInterface struct {
	Interface  string `json:"Interface"`
	Active     bool   `json:"Active"`
	DHCP       bool   `json:"DHCP"`
	IPV4       string `json:"IPV4"`
	Netmask    string `json:"Netmask"`
	Gateway    string `json:"Gateway"`
	DNS1       string `json:"DNS1"`
	DNS2       string `json:"DNS2"`
	AutoReboot bool   `json:"AutoReboot"`
}

// SealminerIPReport represents the IP report JSON payload from Sealminer miners.
type SealminerIPReport struct {
	Info       sealminerInfo
	Interfaces []sealminerInterface
}

func (r *SealminerIPReport) parseInfo(data []any) (*sealminerInfo, error) {
	var info *sealminerInfo
	raw, err := json.Marshal(data[1])
	if err != nil {
		return nil, fmt.Errorf("failed to marshal info: %W", err)
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal info: %W", err)
	}
	return info, nil
}

func (r *SealminerIPReport) parseInterfaces(data []any) (*[]sealminerInterface, error) {
	var interfaces *[]sealminerInterface
	raw, err := json.Marshal(data[2:4])
	if err != nil {
		return nil, fmt.Errorf("failed to marshal interfaces: %W", err)
	}
	if err := json.Unmarshal(raw, &interfaces); err != nil {
		return nil, fmt.Errorf("failed to unmarshal interfaces: %W", err)
	}
	return interfaces, nil
}

func (r *SealminerIPReport) UnmarshalJSON(data []byte) error {
	// remove null bytes
	data = bytes.ReplaceAll(data, []byte(`\x00`), []byte{})
	// add commas between objects
	data = bytes.ReplaceAll(data, []byte("}{"), []byte("}, {"))
	// fix JSON booleans
	data = bytes.ReplaceAll(data, []byte("TRUE"), []byte("true"))
	data = bytes.ReplaceAll(data, []byte("FALSE"), []byte("false"))

	var t []any
	if err := json.Unmarshal(data, &t); err != nil {
		return fmt.Errorf("failed to unmarshal: %W", err)
	}
	if len(t) != 7 {
		return fmt.Errorf("invalid number of elements in array: got %d, want 7", len(t))
	}
	info, err := r.parseInfo(t)
	if err != nil {
		return err
	}
	r.Info = *info
	interfaces, err := r.parseInterfaces(t)
	if err != nil {
		return err
	}
	r.Interfaces = *interfaces
	return nil
}

// GetMsgPatternFromHint returns the UDP payload regex pattern for the given MinerTypeHint, if known.
func GetMsgPatternFromHint(hint MinerTypeHint) (*regexp.Regexp, bool) {
	pattern, ok := msgPatterns[hint]
	return pattern, ok
}

// GetMinerHintFromPort returns the MinerTypeHint for the given port, if known.
func GetMinerHintFromPort(port int) (MinerTypeHint, bool) {
	hint, ok := minerPorts[port]
	return hint, ok
}

// GetKnownMinerPorts returns a list of known miner UDP destination ports.
func GetKnownMinerPorts() []int {
	var ports []int
	for p := range minerPorts {
		ports = append(ports, p)
	}
	return ports
}

// ParseIPAddress parses address and returns a normalized IP address.
func ParseIPAddress(address string) string {
	if address == "" {
		return ""
	}
	address = strings.TrimSpace(address)
	if !validIP.MatchString(address) {
		return ""
	}
	return address
}

// ParseMACAddress parses address and returns a normalized MAC address.
func ParseMACAddress(address string) string {
	if address == "" {
		return ""
	}
	address = strings.ToLower(address)
	switch len(address) {
	case 17:
		address = strings.ReplaceAll(address, "-", ":")
	case 12:
		var newAddress strings.Builder
		newAddress.Grow(17)
		for i := 0; i < 12; i += 2 {
			newAddress.WriteString(address[i : i+2])
			if i < 10 {
				newAddress.WriteString(":")
			}
		}
		address = newAddress.String()
	default:
		return ""
	}

	if !validMAC.MatchString(address) {
		return ""
	}

	return address
}

// ParseBPFNetwork returns the parsed BPF network, or an empty string if invalid.
// network is a BPF IPv4 network number that can be written as a dotted quad (192.168.1.0), dotted triple (192.168.1),
// dotted pair (192.168) or single number (10).
func ParseBPFNetwork(network string) string {
	if network == "" {
		return ""
	}
	network = strings.TrimSpace(network)
	if len(network) > 15 {
		return ""
	}
	octets := strings.Split(network, ".")
	if len(octets) > 4 {
		return ""
	}
	for _, octet := range octets {
		if octet == "" {
			return ""
		}
		if o, err := strconv.Atoi(octet); err != nil || o < 0 || o > 255 {
			return ""
		}
	}

	return network
}
