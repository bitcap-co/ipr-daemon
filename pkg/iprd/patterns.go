package iprd

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
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
	IBeLink     MinerTypeHint = "ibelink"
)

var (
	validIP  = regexp.MustCompile(`\b(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\.){3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))\b`)
	validMAC = regexp.MustCompile(`([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})`)
	// minerPorts is a map of UDP destination ports to MinerTypeHint.
	minerPorts = map[int]MinerTypeHint{
		14235: Antminer, // Known common port for other miner types as well (blackminer/hammer)
		11503: Iceriver,
		8888:  Whatsminer,
		1314:  Goldshell,
		18650: Sealminer,
		9999:  Elphapex,
		12345: Auradine,
		54321: IPollo,
		42069: HiveGPU, // Custom port for HiveOS
		6667:  IBeLink,
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

// IPReport provides access to structured IP report data.
type IPReport interface {
	// IPAddr returns the IP address of the miner.
	IPAddr() string
	// MacAddr returns the MAC address of the miner.
	MacAddr() string
	// SerialNum returns the serial number of the miner if available.
	SerialNum() string
	// Parse parses the raw IP report data into the IPReport object.
	Parse([]byte) error
}

var (
	_ IPReport = (*GoldshellIPReport)(nil)
	_ IPReport = (*AuradineIPReport)(nil)
	_ IPReport = (*SealminerIPReport)(nil)
	_ IPReport = (*IBeLinkIPReport)(nil)
)

type ipReportFactory func() IPReport

var reportFactories = map[MinerTypeHint]ipReportFactory{
	Goldshell: func() IPReport { return &GoldshellIPReport{} },
	IBeLink:   func() IPReport { return &IBeLinkIPReport{} },
	Sealminer: func() IPReport { return &SealminerIPReport{} },
	Auradine:  func() IPReport { return &AuradineIPReport{} },
}

// NewIPReportFromHint returns a new IPReport for the given MinerTypeHint, if known.
func NewIPReportFromHint(hint MinerTypeHint) (IPReport, bool) {
	factory, ok := reportFactories[hint]
	if !ok {
		return nil, false
	}
	return factory(), true
}

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

func (r *GoldshellIPReport) IPAddr() string {
	return r.IPAddress
}

func (r *GoldshellIPReport) MacAddr() string {
	return r.MACAddress
}

func (r *GoldshellIPReport) SerialNum() string {
	return r.Serial
}

func (r *GoldshellIPReport) Parse(data []byte) error {
	var report GoldshellIPReport
	if err := json.Unmarshal(data, &report); err != nil {
		return err
	}
	report.IPAddress = ParseIPAddress(report.IPAddress)
	if report.IPAddress == "" {
		return fmt.Errorf("invalid IP address")
	}
	report.MACAddress = ParseMACAddress(report.MACAddress)
	if report.MACAddress == "" {
		return fmt.Errorf("invalid MAC address")
	}

	*r = report
	return nil
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

func (r *AuradineIPReport) IPAddr() string {
	return r.IPAddress
}

func (r *AuradineIPReport) MacAddr() string {
	return r.MACAddress
}

func (r *AuradineIPReport) SerialNum() string {
	return r.SerialNo
}

func (r *AuradineIPReport) Parse(data []byte) error {
	var report AuradineIPReport
	if err := json.Unmarshal(data, &report); err != nil {
		return err
	}
	report.IPAddress = ParseIPAddress(report.IPAddress)
	if report.IPAddress == "" {
		return fmt.Errorf("invalid IP address")
	}
	report.MACAddress = ParseMACAddress(report.MACAddress)
	if report.MACAddress == "" {
		return fmt.Errorf("invalid MAC address")
	}
	*r = report
	return nil
}

type SealminerInfo struct {
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

type SealminerInterface struct {
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
// IPAddress & MACAddress are extracted from the report.
type SealminerIPReport struct {
	IPAddress  string
	MACAddress string
	Info       SealminerInfo
	Interfaces []SealminerInterface
}

func (r *SealminerIPReport) parseInfo(data any) (SealminerInfo, error) {
	var info SealminerInfo
	raw, err := json.Marshal(data)
	if err != nil {
		return SealminerInfo{}, fmt.Errorf("failed to marshal info: %w", err)
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		return SealminerInfo{}, fmt.Errorf("failed to unmarshal info: %w", err)
	}
	return info, nil
}

func (r *SealminerIPReport) parseInterfaces(data []any) ([]SealminerInterface, error) {
	var interfaces []SealminerInterface
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal interfaces: %w", err)
	}
	if err := json.Unmarshal(raw, &interfaces); err != nil {
		return nil, fmt.Errorf("failed to unmarshal interfaces: %w", err)
	}
	return interfaces, nil
}

func (r *SealminerIPReport) IPAddr() string {
	return r.IPAddress
}

func (r *SealminerIPReport) MacAddr() string {
	return r.MACAddress
}

func (r *SealminerIPReport) SerialNum() string {
	return ""
}

func (r *SealminerIPReport) Parse(data []byte) error {
	var report SealminerIPReport
	// Remove real NUL bytes from datagrams and escaped NULs from text fixtures.
	data = bytes.ReplaceAll(data, []byte{0x00}, nil)
	data = bytes.ReplaceAll(data, []byte(`\x00`), nil)
	// add commas between objects
	data = bytes.ReplaceAll(data, []byte("}{"), []byte("}, {"))
	// fix JSON booleans
	data = bytes.ReplaceAll(data, []byte("TRUE"), []byte("true"))
	data = bytes.ReplaceAll(data, []byte("FALSE"), []byte("false"))

	var t []any
	if err := json.Unmarshal(data, &t); err != nil {
		return fmt.Errorf("failed to unmarshal: %w", err)
	}
	if len(t) != 7 {
		return fmt.Errorf("invalid number of elements in array: got %d, want 7", len(t))
	}
	info, err := r.parseInfo(t[1])
	if err != nil {
		return err
	}
	report.Info = info
	report.MACAddress = ParseMACAddress(info.MACAddress)
	if report.MACAddress == "" {
		return fmt.Errorf("invalid MAC address")
	}
	interfacesEnd := 2 + info.NetInterfaceCnt
	if info.NetInterfaceCnt < 0 || interfacesEnd > len(t) {
		return fmt.Errorf("invalid number of interfaces")
	}
	interfaces, err := r.parseInterfaces(t[2:interfacesEnd])
	if err != nil {
		return err
	}
	report.Interfaces = interfaces
	// find active IPv4 address
	for _, iface := range report.Interfaces {
		if iface.Active {
			report.IPAddress = iface.IPV4
			break
		}
	}
	report.IPAddress = ParseIPAddress(report.IPAddress)
	if report.IPAddress == "" {
		return fmt.Errorf("invalid IP address")
	}
	*r = report
	return nil
}

var (
	iBeLinkPayloadMagic      = []byte{0x41, 0x5a, 0x5a, 0xf0, 0x01}
	iBeLinkHeaderSize    int = 8
	iBelinkAddressFields int = 4
)

type IBeLinkIPReport struct {
	IPAddress  string
	MACAddress string
	Datagram   []byte
}

func (r *IBeLinkIPReport) IPAddr() string {
	return r.IPAddress
}

func (r *IBeLinkIPReport) MacAddr() string {
	return r.MACAddress
}

func (r *IBeLinkIPReport) SerialNum() string {
	return ""
}

func (r *IBeLinkIPReport) Parse(data []byte) error {
	var report IBeLinkIPReport
	if len(data) < iBeLinkHeaderSize {
		return fmt.Errorf("datagram too short")
	}
	if !bytes.Equal(data[:5], iBeLinkPayloadMagic) {
		return fmt.Errorf("invalid magic")
	}
	var addressFields []string
	fields := bytes.Split(data[iBeLinkHeaderSize:], []byte{0x00})
	for _, field := range fields {
		if len(field) > 0 {
			addressFields = append(addressFields, string(field))
		}
	}
	if len(addressFields) < iBelinkAddressFields {
		return fmt.Errorf("invalid address fields")
	}
	report.IPAddress = ParseIPAddress(addressFields[0])
	if report.IPAddress == "" {
		return fmt.Errorf("invalid ip: %s", addressFields[0])
	}
	report.MACAddress = ParseMACAddress(addressFields[3])
	if report.MACAddress == "" {
		return fmt.Errorf("invalid mac: %s", addressFields[3])
	}
	report.Datagram = data
	*r = report
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
	addr, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil || !addr.Is4() {
		return ""
	}
	return addr.String()
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

	if _, err := net.ParseMAC(address); err != nil {
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
