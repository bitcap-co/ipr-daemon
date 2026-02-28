package iprd

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/goccy/go-json"
)

type MinerTypeHint string

const (
	UnknownType   MinerTypeHint = "unknown"
	BitmainCommon MinerTypeHint = "bitmain-common"
	Iceriver      MinerTypeHint = "iceriver"
	Whatsminer    MinerTypeHint = "whatsminer"
	Goldshell     MinerTypeHint = "goldshell"
	Sealminer     MinerTypeHint = "sealminer"
	Elphapex      MinerTypeHint = "elphapex"
)

var (
	ValidIP     = regexp.MustCompile(`\b(?:(?:2(?:[0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9])\.){3}(?:(?:2([0-4][0-9]|5[0-5])|[0-1]?[0-9]?[0-9]))\b`)
	ValidMAC    = regexp.MustCompile(`([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})`)
	MsgPatterns = map[string]*regexp.Regexp{
		"Common": regexp.MustCompile(fmt.Sprintf(`^%s,%s`, ValidIP, ValidMAC)),
		"IR":     regexp.MustCompile(fmt.Sprintf(`^addr:%s`, ValidIP)),
		"BT":     regexp.MustCompile(fmt.Sprintf(`^IP:%sMAC:%s`, ValidIP, ValidMAC)),
		"DG":     regexp.MustCompile(`^DG_IPREPORT_ONLY`),
	}
)

// IPReportGoldshell represents the JSON payload of IP report packet for Goldshell miners.
type IPReportGoldshell struct {
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

type SealMinerBoard struct {
	Serial     string `json:"SN"`
	BinVersion int    `json:"BinVer"`
	BinNumber  int    `json:"BinNum"`
}

type SealMinerInfo struct {
	MACAddress     string           `json:"MAC"`
	Type           string           `json:"Type"`
	Firmware       string           `json:"Firmware"`
	CtrlBoard      string           `json:"CtrlBoardVersion"`
	InterfaceCount int              `json:"NetInterfaceCnt"`
	Upgrade        int              `json:"UpgradeStatus"`
	CtrlBoardSN    string           `json:"MainBoardSN"`
	RatedPower     int              `json:"RatedInputPower"`
	PowerLimit     int              `json:"InputPowerLimit"`
	Boards         []SealMinerBoard `json:"BoardSNArray"`
}

type SealMinerInterface struct {
	Interface  string `json:"Interface"`
	Active     bool   `json:"Active"`
	DHCP       bool   `json:"DHCP"`
	IPAddress  string `json:"IPV4"`
	Netmask    string `json:"Netmask"`
	Gateway    string `json:"Gateway"`
	DNS1       string `json:"DNS1"`
	DNS2       string `json:"DNS2"`
	AutoReboot bool   `json:"AutoReboot"`
}

// IPReportSealminer represents the JSON payload of IP Report packet for SealMiners
type IPReportSealminer struct {
	Info       SealMinerInfo
	Interfaces []SealMinerInterface
}

func (i *IPReportSealminer) getMinerInfo(data []interface{}) (*SealMinerInfo, error) {
	var sminfo *SealMinerInfo
	info_data, err := json.Marshal(data[1])
	if err != nil {
		return nil, fmt.Errorf("failed to marshal miner info: %W", err)
	}
	if err := json.Unmarshal(info_data, &sminfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal miner info: %W", err)
	}
	return sminfo, nil
}

func (i *IPReportSealminer) getInterfaces(data []interface{}) (*[]SealMinerInterface, error) {
	var sminterfaces *[]SealMinerInterface
	interface_data, err := json.Marshal(data[2:4])
	if err != nil {
		return nil, fmt.Errorf("failed to marshal interfaces: %W", err)
	}
	if err := json.Unmarshal(interface_data, &sminterfaces); err != nil {
		return nil, fmt.Errorf("failed to unmarshal interfaces: %W", err)
	}
	return sminterfaces, nil
}

func (i *IPReportSealminer) UnmarshalJSON(data []byte) error {
	// remove null bytes
	data = bytes.ReplaceAll(data, []byte(`\x00`), []byte{})
	// // fix commas
	data = bytes.ReplaceAll(data, []byte("}{"), []byte("}, {"))
	// // fix booleans
	data = bytes.ReplaceAll(data, []byte("TRUE"), []byte("true"))
	data = bytes.ReplaceAll(data, []byte("FALSE"), []byte("false"))

	var temp []interface{}
	if err := json.Unmarshal(data, &temp); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %W", err)
	}

	if len(temp) != 7 {
		return fmt.Errorf("expected 7 elements in array, got %d", len(temp))
	}

	sminfo, err := i.getMinerInfo(temp)
	if err != nil {
		return err
	}
	i.Info = *sminfo

	sminterfaces, err := i.getInterfaces(temp)
	if err != nil {
		return err
	}
	i.Interfaces = *sminterfaces

	return nil
}
