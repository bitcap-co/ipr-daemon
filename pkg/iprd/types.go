package iprd

import (
	"bytes"
	"container/list"
	"fmt"
	"regexp"
	"time"

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

type Record struct {
	items    map[string]RecordEntry
	elements map[string]*list.Element
	order    *list.List
	size     int
}

// RecordEntry represents an entry in Record
type RecordEntry struct {
	SrcIP     string
	SrcMAC    string
	MinerType MinerTypeHint
	CreatedAt int64
	UpdatedAt int64
}

// NewRecord returns a new ordered map of set size of RecordEntry.
func NewRecord(size int) *Record {
	return &Record{
		items:    make(map[string]RecordEntry),
		elements: make(map[string]*list.Element),
		order:    list.New(),
		size:     size,
	}
}

// Add creates/updates a RecordEntry in Record. If size is already reached, oldest entry is popped. FIFO order
func (r *Record) Add(key string, record RecordEntry) {
	if element, ok := r.elements[key]; ok {
		r.order.MoveToBack(element)
		element.Value = key
		record.UpdatedAt = time.Now().UnixMilli()
		r.items[key] = record
		return
	}

	if r.order.Len() > r.size {
		oldest := r.order.Front()
		if oldest != nil {
			delete(r.elements, oldest.Value.(string))
			delete(r.items, oldest.Value.(string))
			r.order.Remove(oldest)
		}
	}

	el := r.order.PushBack(key)
	r.elements[key] = el
	record.UpdatedAt = time.Now().UnixMilli()
	r.items[key] = record
}

// Get returns RecordEntry of key.
func (r *Record) Get(key string) *RecordEntry {
	if ent, ok := r.items[key]; ok {
		return &ent
	}
	return nil
}

// Contains returns bool for if key is present in Record.
func (r *Record) Contains(key string) bool {
	_, ok := r.items[key]
	return ok
}

// Length returns the length of Record.
func (r *Record) Length() int {
	return r.order.Len()
}

func (r *Record) display() {
	for e := r.order.Front(); e != nil; e = e.Next() {
		key := e.Value.(string)
		fmt.Printf("%s: %+v, ", key, r.items[key])
	}
	fmt.Printf("record len: %d", r.Length())
}

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
