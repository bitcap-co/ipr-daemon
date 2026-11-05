package iprd_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	"github.com/goccy/go-json"
)

func TestSealminerParse(t *testing.T) {
	var data json.RawMessage = []byte(`{"Type":3,"Status":0,"Substatus":[]}\x00\x00\x00\x00{"MAC":"50:d4:48:4b:08:1b","Type":"A2","Firmware":"2025040301","CtrlBoardVersion":"taurus_air_v1.1","Protocol":537929985,"NetInterfaceCnt":3,"UpgradeStatus":0,"MainBoardSN":"S127200251200340","RatedInputPower":4300,"InputPowerLimit":3400,"BoardSnArray":[{"SN":"S124600251201353","BinVer":1,"BinNum":29},{"SN":"S124600251200944","BinVer":1,"BinNum":29},{"SN":"S124600251200910","BinVer":1,"BinNum":29}]}\x00\x00{"Interface":"eth0","Active":false,"DHCP":true,"IPV4":"192.168.1.2","Netmask":"255.255.255.0","Gateway":"192.168.1.1","DNS1":"114.114.114.114","DNS2":"8.8.8.8","AutoReboot":false}\x00{"Interface":"eth1","Active":true,"DHCP":true,"IPV4":"172.16.50.29","Netmask":"255.255.255.0","Gateway":"172.16.50.1","DNS1":"172.16.50.1","DNS2":"","AutoReboot":false}\x00\x00\x00\x00{"Interface":"bridge","Active":false,"DHCP":true,"IPV4":"192.168.1.4","Netmask":"255.255.255.0","Gateway":"192.168.1.1","DNS1":"114.114.114.114","DNS2":"8.8.8.8","AutoReboot":false}\x00\x00\x00{"Pools":[{"URL":"sha256asicboost.auto.nicehash.com:9200","Worker":"NHbVmEq1dwpK8RQPdGGPQ4hDoTHVdkidwLcf.seal01","Password":"x"},{"URL":"sha256asicboost.auto.nicehash.com:9200","Worker":"NHbVmEq1dwpK8RQPdGGPQ4hDoTHVdkidwLcf","Password":"x"}],"IPSuffixEnable":false,"SocketProxyEnabale":false,"SocketProxy":"","AutoReboot":false}\x00\x00\x00\x00{"Room":0,"Cabinet":0,"Floor":0,"Pos":0}\x00\x00\x00\x00`)
	data = bytes.ReplaceAll(data, []byte(`\x00`), []byte{0x00})
	data = slices.Concat([]byte("["), data, []byte("]"))
	ipreport, ok := iprd.NewIPReportFromHint(iprd.Sealminer)
	if !ok {
		t.Fatalf("no IP report for miner hint %s", iprd.Sealminer)
	}
	err := ipreport.Parse(data)
	if err != nil {
		t.Fatalf("got error %v, want no error", err)
	}
	got := ipreport.MacAddr()
	want := "50:d4:48:4b:08:1b"
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestNewIPReportFromHintReturnsIndependentReports(t *testing.T) {
	first, ok := iprd.NewIPReportFromHint(iprd.Goldshell)
	if !ok {
		t.Fatalf("no IP report for miner hint %s", iprd.Goldshell)
	}
	second, ok := iprd.NewIPReportFromHint(iprd.Goldshell)
	if !ok {
		t.Fatalf("no IP report for miner hint %s", iprd.Goldshell)
	}
	if first == second {
		t.Fatal("got the same IP report instance, want independent reports")
	}
}

func TestIPolloParse(t *testing.T) {
	var data = []byte("IP Addr:[172.16.6.167]   MAC Addr:[02:81:34:A8:B5:61]    Time:[2026-06-04 23:02:19]")
	pattern, ok := iprd.GetMsgPatternFromHint(iprd.IPollo)
	if !ok {
		t.Fatalf("no pattern for miner hint %s", iprd.IPollo)
	}
	got := pattern.Match(data)
	want := true
	if got != want {
		t.Fatalf("got no match, want match")
	}
}

func TestIBeLinkParse(t *testing.T) {
	var data = []byte("AZZ\xf0\x01\x00\x00\x00198.18.0.1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00198.18.0.3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00198.18.0.4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00020000000003\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1e\x00\x00\x00}'\x00\x00\x00\x01\x00\x00/\x00\x00\x00cgminer-6.0.44\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00ibelink\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	ipreport := &iprd.IBeLinkIPReport{}
	err := ipreport.Parse(data)
	if err != nil {
		t.Fatalf("got error %v, want no error", err)
	}
	got := ipreport.IPAddr()
	if got != "198.18.0.1" {
		t.Errorf("got %s, want 198.18.0.1", got)
	}
	got = ipreport.MacAddr()
	if got != "02:00:00:00:00:03" {
		t.Errorf("got %s, want 02:00:00:00:00:03", got)
	}
}

func TestIBeLinkParseRejectsMissingAddressFields(t *testing.T) {
	data := []byte("AZZ\xf0\x01\x00\x00\x00192.18.0.1\x00")
	ipreport := &iprd.IBeLinkIPReport{}

	if err := ipreport.Parse(data); err == nil {
		t.Fatal("got no error, want invalid address fields error")
	}
}

func TestParseBPFNetwork(t *testing.T) {
	cases := []struct {
		Name string
		Net  string
		Want string
	}{
		{"empty network", "", ""},
		{"over max network length", "255.255.255.2555", ""},
		{"too many octets", "255.255.255.255.1", ""},
		{"octet out of range", "256", ""},
		{"dotted quad", "192.168.1.0", "192.168.1.0"},
		{"dotted triple", "192.168.1", "192.168.1"},
		{"dotted pair", "192.168", "192.168"},
		{"single", "10", "10"},
	}

	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			got := iprd.ParseBPFNetwork(test.Net)
			if got != test.Want {
				t.Errorf("got %q, want %q", got, test.Want)
			}
		})
	}
}
