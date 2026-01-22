package iprd_test

import (
	"slices"
	"testing"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
	"github.com/goccy/go-json"
)

func TestSealminerParse(t *testing.T) {
	var data json.RawMessage = []byte(`{"Type":3,"Status":0,"Substatus":[]}\x00\x00\x00\x00{"MAC":"50:d4:48:4b:08:1b","Type":"A2","Firmware":"2025040301","CtrlBoardVersion":"taurus_air_v1.1","Protocol":537929985,"NetInterfaceCnt":3,"UpgradeStatus":0,"MainBoardSN":"S127200251200340","RatedInputPower":4300,"InputPowerLimit":3400,"BoardSnArray":[{"SN":"S124600251201353","BinVer":1,"BinNum":29},{"SN":"S124600251200944","BinVer":1,"BinNum":29},{"SN":"S124600251200910","BinVer":1,"BinNum":29}]}\x00\x00{"Interface":"eth0","Active":false,"DHCP":true,"IPV4":"192.168.1.2","Netmask":"255.255.255.0","Gateway":"192.168.1.1","DNS1":"114.114.114.114","DNS2":"8.8.8.8","AutoReboot":false}\x00{"Interface":"eth1","Active":true,"DHCP":true,"IPV4":"172.16.50.29","Netmask":"255.255.255.0","Gateway":"172.16.50.1","DNS1":"172.16.50.1","DNS2":"","AutoReboot":false}\x00\x00\x00\x00{"Interface":"bridge","Active":false,"DHCP":true,"IPV4":"192.168.1.4","Netmask":"255.255.255.0","Gateway":"192.168.1.1","DNS1":"114.114.114.114","DNS2":"8.8.8.8","AutoReboot":false}\x00\x00\x00{"Pools":[{"URL":"sha256asicboost.auto.nicehash.com:9200","Worker":"NHbVmEq1dwpK8RQPdGGPQ4hDoTHVdkidwLcf.seal01","Password":"x"},{"URL":"sha256asicboost.auto.nicehash.com:9200","Worker":"NHbVmEq1dwpK8RQPdGGPQ4hDoTHVdkidwLcf","Password":"x"}],"IPSuffixEnable":false,"SocketProxyEnabale":false,"SocketProxy":"","AutoReboot":false}\x00\x00\x00\x00{"Room":0,"Cabinet":0,"Floor":0,"Pos":0}\x00\x00\x00\x00`)
	data = slices.Concat([]byte("["), data, []byte("]"))
	var ipSealMiner *iprd.IPReportSealminer
	err := json.Unmarshal(data, &ipSealMiner)
	if err != nil {
		t.Fatalf("got error %W, want no error", err)
	}
	got := ipSealMiner.Info.MACAddress
	want := "50:d4:48:4b:08:1b"
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}
