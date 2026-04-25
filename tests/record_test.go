package iprd_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/bitcap-co/ipr-daemon/pkg/iprd"
)

func fillRecord(r *iprd.Record, nentries int) {
	for i := 1; i <= nentries; i++ {
		r.Add(fmt.Sprintf("test %d", i), iprd.RecordEntry{})
	}
}

func TestCapacity(t *testing.T) {
	cases := []struct {
		Name       string
		RecordSize int
		Want       int
	}{
		{"initialize record size at 0", 0, 0},
		{"increase record size to capacity", 5, 5},
		{"increase record size past capacity", 6, 5},
	}

	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			record := iprd.NewRecord(5)
			fillRecord(record, test.RecordSize)
			record.Display()
			got := record.Length()
			if got != test.Want {
				t.Errorf("got %d, want %d", got, test.Want)
			}
		})
	}
}

func TestUpdateExistingEntry(t *testing.T) {
	record := iprd.NewRecord(10)
	// fill record with some entries
	fillRecord(record, 4)
	len := record.Length()
	// try and update an existing entry
	entry := iprd.RecordEntry{
		SrcIP:     "192.168.1.1",
		SrcMAC:    "aa:bb:cc:dd:ee:ff",
		MinerHint: iprd.Antminer,
		CreatedAt: time.Now().UnixMilli(),
	}
	record.Add("test 4", entry)
	got_len := record.Length()
	if got_len != len {
		t.Errorf("got %d, want %d", got_len, len)
	}
	got_entry := record.Get("test 4")
	if got_entry.SrcIP != entry.SrcIP {
		t.Errorf("got %s, want %s", got_entry.SrcIP, entry.SrcIP)
	}
	if got_entry.UpdatedAt == 0 {
		t.Errorf("got %d, want not zero", got_entry.UpdatedAt)
	}
}
