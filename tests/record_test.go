package iprd_test

import (
	"fmt"
	"reflect"
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
	record := iprd.NewRecord(5)
	fillRecord(record, 5)
	len := record.Length()

	// update existing entry
	key := "test 1"
	ent := record.Get(key)
	test_entry := iprd.RecordEntry{
		SrcIP:     "192.168.1.111",
		SrcMAC:    "aa:bb:cc:dd:ee:ff",
		MinerHint: iprd.Antminer,
		CreatedAt: time.Now().UnixMilli(),
	}
	record.Add(key, test_entry)
	updatedEnt := record.Get(key)
	assertLength(t, record.Length(), len)
	if reflect.DeepEqual(ent, updatedEnt) {
		t.Errorf("got %+v, wanted %+v", updatedEnt, test_entry)
	}
}

func TestRemoveEntry(t *testing.T) {
	record := iprd.NewRecord(5)
	fillRecord(record, 5)
	len := record.Length()

	t.Run("remove non-existing entry", func(t *testing.T) {
		err := record.Remove("doesn't exist")
		if err == nil {
			t.Errorf("wanted error, got nil")
		}
		assertLength(t, record.Length(), len)
	})
	t.Run("remove existing entry", func(t *testing.T) {
		err := record.Remove("test 1")
		if err != nil {
			t.Errorf("got %v, wanted nil", err)
		}
		assertLength(t, record.Length(), 4)
	})
}

func assertLength(t testing.TB, got, want int) {
	t.Helper()
	if got != want {
		t.Errorf("got length %d, wanted %d", got, want)
	}
}
