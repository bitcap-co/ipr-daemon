package iprd

import (
	"container/list"
	"fmt"
	"time"
)

type Record struct {
	items    map[string]RecordEntry
	elements map[string]*list.Element
	order    *list.List
	capacity int
}

// RecordEntry represents an entry in Record
type RecordEntry struct {
	SrcIP     string
	SrcMAC    string
	MinerHint MinerTypeHint
	CreatedAt int64
	UpdatedAt int64
}

// NewRecord returns a new Record with maximum size of cap.
func NewRecord(cap int) *Record {
	return &Record{
		items:    make(map[string]RecordEntry),
		elements: make(map[string]*list.Element),
		order:    list.New(),
		capacity: cap,
	}
}

// Add creates/updates a RecordEntry in Record. If capacity is reached, entries are removed in FIFO order.
func (r *Record) Add(key string, record RecordEntry) {
	if element, ok := r.elements[key]; ok {
		r.order.MoveToBack(element)
		element.Value = key
		record.UpdatedAt = time.Now().UnixMilli()
		r.items[key] = record
		return
	}

	if r.order.Len() >= r.capacity {
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

// Display prints the current RecordEntries and Length of record to stdout. Useful for logging/debugging.
func (r *Record) Display() {
	fmt.Printf("Record len: %d\n", r.Length())
	for e := r.order.Front(); e != nil; e = e.Next() {
		key := e.Value.(string)
		fmt.Printf("%s: %+v, ", key, r.items[key])
	}
}
