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

// NewRecord returns a new Record with maximum size of capacity.
func NewRecord(capacity int) *Record {
	return &Record{
		items:    make(map[string]RecordEntry),
		elements: make(map[string]*list.Element),
		order:    list.New(),
		capacity: capacity,
	}
}

// Cap returns the capacity set on Record
func (r *Record) Cap() int {
	return r.capacity
}

// Length returns the current length/size of Record
func (r *Record) Length() int {
	return r.order.Len()
}

// Get returns RecordEntry matching key
func (r *Record) Get(key string) *RecordEntry {
	if ent, ok := r.items[key]; ok {
		return &ent
	}
	return nil
}

// Contains returns bool if key exists in Record
func (r *Record) Contains(key string) bool {
	_, ok := r.items[key]
	return ok
}

// Add creates or updates an element in Record. If Record reaches capacity, elements are automatically removed in FIFO order.
func (r *Record) Add(key string, entry RecordEntry) {
	// if key already exists in Record, move to back and update when we saw it
	if element, ok := r.elements[key]; ok {
		r.order.MoveToBack(element)
		element.Value = key
		entry.UpdatedAt = time.Now().UnixMilli()
		r.items[key] = entry
		return
	}
	// remove in FIFO order if we are at capacity
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
	entry.UpdatedAt = time.Now().UnixMilli()
	r.items[key] = entry
}

// Remove deletes element matching key in Record. Returns error if key is not found.
func (r *Record) Remove(key string) error {
	el, ok := r.elements[key]
	if !ok {
		return fmt.Errorf("key %q not found", key)
	}
	delete(r.elements, key)
	delete(r.items, key)
	r.order.Remove(el)
	return nil
}

// Clear removes all elements in Record and resets order.
func (r *Record) Clear() {
	r.items = make(map[string]RecordEntry)
	r.elements = make(map[string]*list.Element)
	r.order.Init()
}

// Display prints the current RecordEntries and Length of record to stdout. Useful for logging/debugging.
func (r *Record) Display() {
	fmt.Printf("Record len: %d\n", r.Length())
	for e := r.order.Front(); e != nil; e = e.Next() {
		key := e.Value.(string)
		fmt.Printf("%s: %+v, ", key, r.items[key])
	}
}
