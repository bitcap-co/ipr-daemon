package iprd

import (
	"container/list"
	"fmt"
	"time"
)

// Record is a fixed-size LRU cache of RecordEntry items.
// Serves as a cache for IP report entries to avoid processing duplicates.
type Record struct {
	items    map[string]RecordEntry
	elements map[string]*list.Element
	order    *list.List
	capacity int
}

// RecordEntry represents an IP report entry in Record
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

// Get returns the RecordEntry for the given key, and a bool indicating if the key was found.
func (r *Record) Get(key string) (*RecordEntry, bool) {
	if ent, ok := r.items[key]; ok {
		return &ent, true
	}
	return nil, false
}

// Add creates or updates an RecordEntry in Record. Once capacity is reached, entries are removed in FIFO order.
func (r *Record) Add(key string, entry RecordEntry) {
	r.addAt(key, entry, time.Now())
}

func (r *Record) addAt(key string, entry RecordEntry, observedAt time.Time) {
	entry.UpdatedAt = observedAt.UnixMilli()
	// if key already exists, move to back and update when we saw it.
	if element, ok := r.elements[key]; ok {
		r.order.MoveToBack(element)
		element.Value = key
		r.items[key] = entry
		return
	}
	// remove entries in FIFO order if we are at capacity
	if r.order.Len() >= r.capacity {
		oldest := r.order.Front()
		if oldest != nil {
			delete(r.elements, oldest.Value.(string))
			delete(r.items, oldest.Value.(string))
			r.order.Remove(oldest)
		}
	}
	// Push new entry to back of order
	el := r.order.PushBack(key)
	r.elements[key] = el
	r.items[key] = entry
}

// Remove deletes entry matching key in Record, if it exists.
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

// Clear removes all entries in Record and resets order.
func (r *Record) Clear() {
	r.items = make(map[string]RecordEntry)
	r.elements = make(map[string]*list.Element)
	r.order.Init()
}

// Display prints the current record entries and length of record to stdout. Useful for logging/debugging.
func (r *Record) Display() {
	fmt.Printf("Record len: %d\n", r.Length())
	for e := r.order.Front(); e != nil; e = e.Next() {
		key := e.Value.(string)
		fmt.Printf("%s: %+v, ", key, r.items[key])
	}
}
