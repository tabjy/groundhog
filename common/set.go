package common

import "sync"

// Set is a ADT that can store certain values, without any particular order,
// and no repeated values. It can be understood as a unordered list with all
// elements being distinct.
type Set interface {
	Add(element interface{})           // adds the specified element to this set if it is not already present.
	Remove(element interface{}) bool   // removes the specified element from this set if it is present
	Contains(element interface{}) bool // returns true if this set contains the specified element.
	Clear()                            // removes all of the elements from this set
	Len() int                          // returns the number of elements in this set (its cardinality).
	Empty() bool                       // returns true if this set contains no elements.

	ForEach(fn func(interface{}))     // apply callback function to each of the elements within the set.
	Filter(fn func(interface{}) bool) // apply callback function to each of the elements within the set, a element is kept if and only if callback returns true.
}

// HashSet is a general implement of Set ADT with a underlying golang built-in
// map. By natures of golang maps (where as order of iteration is undefined),
// iterators are not possible to implement.
type HashSet struct {
	items map[interface{}]bool
	mu    sync.Mutex
}

func NewHashSet() Set {
	return &HashSet{items: make(map[interface{}]bool)}
}

// Add implements Add in Set ADT.
func (s *HashSet) Add(element interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.items[element] = true
}

// Remove implements Remove in Set ADT.
func (s *HashSet) Remove(element interface{}) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, contains := s.items[element]

	if contains {
		delete(s.items, element)
	}
	return contains
}

// Contains implements Contains in Set ADT.
func (s *HashSet) Contains(element interface{}) bool {
	// not sure is map lookup is thread safe, but just better be safe than sorry
	s.mu.Lock()
	defer s.mu.Unlock()

	_, contains := s.items[element]
	return contains
}

// Clear implements Clear in Set ADT.
func (s *HashSet) Clear() {
	// the old map should be recycled by GC, hopefully...
	s.mu.Lock()
	defer s.mu.Unlock()

	s.items = make(map[interface{}]bool)
}

// Len implements Len in Set ADT.
func (s *HashSet) Len() int {
	// this is atomic already
	return len(s.items)
}

// Empty implements Empty in Set ADT.
func (s *HashSet) Empty() bool {
	return s.Len() == 0
}

// ForEach implements ForEach in Set ADT.
//
// IMPORTANT: ForEach causes the set to be locked until finish iterating all
// elements. Therefore, calling any of Add, Remove, Contains, and Clear will
// result in a dead lock. Do these ops in a separate goroutine!
func (s *HashSet) ForEach(fn func(interface{})) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for element := range s.items {
		fn(element)
	}
}

// Filter implements Filter in Set ADT.
//
// IMPORTANT: Filter causes the set to be locked until finish iterating all
// elements. Therefore, calling any of Add, Remove, Contains, and Clear will
// result in a dead lock. Do these ops in a separate goroutine!
func (s *HashSet) Filter(fn func(interface{}) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for element := range s.items {
		if keep := fn(element); !keep {
			delete(s.items, element)
		}
	}
}
