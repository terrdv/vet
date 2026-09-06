package crawler

import (
	"sync"
)
	



type VisitedSet struct {
	mx sync.Mutex
	set map[string]struct{}
}


func NewVisitedSet() *VisitedSet {
	return &VisitedSet{set: make(map[string]struct{})}
}

// Accepts an ABSOLUTE URL
func (v *VisitedSet) Add(url string) bool {
	v.mx.Lock()
	defer v.mx.Unlock()

	if _, seen := v.set[url]; seen {
		return false
	}
	v.set[url] = struct{}{}
	return true
	
}

// Removes absolute URL
func (v *VisitedSet) Remove(url string) {
	v.mx.Lock()
	defer v.mx.Unlock()
	delete(v.set, url)
}

func (v *VisitedSet) Exists(url string) bool {
	v.mx.Lock()
	defer v.mx.Unlock()
	_, seen := v.set[url]
        return seen
}



