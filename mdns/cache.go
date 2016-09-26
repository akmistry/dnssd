package mdns

import (
	"log"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cacheEntry struct {
	rr       dns.RR
	deadline time.Time
}

type typeMap struct {
	entries map[uint16]*cacheEntry
}

type cache struct {
	lock    sync.Mutex
	entries map[string]*typeMap
}

func newCache() *cache {
	return &cache{entries: make(map[string]*typeMap)}
}

func (c *cache) add(rr dns.RR) {
	// ttl == 0 means no caching.
	if rr.Header().Ttl == 0 {
		return
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	name := rr.Header().Name
	tm := c.getTypeMap(name)
	tm.add(rr)
}

func (c *cache) get(name string, t uint16) []dns.RR {
	log.Println("Looking up cache", name, t)
	c.lock.Lock()
	defer c.lock.Unlock()

	tm := c.entries[name]
	if tm == nil {
		//log.Println("Name not found")
		return []dns.RR{}
	}
	return tm.get(name, t)
}

func (c *cache) getTypeMap(name string) *typeMap {
	tm := c.entries[name]
	if tm == nil {
		tm = &typeMap{entries: make(map[uint16]*cacheEntry)}
		c.entries[name] = tm
	}
	return tm
}

func (tm *typeMap) add(rr dns.RR) {
	rrType := rr.Header().Rrtype
	ttl := rr.Header().Ttl
	deadline := time.Now().Add(time.Second * time.Duration(ttl))
	e := tm.entries[rrType]

	if e != nil {
		// If deadline has expired, or new entry's deadline is later than the current cache entry.
		if e.deadline.After(time.Now()) || deadline.After(e.deadline) {
			e = nil
		}
	}

	if e == nil {
		//log.Println("Adding to cache", rr, "deadline", deadline)
		e = &cacheEntry{rr: dns.Copy(rr), deadline: deadline}
		tm.entries[rrType] = e
	}
}

func (e *cacheEntry) resetTtl() dns.RR {
	rr := dns.Copy(e.rr)
	ttl := int64(e.deadline.Sub(time.Now()) / time.Second)
	if ttl < 0 {
		ttl = 0
	}
	rr.Header().Ttl = uint32(ttl)
	//log.Println("From cache with reset ttl", rr)
	return rr
}

func (tm *typeMap) get(name string, t uint16) []dns.RR {
	now := time.Now()
	if t != dns.TypeANY {
		e := tm.entries[t]
		if e == nil || e.deadline.After(now) {
			//log.Println("Entry not found, or deadline expired", e)
			delete(tm.entries, t)
			return []dns.RR{}
		}
		return []dns.RR{e.resetTtl()}
	}

	var ret []dns.RR
	for k, v := range tm.entries {
		if now.After(v.deadline) {
			//log.Println("Deadline expired", v)
			delete(tm.entries, k)
			continue
		}

		ret = append(ret, v.resetTtl())
	}
	return ret
}
