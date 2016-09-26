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

type entryList struct {
	entries []*cacheEntry
}

type cache struct {
	lock    sync.Mutex
	entries map[string]*entryList
}

func newCache() *cache {
	return &cache{entries: make(map[string]*entryList)}
}

func (c *cache) add(rr dns.RR) {
	// ttl == 0 means no caching.
	if rr.Header().Ttl == 0 {
		return
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	name := rr.Header().Name
	el := c.entries[name]
	if el == nil {
		el = &entryList{}
		c.entries[name] = el
	}
	el.add(rr)
}

func (c *cache) get(name string, t uint16) []dns.RR {
	log.Println("Looking up cache", name, t)
	c.lock.Lock()
	defer c.lock.Unlock()

	el := c.entries[name]
	if el == nil {
		log.Println("Name not found")
		return []dns.RR{}
	}
	return el.get(t)
}

func (el *entryList) add(rr dns.RR) {
	log.Println("Adding to cache", rr)
	ttl := rr.Header().Ttl
	now := time.Now()
	deadline := now.Add(time.Second * time.Duration(ttl))

	rrStr := rr.String()
	for _, e := range el.entries {
		// TODO: Compare without deadline.
		if e.rr.String() == rrStr {
			log.Println("Entry found, updating deadline")
			// Don't store dup entries, but update the deadline.
			e.deadline = deadline
			return
		}
	}

	// Not found, add.
	// TODO: Expire after deadline.
	log.Println("New entry added to cache")
	el.entries = append(el.entries, &cacheEntry{rr: dns.Copy(rr), deadline: deadline})
}

func (el *entryList) get(t uint16) []dns.RR {
	var ret []dns.RR
	now := time.Now()
	for _, e := range el.entries {
		if now.After(e.deadline) {
			// Deadline expired, ignore.
			continue
		}

		if t == dns.TypeANY || e.rr.Header().Rrtype == t {
			ret = append(ret, e.getWithFixedTtl())
		}
	}

	if len(ret) != 0 {
		log.Println("Found in cache", ret)
	}

	return ret
}

func (e *cacheEntry) getWithFixedTtl() dns.RR {
	rr := dns.Copy(e.rr)
	ttl := int64(e.deadline.Sub(time.Now()) / time.Second)
	if ttl < 0 {
		ttl = 0
	}
	rr.Header().Ttl = uint32(ttl)
	log.Println("From cache with reset ttl", rr)
	return rr
}
