package mdns

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Query struct {
	Chan <-chan dns.RR

	ch         chan<- dns.RR
	done       chan bool
	q          dns.Question
	continuous bool
}

func NewQuery(name string) *Query {
	ch := make(chan dns.RR)
	resp := &Query{Chan: ch, ch: ch, done: make(chan bool)}
	resp.q = dns.Question{Name: name, Qtype: dns.TypeANY, Qclass: dns.ClassINET}
	go resp.do()
	return resp
}

func NewQueryType(name string, t uint16) *Query {
	ch := make(chan dns.RR)
	resp := &Query{Chan: ch, ch: ch, done: make(chan bool)}
	resp.q = dns.Question{Name: name, Qtype: t, Qclass: dns.ClassINET}
	go resp.do()
	return resp
}

func NewRetryQuery(name string, t uint16, tries int, interval time.Duration) *Query {
	ch := make(chan dns.RR)
	resp := &Query{Chan: ch, ch: ch, done: make(chan bool)}
	resp.q = dns.Question{Name: name, Qtype: t, Qclass: dns.ClassINET}
	go resp.doRetries(tries, interval)
	return resp
}

func (r *Query) OneShot() dns.RR {
	rr := <-r.Chan
	r.Done()
	return rr
}

func (r *Query) Done() {
	close(r.done)
}

func (r *Query) do() {
	ip4Server.query(r)

	<-r.done
	ip4Server.endQuery(r)

	close(r.ch)
}

func (r *Query) doRetries(tries int, interval time.Duration) {
	for i := 0; i < tries; i++ {
		q := NewQueryType(r.q.Name, r.q.Qtype)
		select {
		case rr := <-q.Chan:
			r.answer(rr)
			q.Done()
			return
		case <-time.After(interval):
			// Timeout, retry.
		}
		q.Done()
	}

	// No result after retries. Close result channel.
	close(r.ch)
}

func (r *Query) answer(rr dns.RR) {
	select {
	case <-r.done:
		// Do nothing, query is finished.
	case r.ch <- rr:
		// Answer delivered.
	}
}

type queryMap struct {
	lock    sync.Mutex
	queries map[string][]*Query
}

func newQueryMap() *queryMap {
	return &queryMap{queries: make(map[string][]*Query)}
}

func (m *queryMap) add(r *Query) {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.queries[r.q.Name] = append(m.queries[r.q.Name], r)
}

func (m *queryMap) remove(r *Query) {
	m.lock.Lock()
	defer m.lock.Unlock()

	name := r.q.Name
	qs := m.queries[name]

	for i, q := range qs {
		if q == r {
			last := len(qs) - 1
			qs[i], qs[last] = qs[last], nil
			m.queries[name] = qs[:last]
			break
		}
	}
}

// TODO: Make this more efficient by coalescing RRs by name.
func (m *queryMap) answer(rr dns.RR) {
	var rs []*Query

	m.lock.Lock()
	name := rr.Header().Name
	qs := m.queries[name]
	for _, r := range qs {
		if r.q.Name == name && (r.q.Qtype == dns.TypeANY || r.q.Qtype == rr.Header().Rrtype) {
			// Build a list and answer outside the lock to avoid a potential deadlock with the requester.
			rs = append(rs, r)
		}
	}
	m.lock.Unlock()

	for _, r := range rs {
		r.answer(rr)
	}
}
