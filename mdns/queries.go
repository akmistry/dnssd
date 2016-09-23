package mdns

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Response struct {
	Chan <-chan dns.RR

	ch   chan<- dns.RR
	done chan bool
	q    dns.Question
}

func Query(name string) *Response {
	ch := make(chan dns.RR)
	resp := &Response{Chan: ch, ch: ch, done: make(chan bool)}
	resp.q = dns.Question{Name: name, Qtype: dns.TypeANY, Qclass: dns.ClassINET}
	go resp.do()
	return resp
}

func QueryType(name string, t uint16) *Response {
	ch := make(chan dns.RR)
	resp := &Response{Chan: ch, ch: ch, done: make(chan bool)}
	resp.q = dns.Question{Name: name, Qtype: t, Qclass: dns.ClassINET}
	go resp.do()
	return resp
}

func RetryQuery(name string, t uint16, tries int, interval time.Duration) *Response {
	ch := make(chan dns.RR)
	resp := &Response{Chan: ch, ch: ch, done: make(chan bool)}
	resp.q = dns.Question{Name: name, Qtype: t, Qclass: dns.ClassINET}
	go resp.doRetries(tries, interval)
	return resp
}

func (r *Response) OneShot() dns.RR {
	rr := <-r.Chan
	r.Done()
	return rr
}

func (r *Response) Done() {
	close(r.done)
}

func (r *Response) do() {
	ip4Server.query(r)

	<-r.done
	ip4Server.endQuery(r)
}

func (r *Response) doRetries(tries int, interval time.Duration) {
	for i := 0; i < tries; i++ {
		q := QueryType(r.q.Name, r.q.Qtype)
		select {
		case rr := <-q.Chan:
			select {
			case <-r.done:
			case r.ch <- rr:
			}
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

func (r *Response) answer(rr dns.RR) {
	select {
	case <-r.done:
		// Do nothing, query is finished.
	case r.ch <- rr:
		// Answer delivered.
	}
}

type queryMap struct {
	lock    sync.Mutex
	queries map[string][]*Response
}

func newQueryMap() *queryMap {
	return &queryMap{queries: make(map[string][]*Response)}
}

func (m *queryMap) add(r *Response) {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.queries[r.q.Name] = append(m.queries[r.q.Name], r)
}

func (m *queryMap) remove(r *Response) {
	m.lock.Lock()
	defer m.lock.Unlock()

	qs := m.queries[r.q.Name]

	for i, q := range qs {
		if q == r {
			last := len(qs) - 1
			qs[i] = qs[last]
			qs[last] = nil
			m.queries[q.q.Name] = qs[:last]
			break
		}
	}
}

// TODO: Make this more efficient by coalescing RRs by name.
func (m *queryMap) answer(rr dns.RR) {
	var rs []*Response

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
