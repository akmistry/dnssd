package mdns

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Query struct {
	Chan <-chan dns.RR

	ch         chan<- dns.RR
	ansCh      chan dns.RR
	ctx        context.Context
	cancelFunc context.CancelFunc
	q          dns.Question
	opts       QueryOpts
}

type QueryOpts struct {
	Continuous    bool
	Retries       int
	RetryInterval time.Duration
}

var defaultOpts QueryOpts

func NewQuery(name string, qtype uint16, opts *QueryOpts) *Query {
	ch := make(chan dns.RR)
	ctx, cf := context.WithCancel(context.Background())
	if opts == nil {
		opts = &defaultOpts
	}
	query := &Query{Chan: ch, ch: ch, ansCh: make(chan dns.RR), ctx: ctx, cancelFunc: cf, opts: *opts}
	query.q = dns.Question{Name: name, Qtype: qtype, Qclass: dns.ClassINET}
	go query.do()
	return query
}

func (q *Query) OneShot() dns.RR {
	rr := <-q.Chan
	q.Done()
	return rr
}

func (q *Query) Done() {
	q.cancelFunc()
}

func (q *Query) do() {
	var tries uint = 1
	retries := q.opts.Retries
	if retries > 0 {
		tries = uint(retries) + 1
	} else if retries < 0 {
		tries = uint(retries)
	}

	go func() {
		defer close(q.ch)
		for {
			var rr dns.RR
			select {
			case <-q.ctx.Done():
				return
			case rr = <-q.ansCh:
			}

			select {
			case <-q.ctx.Done():
				return
			case q.ch <- rr:
			}
			if !q.opts.Continuous {
				q.Done()
				return
			}
		}
	}()

	done := false
	for i := uint(0); i < tries && !done; i++ {
		ip4Server.query(q)

		if tries == 1 {
			// No retry timeout.
			<-q.ctx.Done()
			done = true
		} else {
			select {
			case <-q.ctx.Done():
				// Done.
				done = true
			case <-time.After(q.opts.RetryInterval):
				// Timeout, retry.
			}
		}

		ip4Server.endQuery(q)
	}

	q.Done()
}

func (q *Query) answer(rr dns.RR) {
	select {
	case <-q.ctx.Done():
		// Do nothing, query is finished.
	case q.ansCh <- rr:
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
