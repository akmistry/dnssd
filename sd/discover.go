package sd

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/akmistry/dnssd/mdns"
)

type Service struct {
	Name string
	Ip   net.IP
	Port uint16
}

type Query struct {
	Chan <-chan *Service

	serv       string
	ch         chan<- *Service
	ansCh      chan *Service
	ctx        context.Context
	cancelFunc context.CancelFunc
	opts       QueryOpts
}

type QueryOpts struct {
	Dedup        bool
	ScanInterval time.Duration
}

const defaultScanInterval = time.Second * 60

var defaultOpts QueryOpts

func Discover(service string, opts *QueryOpts) *Query {
	ch := make(chan *Service)
	ctx, cf := context.WithCancel(context.Background())
	if opts == nil {
		opts = &defaultOpts
	}
	q := &Query{Chan: ch, serv: service, ch: ch, ansCh: make(chan *Service),
		ctx: ctx, cancelFunc: cf, opts: *opts}
	go q.do()
	go q.dedup()
	return q
}

func (q *Query) Done() {
	q.cancelFunc()
}

func (q *Query) dedup() {
	seen := make(map[string]bool)
	for {
		var s *Service
		select {
		case <-q.ctx.Done():
			return
		case s = <-q.ansCh:
		}

		if q.opts.Dedup {
			str := fmt.Sprintf("%s %v %d", s.Name, s.Ip, s.Port)
			if seen[str] {
				continue
			}
			seen[str] = true
		}

		select {
		case <-q.ctx.Done():
			return
		case q.ch <- s:
		}
	}
}

func (q *Query) do() {
	scanInterval := q.opts.ScanInterval
	if scanInterval == 0 {
		scanInterval = defaultScanInterval
	}
	ptrQ := mdns.NewQuery(q.serv, dns.TypePTR,
		&mdns.QueryOpts{Continuous: true, Retries: -1, RetryInterval: scanInterval})
	for {
		var rr dns.RR
		select {
		case <-q.ctx.Done():
			return
		case rr = <-ptrQ.Chan:
		}

		if rr.Header().Rrtype != dns.TypePTR {
			log.Println("Unexpected RR in PTR query", rr)
			continue
		}

		ptr := rr.(*dns.PTR)
		go q.doInstanceQuery(ptr.Ptr)
	}
}

func (q *Query) doInstanceQuery(name string) {
	// Note: Only a single instance is expected for each instance name.
	s := &Service{Name: name}
	// Ask for all records, but we're really just looking for TXT and SRV... for now.
	// Be aggressive with query attempts.
	rrQ := mdns.NewQuery(name, dns.TypeANY,
		&mdns.QueryOpts{Continuous: true, Retries: 5, RetryInterval: time.Second * time.Duration(1)})
	defer rrQ.Done()

	var srvRr *dns.SRV
	var txtRr *dns.TXT
	for {
		var rr dns.RR
		select {
		case <-q.ctx.Done():
			return
		case rr = <-rrQ.Chan:
		}

		if rr == nil {
			return
		}

		switch rr.Header().Rrtype {
		case dns.TypeSRV:
			srvRr = rr.(*dns.SRV)
		case dns.TypeTXT:
			txtRr = rr.(*dns.TXT)
		}

		if srvRr != nil && txtRr != nil {
			rrQ.Done()
			break
		}
	}

	// Resolve the A or AAAA record from the SRV target.
	// Again, be aggressive, but we only care about the first result.
	aq := mdns.NewQuery(srvRr.Target, dns.TypeA,
		&mdns.QueryOpts{Retries: 5, RetryInterval: time.Second * time.Duration(1)})
	aaaaq := mdns.NewQuery(srvRr.Target, dns.TypeAAAA,
		&mdns.QueryOpts{Retries: 5, RetryInterval: time.Second * time.Duration(1)})
	ch := make(chan net.IP, 2)
	go func() {
		rr := <-aq.Chan
		if rr != nil {
			ch <- rr.(*dns.A).A.To4()
		} else {
			ch <- nil
		}
	}()
	go func() {
		rr := <-aaaaq.Chan
		if rr != nil {
			ch <- rr.(*dns.AAAA).AAAA.To16()
		} else {
			ch <- nil
		}
	}()
	for i := 0; i < 2 && s.Ip == nil; i++ {
		s.Ip = <-ch
	}
	aq.Done()
	aaaaq.Done()
	if s.Ip == nil {
		log.Println("No A or AAAA record after retries", srvRr.Target)
		return
	}

	s.Port = srvRr.Port
	// TODO: Parse TXT.

	select {
	case <-q.ctx.Done():
	case q.ansCh <- s:
	}
}
