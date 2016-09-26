package sd

import (
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

// TODO: Solve the naming problem... and get a Turing award in the process.
type Query struct {
	Chan <-chan *Service

	serv string
	ch   chan<- *Service
	done chan bool
}

func Discover(service string) *Query {
	ch := make(chan *Service)
	q := &Query{Chan: ch, serv: service, ch: ch, done: make(chan bool)}
	go q.do()
	return q
}

func (q *Query) Done() {
	close(q.done)
}

func (q *Query) do() {
	ptrQ := mdns.NewQueryType(q.serv, dns.TypePTR)
	for {
		var rr dns.RR
		select {
		case <-q.done:
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
	rrQ := mdns.NewQueryType(name, dns.TypeANY)
	var srvRr *dns.SRV
	var txtRr *dns.TXT
	for {
		var rr dns.RR
		select {
		case <-q.done:
			return
		case rr = <-rrQ.Chan:
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

	// Resolve the A record from the SRV target.
	// TODO: Resolve AAAA record.
	// TODO: Timeout and cancel.
	aq := mdns.NewRetryQuery(srvRr.Target, dns.TypeA, 5, time.Second)
	rr := <-aq.Chan
	aq.Done()
	if rr == nil {
		log.Println("No A record after retries", srvRr.Target)
		return
	}

	s.Ip = rr.(*dns.A).A
	s.Port = srvRr.Port
	// TODO: Parse TXT.

	select {
	case <-q.done:
	case q.ch <- s:
	}
}
