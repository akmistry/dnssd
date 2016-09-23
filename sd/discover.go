package sd

import (
	"log"
	"net"

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
	ptrQ := mdns.QueryType(q.serv, dns.TypePTR)
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
	rrQ := mdns.QueryType(name, dns.TypeANY)
	var aRr *dns.A
	var aaaaRr *dns.AAAA
	var srvRr *dns.SRV
	var txtRr *dns.TXT
	for {
		var rr dns.RR
		select {
		case <-q.done:
			return
		case rr := <-rrQ.Chan:
		}

		switch rr.Header().Rrtype {
		case dns.TypeA:
			aRr = rr.(*dns.A)
		case dns.TypeAAAA:
			aaaaRr = rr.(*dns.AAAA)
		case dns.TypeSRV:
			srvRr = rr.(*dns.SRV)
		case dns.TypeTXT:
			txtRr = rr.(*dns.TXT)
		}

		// TODO: Wait for AAAA record, in case it exists.
		if aRr != nil && srvRr != nil && txtRr != nil {
			break
		}
	}

	s.Ip = aRr.A
	s.Port = srvRr.Port
	// TODO: Parse TXT.

	select {
	case <-q.done:
	case q.ch <- s:
	}
}
