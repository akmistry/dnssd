package mdns

import (
	"log"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

const (
	maxMsgSize = 512
	bufSize    = 1500
)

var (
	ip4Addr   = &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	ip6Addr   = &net.UDPAddr{IP: net.ParseIP("FF02::FB"), Port: 5353}
	localZone = &zone{entries: make(map[string][]dns.RR)}

	rrCache   *cache
	ip4Server *server
)

type server struct {
	conn *multicastConn

	queries *queryMap
}

type zone struct {
	lock    sync.Mutex
	entries map[string][]dns.RR
}

func Publish(rrStr string) {
	rr, err := dns.NewRR(rrStr)
	if err != nil {
		log.Println("Failure parsing RR", err)
		return
	}
	PublishRR(rr)
}

func PublishRR(rr dns.RR) {
	hdr := rr.Header()
	if !strings.HasSuffix(hdr.Name, ".local.") {
		log.Panicln("Published domain MUST end with .local.", hdr.Name)
		return
	}

	localZone.publish(rr)
}

func init() {
	rrCache = newCache()
	ip4Server = newServer(ip4Addr)
}

func newServer(addr *net.UDPAddr) *server {
	conn, err := newConn(addr)
	if err != nil {
		log.Panicln("Unable to listen to MDNS port", err)
	}

	s := &server{conn: conn, queries: newQueryMap()}
	go s.listen()
	return s
}

func (s *server) query(q *Query) {
	s.queries.add(q)

	// Get cache answers, but also submit the query in case someone else gives us an answer.
	cacheRrs := rrCache.get(q.q.Name, q.q.Qtype)
	for _, a := range cacheRrs {
		q.answer(a)
	}
	if len(cacheRrs) > 0 && !q.opts.Continuous {
		return
	}

	msg := new(dns.Msg)
	msg.Question = []dns.Question{q.q}
	err := s.send(msg, nil)
	if err != nil {
		log.Println("Error sending query", err)
	}
}

func (s *server) endQuery(q *Query) {
	s.queries.remove(q)
}

func (s *server) send(msg *dns.Msg, addr net.Addr) error {
	b, err := msg.Pack()
	if err != nil {
		return err
	}

	if addr == nil {
		return s.conn.sendMulticast(b)
	}
	return s.conn.send(b, addr)
}

func (s *server) listen() {
	buf := make([]byte, bufSize)
	for {
		n, _, err := s.conn.recv(buf)
		if err != nil {
			log.Panicln("Error reading UDP packet", err)
		}

		msg := &dns.Msg{}
		err = msg.Unpack(buf[:n])
		if err != nil {
			log.Println("Error unpacking DNS packet", err)
			continue
		}
		//log.Println("=======================================================================")
		//log.Println(msg)

		var resp *dns.Msg
		if msg.MsgHdr.Response {
			resp = s.doResponse(msg)
		} else {
			resp = s.doQuestion(msg)
		}

		if resp != nil {
			// TODO: Delay response by up to 500ms as per RFC.
			// TODO: Send unicast as per RFC.
			// TODO: Coalesce responses.
			err = s.send(resp, nil)
			if err != nil {
				log.Println("Unable to send response", err)
			}
		}
	}
}

func (s *server) doQuestion(msg *dns.Msg) *dns.Msg {
	if msg.MsgHdr.Opcode != dns.OpcodeQuery {
		log.Println("Non-query opcodes not supported", msg.MsgHdr.Opcode)
		return nil
	}

	resp := new(dns.Msg)
	resp.MsgHdr = dns.MsgHdr{
		Id:            msg.MsgHdr.Id,
		Response:      true,
		Authoritative: true,
		Opcode:        dns.OpcodeQuery,
	}

	for _, q := range msg.Question {
		// RFC 6762, section 6: Multicast DNS responses MUST NOT contain any questions in the
		// Question Section.
		resp.Answer = append(resp.Answer, localZone.query(q)...)
	}

	if len(resp.Answer) == 0 {
		return nil
	}

	// TODO: Fill additional data.

	return resp
}

func (s *server) doResponse(msg *dns.Msg) *dns.Msg {
	// Cache answers and additional RRs.
	for _, a := range msg.Answer {
		rrCache.add(a)
	}
	for _, a := range msg.Extra {
		rrCache.add(a)
	}

	for _, a := range msg.Answer {
		s.queries.answer(a)
	}

	return nil
}

func (z *zone) query(q dns.Question) []dns.RR {
	z.lock.Lock()
	defer z.lock.Unlock()

	name := q.Name
	entries := z.entries[name]

	var ans []dns.RR
	for _, e := range entries {
		if q.Qtype == dns.TypeANY || q.Qtype == e.Header().Rrtype {
			ans = append(ans, e)
		}
	}

	return ans
}

func (z *zone) publish(rr dns.RR) {
	z.lock.Lock()
	defer z.lock.Unlock()

	name := rr.Header().Name
	z.entries[name] = append(z.entries[name], rr)
}
