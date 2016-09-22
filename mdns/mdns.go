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
	localZone = &zone{entries: make(map[string][]dns.RR)}

	ip4Server *server
)

type Response struct {
	Chan <-chan dns.RR

	ch   chan<- dns.RR
	done chan bool
	q    dns.Question
}

type server struct {
	conn *net.UDPConn

	lock    sync.Mutex
	queries []*Response
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

func Query(name string) *Response {
	ch := make(chan dns.RR)
	resp := &Response{Chan: ch, ch: ch, done: make(chan bool)}
	resp.q = dns.Question{Name: name, Qtype: dns.TypeANY, Qclass: dns.ClassINET}
	go resp.query()
	return resp
}

func QueryType(name string, t uint16) *Response {
	ch := make(chan dns.RR)
	resp := &Response{Chan: ch, ch: ch, done: make(chan bool)}
	resp.q = dns.Question{Name: name, Qtype: t, Qclass: dns.ClassINET}
	go resp.query()
	return resp
}

func (r *Response) Done() {
	close(r.done)
}

func (r *Response) query() {
	ip4Server.query(r)

	<-r.done
	ip4Server.endQuery(r)
}

func (r *Response) answer(rr dns.RR) {
	select {
	case <-r.done:
		// Do nothing, query is finished.
	case r.ch <- rr:
		// Answer delivered.
	}
}

func init() {
	ip4Server = newServer(ip4Addr)
}

func newServer(addr *net.UDPAddr) *server {
	conn, err := net.ListenMulticastUDP("udp", nil, addr)
	if err != nil {
		log.Panicln("Unable to listen to MDNS port", err)
	}

	s := &server{conn: conn}
	go s.listen()
	return s
}

func (s *server) query(r *Response) {
	s.lock.Lock()
	s.queries = append(s.queries, r)
	s.lock.Unlock()

	msg := new(dns.Msg)
	// TODO: Use ID
	// msg.Id = dns.Id()
	msg.Question = []dns.Question{r.q}
	//	err := s.send(msg, s.conn.LocalAddr().(*net.UDPAddr))
	err := s.send(msg, ip4Addr)
	if err != nil {
		log.Println("Error sending query", err)
	}
}

func (s *server) endQuery(r *Response) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for i, q := range s.queries {
		if q == r {
			last := len(s.queries) - 1
			s.queries[i] = s.queries[last]
			s.queries[last] = nil
			s.queries = s.queries[:last]
			break
		}
	}
}

func (s *server) send(msg *dns.Msg, addr *net.UDPAddr) error {
	b, err := msg.Pack()
	if err != nil {
		return err
	}

	_, err = s.conn.WriteToUDP(b, addr)
	if err != nil {
		return err
	}
	log.Println("****************** Sent", msg)
	return nil
}

func (s *server) listen() {
	buf := make([]byte, bufSize)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			log.Panicln("Error reading UDP packet", err)
		}

		msg := &dns.Msg{}
		err = msg.Unpack(buf[:n])
		if err != nil {
			log.Println("Error unpacking DNS packet", err)
			continue
		}
		log.Println("-----------------------------------------------")
		log.Println("Addr", addr, "Packet", msg)

		var resp *dns.Msg
		if msg.MsgHdr.Response {
			resp = s.doResponse(msg)
		} else {
			resp = s.doQuestion(msg)
		}

		if resp != nil {
			// TODO: Delay response by up to 500ms as per RFC.
			err = s.send(resp, addr)
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

	return resp
}

func (s *server) doResponse(msg *dns.Msg) *dns.Msg {
	s.lock.Lock()
	defer s.lock.Unlock()

	for _, q := range s.queries {
		for _, a := range msg.Answer {
			if q.q.Name == a.Header().Name && (q.q.Qtype == a.Header().Rrtype || q.q.Qtype == dns.TypeANY) {
				q.answer(a)
			}
		}
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
