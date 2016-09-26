package sd

import (
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/akmistry/dnssd/mdns"
)

func Publish(name, service string, ip net.IP, port uint16, txt map[string][]byte) {
	if name == "" || service == "" {
		log.Panicln("name and service must be non-empty", name, service)
	}
	if !strings.HasSuffix(service, ".local.") {
		log.Panicln("Service MUST be in the local. domain", service)
	}

	// Construct A or AAAA record.
	instanceName := name + "." + service
	var rr dns.RR
	if ip4 := ip.To4(); ip4 != nil {
		log.Println("Publishing A record")
		aRr := new(dns.A)
		aRr.Hdr = dns.RR_Header{Name: instanceName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}
		aRr.A = ip4
		rr = aRr
	} else if ip6 := ip.To16(); ip6 != nil {
		log.Println("Publishing AAAA record")
		aaaaRr := new(dns.AAAA)
		aaaaRr.Hdr = dns.RR_Header{Name: instanceName, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600}
		aaaaRr.AAAA = ip6
		rr = aaaaRr
	} else {
		log.Panicln("Invalid IP address", ip)
	}

	// Construct SRV record.
	srvRr := new(dns.SRV)
	srvRr.Hdr = dns.RR_Header{Name: instanceName, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 3600}
	srvRr.Port = port
	srvRr.Target = instanceName

	// Construct PTR record.
	ptrRr := new(dns.PTR)
	ptrRr.Hdr = dns.RR_Header{Name: service, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 3600}
	ptrRr.Ptr = instanceName

	// Validate and construct TXT record.
	txtRr := new(dns.TXT)
	txtRr.Hdr = dns.RR_Header{Name: instanceName, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}
	for k, v := range txt {
		// MUST be at least one character.
		if k == "" {
			log.Panicln("Empty key not allowed in TXT record")
		}
		// MUST be printable US-ASCII (0x20-0x7E), excluding '=' (0x3D).
		for _, r := range k {
			if r == '=' || r < 0x20 || r > 0x7E {
				log.Panicf("Invalid character %d in TXT record key %s", r, k)
			}
		}
		// SHOULD be no more than 9 characters.
		if len(k) > 9 {
			log.Println("Key length longer than recommended (9)", k)
		}
		// "k=v" string MUST be <= 255 bytes.
		l := len(k)
		if len(v) > 0 {
			// '=' can be omitted if v is empty.
			l += 1 + len(v)
		}
		if l > 255 {
			log.Panicf("Key (%s) + value (%v) length > 255 bytes", k, v)
		}

		txtStr := k
		if len(v) > 0 {
			txtStr += "=" + string(v)
		}
		txtRr.Txt = append(txtRr.Txt, txtStr)
	}

	mdns.PublishRR(rr)
	mdns.PublishRR(srvRr)
	mdns.PublishRR(ptrRr)
	mdns.PublishRR(txtRr)
}
