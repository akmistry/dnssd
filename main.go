package main

import (
	"flag"
	"log"

	"github.com/miekg/dns"

	"github.com/akmistry/dnssd/mdns"
	"github.com/akmistry/dnssd/sd"
)

var (
	query      = flag.String("query", "", "Record name to query.")
	service    = flag.String("service", "", "Service name to query.")
	numRecords = flag.Int("num", 0, "Number of records to wait for. 0 for infinite.")
	publish    = flag.String("publish", "", "RR string to publish (i.e. \"foo.local. 3600 A 1.2.3.4\").")
)

func main() {
	flag.Parse()

	if *publish != "" {
		mdns.Publish(*publish)
	}

	if *query != "" {
		r := mdns.NewQuery(*query, dns.TypeANY, &mdns.QueryOpts{Continuous: true})
		i := 0
		for rr := range r.Chan {
			log.Println(rr)
			i++
			if *numRecords != 0 && i >= *numRecords {
				r.Done()
				break
			}
		}
	}

	if *service != "" {
		q := sd.Discover(*service)
		i := 0
		for s := range q.Chan {
			log.Println(s)
			i++
			if *numRecords != 0 && i >= *numRecords {
				q.Done()
				break
			}
		}
	}

	if *publish != "" {
		select {}
	}
}
