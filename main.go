package main

import (
	"flag"
	"log"

	"github.com/akmistry/dnssd/mdns"
)

var (
	query      = flag.String("query", "", "Record name to query.")
	numRecords = flag.Int("num", 0, "Number of records to wait for. 0 for infinite.")
	publish    = flag.String("publish", "", "RR string to publish (i.e. \"foo.local. 3600 A 1.2.3.4\").")
)

func main() {
	flag.Parse()

	if *publish != "" {
		mdns.Publish(*publish)
	}

	if *query != "" {
		r := mdns.Query(*query)
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

	if *publish != "" {
		select {}
	}
}
