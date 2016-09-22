package main

import (
	"log"

	"github.com/akmistry/dnssd/mdns"
)

func main() {
	log.Println("========================================================")

	mdns.Publish("fooooo.local. 3600 A 10.10.10.10")

	r := mdns.Query("_http._tcp.local.")
	rr := <-r.Chan
	log.Print(rr)
	r.Done()
}
