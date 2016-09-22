package main

import (
	"log"

	"github.com/akmistry/dnssd/mdns"
)

func main() {
	log.Println("========================================================")

	mdns.Publish("fooooo.local. 3600 A 10.10.10.10")

	select {}
}
