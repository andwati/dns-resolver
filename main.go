package main

import (
	"fmt"
	"github.com/andwati/dns-resolver/internal/dns"
	"github.com/andwati/dns-resolver/internal/network"
	"log"
)

func main() {
	domain := "dns.google.com"

	header := dns.DNSHeader{
		ID:      dns.GenerateRandomID(),
		Flags:   0x0100,
		QDCount: 1,
	}

	question := dns.DNSQuestion{
		QName:  domain,
		QType:  dns.QTypeA,
		QClass: dns.QClassIN,
	}

	message := dns.DNSMessage{
		Header:   header,
		Question: question,
	}

	serializedMessage := message.Serialize()

	response, err := network.SendDNSQuery(serializedMessage, network.DefaultServer)

	if err != nil {
		log.Fatalf("Error sending DNS query: %s", err)
	}

	fmt.Printf("DNS Response: %x\n", response)

	answers, err := dns.ParseResponse(response)
	if err != nil {
		log.Fatalf("Error parsing response: %s", err)
	}

	for _, answer := range answers {
		fmt.Printf("Name: %s, Type: %d, Class: %d, TTL: %d, Data: %s\n",
			answer.Name, answer.Type, answer.Class, answer.TTL, answer.Data)
	}

}
