package main

import (
	"fmt"
	"github.com/andwati/dns-resolver/internal/dns"
	"github.com/andwati/dns-resolver/internal/network"
	"log"
)

func main() {
	domain := "dns.google.com"

	rootServer := "198.41.0.4:53"
	ip, err := resolve(domain, rootServer)
	if err != nil {
		log.Fatalf("Failed to resolve %s: %v", domain, err)
	}

	fmt.Printf("Resolved %s to IP: %s\n", domain, ip)
}

func resolve(domain, nameServer string) (string, error) {
	for {
		fmt.Printf("Querying %s for %s\n", nameServer, domain)

		header := dns.DNSHeader{
			ID:      dns.GenerateRandomID(),
			Flags:   0,
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
		query := message.Serialize()

		response, err := network.SendDNSQuery(query, nameServer)
		if err != nil {
			return "", fmt.Errorf("failed to send query: %w", err)
		}

		answers, authorities, additionals, err := dns.ParseFullResponse(response)
		if err != nil {
			return "", fmt.Errorf("failed to parse response: %w", err)
		}

		for _, answer := range answers {
			if answer.Type == dns.QTypeA {
				return answer.Data, nil
			}
			if answer.Type == dns.QTypeCNAME {
				domain = answer.Data
			}
		}

		var nextNameServer string
		for _, additional := range additionals {
			if additional.Type == dns.QTypeA {
				nextNameServer = additional.Data
				break
			}
		}

		if nextNameServer == "" && len(authorities) > 0 {
			for _, authority := range authorities {
				if authority.Type == dns.QTypeNS {
					ns := authority.Data
					nextNameServer, err = resolve(ns, "198.41.0.4:53") // Use root server for NS IP
					if err == nil {
						break
					}
				}
			}
		}

		if nextNameServer == "" {
			return "", fmt.Errorf("could not find next name server")
		}

		nameServer = nextNameServer + ":53"
	}
}
