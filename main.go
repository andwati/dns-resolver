package main

type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type DNSQuestion struct {
	QName  string
	QType  uint16
	QClass uint16
}

type DNSRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

type DNSMessage struct {
	Header      DNSHeader
	Question    []DNSQuestion
	Answers     []DNSRecord
	Authorities []DNSRecord
	Additionals []DNSRecord
}
