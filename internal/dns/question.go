package dns

import (
	"encoding/binary"
	"strings"
)

type DNSQuestion struct {
	QName  string
	QType  uint16
	QClass uint16
}

// convert dns question into a byte slice
func (q *DNSQuestion) Serialize() []byte {
	buf := EncodeQName(q.QName)
	question := make([]byte, 4)
	binary.BigEndian.PutUint16(question[0:2], q.QType)
	binary.BigEndian.PutUint16(question[2:4], q.QClass)
	return append(buf, question...)
}

// encode a domain name to dns format
func EncodeQName(domain string) []byte {
	parts := strings.Split(domain, ".")
	var encoded []byte
	for _, part := range parts {
		encoded = append(encoded, byte(len(part)))
		encoded = append(encoded, part...)
	}
	encoded = append(encoded, 0)
	return encoded
}
