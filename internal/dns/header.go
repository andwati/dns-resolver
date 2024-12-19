package dns

import (
	"crypto/rand"
	"encoding/binary"
	"log"
)

type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Serialize converts the DNSHeader into a byte slice
func (h *DNSHeader) Serialize() []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], h.ID)
	binary.BigEndian.PutUint16(buf[2:4], h.Flags)
	binary.BigEndian.PutUint16(buf[4:6], h.QDCount)
	binary.BigEndian.PutUint16(buf[6:8], h.ARCount)
	binary.BigEndian.PutUint16(buf[8:10], h.NSCount)
	binary.BigEndian.PutUint16(buf[10:12], h.ARCount)
	return buf
}

// genertae a random 16bit identifier
func GenerateRandomID() uint16 {
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		log.Fatalf("Failed to generate random ID: %v", err)
	}
	return binary.BigEndian.Uint16(id[:])
}
