package dns

type DNSMessage struct {
	Header   DNSHeader
	Question DNSQuestion
}

// convert dns message into a byte slice
func (m *DNSMessage) Serialize() []byte {
	header := m.Header.Serialize()
	question := m.Question.Serialize()
	return append(header, question...)
}
