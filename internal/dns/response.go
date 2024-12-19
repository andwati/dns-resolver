package dns

import (
	"encoding/binary"
	"fmt"
)

type DNSAnswer struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  string
}

func parseHeader(data []byte) DNSHeader {
	return DNSHeader{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		Flags:   binary.BigEndian.Uint16(data[2:4]),
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: binary.BigEndian.Uint16(data[6:8]),
		NSCount: binary.BigEndian.Uint16(data[8:10]),
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}
}

func parseName(data []byte, offset int) (string, int) {
	name := ""
	for {
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}

		if length&0xc0 == 0xc0 {
			pointer := binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FF
			offset = offset + 2
			partial, _ := parseName(data, int(pointer))
			return name + partial, offset
		}

		offset++
		name += string(data[offset:offset+length]) + "."
		offset += length
	}

	return name[:len(name)-1], offset
}

func ParseFullResponse(response []byte) ([]DNSAnswer, []DNSAnswer, []DNSAnswer, error) {
	if len(response) < 12 {
		return nil, nil, nil, fmt.Errorf("response too short to contain header")
	}

	header := parseHeader(response[:12])
	if header.Flags&0x8000 == 0 { // Check QR bit
		return nil, nil, nil, fmt.Errorf("not a response")
	}

	offset := 12

	for i := 0; i < int(header.QDCount); i++ {
		_, newOffset := parseName(response, offset)
		offset = newOffset + 4
	}

	answers := []DNSAnswer{}
	for i := 0; i < int(header.ANCount); i++ {
		answer, newOffset := parseResourceRecord(response, offset)
		answers = append(answers, answer)
		offset = newOffset
	}
	authorities := []DNSAnswer{}
	for i := 0; i < int(header.NSCount); i++ {
		authority, newOffset := parseResourceRecord(response, offset)
		authorities = append(authorities, authority)
		offset = newOffset
	}

	additionals := []DNSAnswer{}
	for i := 0; i < int(header.ARCount); i++ {
		additional, newOffset := parseResourceRecord(response, offset)
		additionals = append(additionals, additional)
		offset = newOffset
	}

	return answers, authorities, additionals, nil
}

func parseResourceRecord(data []byte, offset int) (DNSAnswer, int) {
	name, newOffset := parseName(data, offset)
	offset = newOffset

	answer := DNSAnswer{
		Name:  name,
		Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
		Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
		TTL:   binary.BigEndian.Uint32(data[offset+4 : offset+8]),
	}
	dataLen := binary.BigEndian.Uint16(data[offset+8 : offset+10])
	offset += 10

	if answer.Type == QTypeA && dataLen == 4 {
		answer.Data = fmt.Sprintf("%d.%d.%d.%d", data[offset], data[offset+1], data[offset+2], data[offset+3])
	} else if answer.Type == QTypeCNAME || answer.Type == QTypeNS {
		answer.Data, _ = parseName(data, offset)
	}
	offset += int(dataLen)

	return answer, offset
}
