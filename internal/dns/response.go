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

func ParseResponse(response []byte) ([]DNSAnswer, error) {
	if len(response) < 12 {
		return nil, fmt.Errorf("response too short to contain header")
	}

	header := parseHeader(response[:12])
	if header.Flags&0x8000 == 0 {
		return nil, fmt.Errorf("not a response")
	}

	if header.Flags&0x000F != 0 {
		return nil, fmt.Errorf("response contains errors")
	}

	offset := 12
	for i := 0; i < int(header.QDCount); i++ {
		_, newOffset := parseName(response, offset)
		offset = newOffset + 4
	}

	answers := []DNSAnswer{}

	for i := 0; i < int(header.ANCount); i++ {
		name, newOffset := parseName(response, offset)
		offset = newOffset

		answer := DNSAnswer{
			Name: name,
		}

		// Extract type, class, TTL, and data length
		answer.Type = binary.BigEndian.Uint16(response[offset : offset+2])
		answer.Class = binary.BigEndian.Uint16(response[offset+2 : offset+4])
		answer.TTL = binary.BigEndian.Uint32(response[offset+4 : offset+8])
		dataLen := binary.BigEndian.Uint16(response[offset+8 : offset+10])
		offset += 10

		if answer.Type == QTypeA && dataLen == 4 {
			answer.Data = fmt.Sprintf("%d.%d.%d.%d", response[offset], response[offset+1], response[offset+2], response[offset+3])
		} else {
			answer.Data = fmt.Sprintf("unsupported type %d", answer.Type)
		}
		offset += int(dataLen)

		answers = append(answers, answer)
	}

	return answers, nil
}
