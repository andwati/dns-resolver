package network

import (
	"net"
	"time"
)

func SendDNSQuery(query []byte, server string) ([]byte, error) {
	conn, err := net.Dial("udp", server)
	if err != nil {
		return nil, err
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {

		}
	}(conn)

	err = conn.SetDeadline(time.Now().Add(DefaultTimeout))
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	return response[:n], nil
}
