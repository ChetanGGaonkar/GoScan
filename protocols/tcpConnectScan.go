package protocols

import (
	"fmt"
	"net"
	"time"
)

func TcpConScan(laddr, remoteHost string, ports []int) ([]int, []int, []int) {
	var (
		openPort     []int
		filteredPort []int
		closedPort   []int
	)
	for _, p := range ports {
		address := fmt.Sprintf("%v:%d", remoteHost, p)
		conn, err := net.DialTimeout("tcp", address, time.Duration(500*time.Millisecond))
		if err != nil {
			_, err2 := net.DialTimeout("udp:icmp", address, time.Duration(500*time.Millisecond))
			if err2 != nil {
				filteredPort = append(filteredPort, p)
				continue
			}
			closedPort = append(closedPort, p)
		} else {
			openPort = append(openPort, p)
			defer conn.Close()
		}
	}
	return openPort, filteredPort, closedPort
}
