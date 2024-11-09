package protocols

import (
	"fmt"
	"time"
)

func TcpAckScan(laddr, remoteAddr string, ports []int) {

	for _, p := range ports {
		var status string
		srcPort := uint16(9000)
		dstPort := uint16(p)
		sendPacket(laddr, remoteAddr, srcPort, dstPort, uint8(16))
		var statusValue int = receivePacket(laddr, remoteAddr)
		time.Sleep(100 * time.Millisecond)
		if statusValue == 2 {
			status = "Unfiltered"
		} else {
			status = "Filtered"
		}
		fmt.Printf("Port %d status: %s\n", p, status)
	}
}
