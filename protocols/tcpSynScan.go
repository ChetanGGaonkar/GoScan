package protocols

import "sync"

func TcpSynScan(laddr, remoteAddr string, ports []int) ([]int, []int, []int) {
	var (
		openPort     []int
		filteredPort []int
		closedPort   []int
	)

	for _, p := range ports {
		srcPort := uint16(9000)
		dstPort := uint16(p)
		sendPacket(laddr, remoteAddr, srcPort, dstPort, uint8(2))
		var statusValue int
		var wg sync.WaitGroup
		go func() {
			statusValue = receivePacket(laddr, remoteAddr)
			wg.Add(1)
		}()
		wg.Wait()

		if statusValue == 1 {
			openPort = append(openPort, p)
			sendPacket(laddr, remoteAddr, srcPort, dstPort, uint8(4))
		} else if statusValue == 2 {
			closedPort = append(closedPort, p)
		} else {
			sendPacket(laddr, remoteAddr, srcPort, dstPort, uint8(2))
			if statusValue := receivePacket(laddr, remoteAddr); statusValue == -1 {
				filteredPort = append(filteredPort, p)
			} else if statusValue == 1 {
				openPort = append(openPort, p)
				sendPacket(laddr, remoteAddr, srcPort, dstPort, uint8(4))
			} else if statusValue == 2 {
				closedPort = append(closedPort, p)
			}
		}
	}
	return openPort, filteredPort, closedPort
}
