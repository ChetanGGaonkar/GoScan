package netscanner

import (
	protocol "GoScan/protocols"
	"fmt"
	"log"
	"math"
	"net"
	"runtime"
	"sync"
)

func ScanSelect(laddr, rHost, scanType, port string) {
	if scanType == "" {
		scanType = "S"
	}

	addrs, err := net.LookupHost(rHost)
	if err != nil {
		log.Fatalf("Error resolving %s\n", rHost)
	}
	//generate port array
	ports := PortGen(port)

	numCpu := int(math.Ceil(float64(runtime.NumCPU()) / 2))
	var wg sync.WaitGroup
	endIndex := 0
	startIndex := 0

	switch scanType {
	case "S":
		fmt.Println("Doing a TCP SYN scan (Stealth scan)")
		for i := 0; i < numCpu-1; i++ {
			endIndex += (len(ports) / numCpu)
			go protocol.TcpSynScan(laddr, addrs[0], ports[startIndex:endIndex])
			startIndex = endIndex + 1
			wg.Add(1)
		}
		go protocol.TcpSynScan(laddr, addrs[0], ports[startIndex:])
		wg.Add(1)
		wg.Wait()
	}
}
