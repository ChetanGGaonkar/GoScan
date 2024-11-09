package netscanner

import (
	protocol "GoScan/protocols"
	"fmt"
	"log"
	"math"
	"net"
	"os"
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
	endIndex := 0
	startIndex := 0

	var wg sync.WaitGroup
	var (
		openPort       = make([]int, 0)
		filteredPort   = make([]int, 0)
		unfilteredPort = make([]int, 0)
		closedPort     = make([]int, 0)
	)

	switch scanType {
	case "S":
		fmt.Println("Doing a TCP SYN scan (Stealth scan)")
		wg.Add(numCpu)
		for i := 0; i < numCpu-1; i++ {
			startIndex += endIndex
			endIndex = endIndex + (len(ports) / numCpu)
			portSlice := ports[startIndex:endIndex]
			go func() {
				open, filtered, closed := protocol.TcpSynScan(laddr, addrs[0], portSlice)
				openPort = append(openPort, open...)
				filteredPort = append(filteredPort, filtered...)
				closedPort = append(closedPort, closed...)
				wg.Done()
			}()
		}
		startIndex += endIndex
		endIndex += (len(ports) / numCpu)
		go func() {
			open, filtered, closed := protocol.TcpSynScan(laddr, addrs[0], ports[startIndex:])
			openPort = append(openPort, open...)
			filteredPort = append(filteredPort, filtered...)
			closedPort = append(closedPort, closed...)
			wg.Done()
		}()
		wg.Wait()
		dispResult(openPort, filteredPort, unfilteredPort, closedPort)

	case "A":
		fmt.Println("Doing a TCP Ack scan")
		for i := 0; i < numCpu-1; i++ {
			endIndex += (len(ports) / numCpu)
			go protocol.TcpAckScan(laddr, addrs[0], ports[startIndex:endIndex])
			startIndex = endIndex + 1
			wg.Add(1)
		}
		go protocol.TcpAckScan(laddr, addrs[0], ports[startIndex:])
		wg.Add(1)
		wg.Wait()

	case "T":
		fmt.Println("Doing TCP Connect scan")
		wg.Add(numCpu)
		for i := 0; i < numCpu-1; i++ {
			startIndex += endIndex
			endIndex = endIndex + (len(ports) / numCpu)
			portSlice := ports[startIndex:endIndex]
			go func() {
				open, filtered, closed := protocol.TcpConScan(laddr, rHost, portSlice)
				openPort = append(openPort, open...)
				closedPort = append(closedPort, closed...)
				filteredPort = append(filteredPort, filtered...)
				wg.Done()
			}()
		}
		startIndex += endIndex
		endIndex += (len(ports) / numCpu)
		go func() {
			open, closed, filtered := protocol.TcpConScan(laddr, rHost, ports[startIndex:])
			openPort = append(openPort, open...)
			closedPort = append(closedPort, closed...)
			filteredPort = append(filteredPort, filtered...)
			wg.Done()
		}()
		wg.Wait()
		dispResult(openPort, filteredPort, unfilteredPort, closedPort)

	default:
		fmt.Println("Invalid scan option!!!")
		os.Exit(1)
	}
}
