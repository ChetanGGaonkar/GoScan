package netscanner

import (
	protocol "GoScan/protocols"
	"fmt"
)

func ScanSelect(rHost, laddr, scanType, port string) {
	if scanType == "" {
		scanType = "S"
	}

	//generate port array
	ports := PortGen(port)

	switch scanType {
	case "S":
		fmt.Println("Doing a TCP SYN scan (Stealth scan)")
		protocol.TcpSynScan(rHost, laddr, ports)
	}
}
