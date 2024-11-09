package netscanner

import "fmt"

func DispHelp() {
	fmt.Println(`Usage:
./main <arguments> remoteHost
Arguments:
Scanning options:
	-t S:	TCP SYN scan
	-t A:	TCP ACK scan
Port options:
	-p F:	Fast scan, only top 1000 ports
	-p -:	Full scan, all ports
Interface:
	-i <interfaceName>:	Specify which network interface to use`)
}

func dispResult(openPort []int, filteredPort []int, unfilteredPort []int, closedPort []int) {
	fmt.Println("Results:")

	if len(unfilteredPort) == 0 {
		if (len(openPort) < len(filteredPort) && len(openPort) != 0) || (len(openPort) < 10 && len(openPort) > 0) {
			fmt.Printf("There are %v filtered ports\n", len(filteredPort))
			fmt.Printf("There are %v closed ports\n", len(closedPort))
			fmt.Println("Port\tStatus")
			for _, i := range openPort {
				fmt.Printf("%v\tOpen\n", i)
			}
		} else {
			fmt.Printf("There are %v number of open ports\n", len(openPort))
			fmt.Println("Port\tStatus")
			for _, i := range filteredPort {
				fmt.Printf("%v\tFiltered\n", i)
			}
		}
	}
}
