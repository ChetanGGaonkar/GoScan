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
