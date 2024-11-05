package main

import (
	nS "GoScan/netScanner"
	"flag"
	"fmt"
	"os"
	"strings"
)

var (
	ifaceParam    = flag.String("i", "", "Interface (e.g. eth0, wlan1, etc)")
	helpParam     = flag.Bool("h", false, "Display help")
	scanTypeParam = flag.String("s", "", "Choose port scan type")
	portParam     = flag.String("p", "", "Select what ports to do the scan on (use -p 80-100) or use F or -")
)

func main() {
	flag.Parse()

	//print help
	if *helpParam {
		nS.DispHelp()
		os.Exit(1)
	}

	//check if remote address is specified
	if len(flag.Args()) == 0 {
		fmt.Println("Missing remote address")
		os.Exit(1)
	}
	remoteHost := flag.Arg(0)

	//if interface specified, select the interface, else choose default interface
	iface := *ifaceParam
	if iface == "" {
		iface = nS.ChooseInterface()
		if iface == "" {
			fmt.Println("Could not decide which net interface to use.")
			fmt.Println("Specify it with -i <iface> param")
			os.Exit(1)
		}
	}

	//get the ip address of the interface selected
	localAddr := nS.InterfaceAddress(iface)
	laddr := strings.Split(localAddr.String(), "/")[0]

	nS.ScanSelect(laddr, remoteHost, *scanTypeParam, *portParam)
}
