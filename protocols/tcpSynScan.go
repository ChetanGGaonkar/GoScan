package protocols

import (
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"time"
)

func TcpSynScan(laddr, remoteAddr string, ports []int) {

	for _, p := range ports {
		var status string
		srcPort := uint16(9000)
		sendSyn(laddr, remoteAddr, srcPort, uint16(p))

		statusValue := receiveSynAck(laddr, remoteAddr)

		if statusValue == 1 {
			status = "Open"
		} else if statusValue == 2 {
			status = "Closed"
		} else {
			sendSyn(laddr, remoteAddr, srcPort, uint16(p))
			if statusValue := receiveSynAck(laddr, remoteAddr); statusValue == -1 {
				status = "Filtered"
			} else if statusValue == 1 {
				status = "Open"
			} else {
				status = "Closed"
			}
		}
		time.Sleep(100 * time.Millisecond)
		fmt.Printf("Port %d status: %s\n", p, status)
	}
}

func sendSyn(laddr, raddr string, srcPort, dstPort uint16) {
	//create a tcp header with the said src and dst ports
	packet := TCPHeader{
		Source:      srcPort,
		Destination: dstPort,
		SeqNum:      rand.Uint32(),
		AckNum:      0,
		DataOffset:  5,      // 4 bits
		Reserved:    0,      // 3 bits
		ECN:         0,      // 3 bits
		Ctrl:        2,      // 6 bits (000010, SYN bit set)
		Window:      0xaaaa, // The amount of data that it is able to accept in bytes
		Checksum:    0,      // Kernel will set this if it's 0
		Urgent:      0,
		Options:     []TCPOption{},
	}
	//create data packet
	data := packet.Marshal()
	packet.Checksum = Csum(data, to4byte(laddr), to4byte(raddr))
	data = packet.Marshal()

	//pass the data packet to the remote host address
	conn, err := net.Dial("ip4:tcp", raddr)
	if err != nil {
		log.Fatalf("Dial: %s\n", err)
	}
	defer conn.Close()

	numWrote, err := conn.Write(data)
	if err != nil {
		log.Fatalf("Write: %s\n", err)
	}
	if numWrote != len(data) {
		log.Fatalf("Short write. Wrote %d/%d bytes\n", numWrote, len(data))
	}

}

func to4byte(addr string) [4]byte {
	parts := strings.Split(addr, ".")
	b0, err := strconv.Atoi(parts[0])
	if err != nil {
		log.Fatalf("to4byte: %s (latency works with IPv4 addresses only, but not IPv6!)\n", err)
	}
	b1, _ := strconv.Atoi(parts[1])
	b2, _ := strconv.Atoi(parts[2])
	b3, _ := strconv.Atoi(parts[3])
	return [4]byte{byte(b0), byte(b1), byte(b2), byte(b3)}
}

func receiveSynAck(localAddress, remoteAddress string) int {

	netaddr, err := net.ResolveIPAddr("ip4", localAddress)
	if err != nil {
		log.Fatalf("net.ResolveIPAddr: %s. %s\n", localAddress, netaddr)
	}

	conn, err := net.ListenIP("ip4:tcp", netaddr)
	if err != nil {
		log.Fatalf("ListenIP: %s\n", err)
	}
	timeout := conn.SetDeadline(time.Now().Add(1000 * time.Millisecond))
	buf := make([]byte, 1024)
	for {
		if timeout == nil {
			numRead, raddr, err := conn.ReadFrom(buf)
			if err != nil {
				return -1
			}
			if raddr.String() == remoteAddress {

				tcp := NewTCPHeader(buf[:numRead])
				// Closed port gets RST, open port gets SYN ACK
				if tcp.HasFlag(RST) {
					return 2
				} else if tcp.HasFlag(SYN) && tcp.HasFlag(ACK) {
					return 1
				}
			}
		}
	}
}
