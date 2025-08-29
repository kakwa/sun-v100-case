package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// EtherType values
const (
	ETH_P_RARP = 0x8035 // Reverse ARP
	ETH_P_IP   = 0x0800
)

// ARP / RARP opcodes
const (
	ARP_REQUEST      = 1
	ARP_REPLY        = 2
	RARP_REQUEST     = 3
	RARP_REPLY       = 4
)

// Ethernet header is 14 bytes
// dst(6) | src(6) | ethertype(2)
type EthHdr struct {
	Dst  [6]byte
	Src  [6]byte
	Type uint16
}

// ARP payload per RFC 826/903 (network byte order)
// hrd(2) pro(2) hln(1) pln(1) op(2) sha(6) spa(4) tha(6) tpa(4)
// For our use: hrd=1 (Ethernet), pro=0x0800 (IPv4), hln=6, pln=4

type RarpPacket struct {
	HType  uint16 // hardware type
	PType  uint16 // protocol type
	HLEN   uint8  // hardware length
	PLEN   uint8  // protocol length
	Oper   uint16 // opcode
	SHA    [6]byte
	SPA    [4]byte
	THA    [6]byte
	TPA    [4]byte
}

func htons(i uint16) uint16 { return (i<<8)&0xff00 | i>>8 }

func parseMapping(s string) (map[[6]byte][4]byte, error) {
	m := make(map[[6]byte][4]byte)
	if s == "" {
		return m, nil
	}
	pairs := strings.Split(s, ",")
	for _, p := range pairs {
		p = strings.TrimSpace(p)
		if p == "" { continue }
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid mapping entry: %q (want mac=ipv4)", p)
		}
		macStr := strings.TrimSpace(kv[0])
		ipStr := strings.TrimSpace(kv[1])
		mac, err := net.ParseMAC(macStr)
		if err != nil {
			return nil, fmt.Errorf("parse MAC %q: %w", macStr, err)
		}
		ip := net.ParseIP(ipStr).To4()
		if ip == nil {
			return nil, fmt.Errorf("parse IPv4 %q: invalid", ipStr)
		}
		var mac6 [6]byte
		copy(mac6[:], mac[:6])
		var ip4 [4]byte
		copy(ip4[:], ip[:4])
		m[mac6] = ip4
	}
	return m, nil
}

func ifaceByName(name string) (*net.Interface, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil { return nil, err }
	if (ifc.Flags & net.FlagUp) == 0 { return nil, fmt.Errorf("interface %s is down", name) }
	if ifc.HardwareAddr == nil || len(ifc.HardwareAddr) != 6 { return nil, fmt.Errorf("interface %s has no 6-byte MAC", name) }
	return ifc, nil
}

func firstIPv4Addr(name string) (net.IP, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil { return nil, err }
	addrs, err := ifc.Addrs()
	if err != nil { return nil, err }
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			ip := v.IP.To4()
			if ip != nil { return ip, nil }
		}
	}
	return nil, errors.New("no IPv4 on interface")
}

func openRawSocket(ifc *net.Interface) (int, error) {
	// AF_PACKET/SOCK_RAW for Ethernet frames on Linux
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ETH_P_RARP)))
	if err != nil { return -1, fmt.Errorf("socket: %w", err) }

	// Bind to device + protocol
	ll := &unix.SockaddrLinklayer{Protocol: htons(ETH_P_RARP), Ifindex: ifc.Index}
	if err := unix.Bind(fd, ll); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("bind: %w", err)
	}
	return fd, nil
}

func macToArray(mac net.HardwareAddr) (out [6]byte) { copy(out[:], mac[:6]); return }
func ipToArray(ip net.IP) (out [4]byte)             { copy(out[:], ip.To4()[:4]); return }

func buildRarpReply(serverMAC net.HardwareAddr, serverIP net.IP, targetMAC net.HardwareAddr, targetIP net.IP) ([]byte, error) {
	var eth EthHdr
	copy(eth.Dst[:], targetMAC[:6])
	copy(eth.Src[:], serverMAC[:6])
	eth.Type = htons(ETH_P_RARP)

	var pkt RarpPacket
	pkt.HType = htons(1)                 // Ethernet
	pkt.PType = htons(ETH_P_IP)          // IPv4
	pkt.HLEN = 6
	pkt.PLEN = 4
	pkt.Oper = htons(RARP_REPLY)
	pkt.SHA = macToArray(serverMAC)
	pkt.SPA = ipToArray(serverIP)
	pkt.THA = macToArray(targetMAC)
	pkt.TPA = ipToArray(targetIP)

	buf := make([]byte, 14+28)
	binary.BigEndian.PutUint16(buf[12:14], eth.Type)
	copy(buf[0:6], eth.Dst[:])
	copy(buf[6:12], eth.Src[:])

	o := 14
	binary.BigEndian.PutUint16(buf[o:o+2], pkt.HType); o += 2
	binary.BigEndian.PutUint16(buf[o:o+2], pkt.PType); o += 2
	buf[o] = pkt.HLEN; o++
	buf[o] = pkt.PLEN; o++
	binary.BigEndian.PutUint16(buf[o:o+2], pkt.Oper); o += 2
	copy(buf[o:o+6], pkt.SHA[:]); o += 6
	copy(buf[o:o+4], pkt.SPA[:]); o += 4
	copy(buf[o:o+6], pkt.THA[:]); o += 6
	copy(buf[o:o+4], pkt.TPA[:]); o += 4

	return buf, nil
}

func parseIncomingRarp(b []byte) (EthHdr, RarpPacket, error) {
	var eth EthHdr
	var pkt RarpPacket
	if len(b) < 14+28 {
		return eth, pkt, fmt.Errorf("frame too short: %d", len(b))
	}
	copy(eth.Dst[:], b[0:6])
	copy(eth.Src[:], b[6:12])
	eth.Type = binary.BigEndian.Uint16(b[12:14])
	if eth.Type != htons(ETH_P_RARP) {
		return eth, pkt, fmt.Errorf("not RARP ethertype: 0x%04x", eth.Type)
	}
	o := 14
	pkt.HType = binary.BigEndian.Uint16(b[o : o+2]); o += 2
	pkt.PType = binary.BigEndian.Uint16(b[o : o+2]); o += 2
	pkt.HLEN = b[o]; o++
	pkt.PLEN = b[o]; o++
	pkt.Oper = binary.BigEndian.Uint16(b[o : o+2]); o += 2
	copy(pkt.SHA[:], b[o:o+6]); o += 6
	copy(pkt.SPA[:], b[o:o+4]); o += 4
	copy(pkt.THA[:], b[o:o+6]); o += 6
	copy(pkt.TPA[:], b[o:o+4]); o += 4
	return eth, pkt, nil
}

func main() {
	iface := flag.String("i", "eth0", "interface to bind (Linux only)")
	mapping := flag.String("map", "", "comma-separated MAC=IPv4 mappings (e.g. 52:54:00:12:34:56=192.168.1.10,aa:bb:cc:dd:ee:ff=192.168.1.11)")
	verbose := flag.Bool("v", false, "verbose logging")
	flag.Parse()

	ifc, err := ifaceByName(*iface)
	if err != nil { log.Fatalf("%v", err) }

	serverIP, err := firstIPv4Addr(*iface)
	if err != nil { log.Fatalf("%v", err) }

	macToIP, err := parseMapping(*mapping)
	if err != nil { log.Fatalf("%v", err) }

	fd, err := openRawSocket(ifc)
	if err != nil { log.Fatalf("%v", err) }
	defer unix.Close(fd)

	log.Printf("RARP server on %s (MAC %s, IP %s) listening for requests...", ifc.Name, ifc.HardwareAddr, serverIP)

	reader := bufio.NewReader(os.NewFile(uintptr(fd), fmt.Sprintf("fd%d", fd)))
	for {
		// Read a single Ethernet frame (up to MTU; 1518 is safe default)
		buf := make([]byte, 2048)
		n, err := reader.Read(buf)
		if err != nil {
			log.Fatalf("read: %v", err)
		}
		frame := buf[:n]
		eth, pkt, err := parseIncomingRarp(frame)
		if err != nil {
			// not RARP or malformed; skip silently unless verbose
			if *verbose { log.Printf("skip frame: %v", err) }
			continue
		}

		// Only handle RARP requests
		if pkt.Oper != htons(RARP_REQUEST) {
			if *verbose { log.Printf("ignore opcode %d", pkt.Oper) }
			continue
		}

		// Target MAC is who is asking for its IP
		var targetMAC [6]byte = pkt.THA
		ip4, ok := macToIP[targetMAC]
		if !ok {
			if *verbose { log.Printf("no mapping for %02x:%02x:%02x:%02x:%02x:%02x", targetMAC[0], targetMAC[1], targetMAC[2], targetMAC[3], targetMAC[4], targetMAC[5]) }
			continue
		}

		reply, err := buildRarpReply(ifc.HardwareAddr, serverIP, net.HardwareAddr(pkt.THA[:]), net.IP(ip4[:]))
		if err != nil { log.Printf("build reply: %v", err); continue }

		// Send using sendto() with SockaddrLinklayer (dst MAC is in frame)
		ll := &unix.SockaddrLinklayer{Ifindex: ifc.Index}
		if err := unix.Sendto(fd, reply, 0, ll); err != nil {
			log.Printf("sendto: %v", err)
			continue
		}

		if *verbose {
			log.Printf("answered RARP for %02x:%02x:%02x:%02x:%02x:%02x -> %d.%d.%d.%d",
				pkt.THA[0], pkt.THA[1], pkt.THA[2], pkt.THA[3], pkt.THA[4], pkt.THA[5],
				ip4[0], ip4[1], ip4[2], ip4[3],
			)
		}
	}
}
