package main

import (
	"fmt"
	// "net"
	"encoding/binary"
	// "log"
	"golang.org/x/sys/unix"
	"bytes"
	"math/rand"
	// "crypto/md5"
)

// const (
// 	CONN_HOST = "10.0.0.1"
// 	CONN_PORT = "1025"
// 	CONN_TYPE = "udp4"
// 	MIN_UDP_SEG_SIZE = 56
// 	MIN_IP_PAYLOAD = 64
// )

func check(e error) {
	if e != nil {
		fmt.Println(e)
		panic(e)
	}
}

type ATTR struct {
	_type  uint8
	length uint8
	value  []byte
}

type COA_REQUEST struct {
	code   uint8
	id     uint8
	length uint16
	auth   [16]byte
	attrs  ATTR
}

type IPHDR struct {
	vhl uint8
	tos uint8
	iplen uint16
	id uint16
	off uint16
	ttl uint8
	proto uint8
	csum uint16
	src [4]byte
	dst [4]byte
}

type pseudo_iphdr struct {
	ipsrc [4]byte
	ipdst [4]byte
	zero uint8
	ipproto uint8
	plen uint16
}

type UDP_HEADER struct {
	sport uint16
	dport uint16
	length uint16
	checksum uint16
}

func NewCOARequest(coa *COA_REQUEST) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, coa.code)
	binary.Write(buf, binary.BigEndian, coa.id)
	binary.Write(buf, binary.BigEndian, coa.length)
	binary.Write(buf, binary.BigEndian, coa.auth)

	binary.Write(buf, binary.BigEndian, coa.attrs._type)
	binary.Write(buf, binary.BigEndian, coa.attrs.length)
	binary.Write(buf, binary.BigEndian, coa.attrs.value)

	return buf.Bytes()
}

func udp_packet(ip *IPHDR, udp *UDP_HEADER, payload []byte) []byte {
	pre_buf := new(bytes.Buffer)
	buf := new(bytes.Buffer)
	var pseudo_buf []byte

	pseudo_hdr := pseudo_iphdr {
		ipsrc: ip.src,
		ipdst: ip.dst,
		zero: 0x0,
		ipproto: unix.IPPROTO_UDP,   // contant value, because func of UDP packet!
		plen: udp.length,
	}
	binary.Write(pre_buf, binary.BigEndian, pseudo_hdr.ipsrc)
	binary.Write(pre_buf, binary.BigEndian, pseudo_hdr.ipdst)
	binary.Write(pre_buf, binary.BigEndian, pseudo_hdr.zero)
	binary.Write(pre_buf, binary.BigEndian, pseudo_hdr.ipproto)
	binary.Write(pre_buf, binary.BigEndian, pseudo_hdr.plen)
	binary.Write(pre_buf, binary.BigEndian, udp.sport)
	binary.Write(pre_buf, binary.BigEndian, udp.dport)
	binary.Write(pre_buf, binary.BigEndian, udp.length)
	binary.Write(pre_buf, binary.BigEndian, udp.checksum)

	for _,val := range pre_buf.Bytes(){
		pseudo_buf = append(pseudo_buf, val)
	}
	for _,val := range payload{
		pseudo_buf = append(pseudo_buf, val)
	}
	for len(pseudo_buf)%2!=0 {
		pseudo_buf = append(pseudo_buf, 0x0)
	}
	udp.checksum = csum(pseudo_buf)
	binary.Write(buf, binary.BigEndian, udp.sport)  //source port
	binary.Write(buf, binary.BigEndian, udp.dport)  //destination port
	binary.Write(buf, binary.BigEndian, udp.length) //length	
	binary.Write(buf, binary.LittleEndian, udp.checksum) //length

	return buf.Bytes()

}

func ip_header (ip *IPHDR) []byte {
	buf := new(bytes.Buffer)
	pseudo_buf := new(bytes.Buffer)

	binary.Write(pseudo_buf, binary.BigEndian, ip.vhl)
	binary.Write(pseudo_buf, binary.BigEndian, ip.tos)
	binary.Write(pseudo_buf, binary.BigEndian, ip.iplen)
	binary.Write(pseudo_buf, binary.BigEndian, ip.id)
	binary.Write(pseudo_buf, binary.BigEndian, ip.off)
	binary.Write(pseudo_buf, binary.BigEndian, ip.ttl)
	binary.Write(pseudo_buf, binary.BigEndian, ip.proto)
	binary.Write(pseudo_buf, binary.BigEndian, ip.src)
	binary.Write(pseudo_buf, binary.BigEndian, ip.dst)
	
	ip.csum = csum(pseudo_buf.Bytes())
	binary.Write(buf, binary.BigEndian, ip.vhl)
	binary.Write(buf, binary.BigEndian, ip.tos)
	binary.Write(buf, binary.BigEndian, ip.iplen)
	binary.Write(buf, binary.BigEndian, ip.id)
	binary.Write(buf, binary.BigEndian, ip.off)
	binary.Write(buf, binary.BigEndian, ip.ttl)
	binary.Write(buf, binary.BigEndian, ip.proto)
	binary.Write(buf, binary.BigEndian, ip.csum)
	binary.Write(buf, binary.BigEndian, ip.src)
	binary.Write(buf, binary.BigEndian, ip.dst)	

	return buf.Bytes()
}

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i < len(b); i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return uint16(^s)
}

func main() {
	payload := make([]byte, 2048)
	udp_pkt := make([]byte, 2048)
	ip_pkt := make([]byte, 2048)

	payload_header := new(COA_REQUEST)
	payload_header.code = 43
	payload_header.id = uint8(rand.Uint32())             // should be random
	payload_header.auth[0] = 0

	payload_header.attrs._type = 1
	payload_header.attrs.value = []byte("78:54:ee:db:00:01")
	payload_header.attrs.length = uint8(len(payload_header.attrs.value) + 2)
	payload_header.length = uint16(payload_header.attrs.length + 20)

    udp := new(UDP_HEADER)
    udp.sport = 3799
    udp.dport = 3799
    udp.length = 8 + payload_header.length
    udp.checksum = 0

	ip := new(IPHDR)
	ip.vhl = 0x45                   // 0x40 means->IPv4, 0x05 means -> 5*4=20bytes, IP header length
	ip.tos = 0
	ip.iplen = udp.length + 20     // 0x05*4=20 bytes
	ip.id = uint16(rand.Uint32())  // should be uniq 
	ip.off = 0
	ip.ttl = 64
	ip.proto = unix.IPPROTO_UDP
	ip.csum = 0x0000               // should be calculated later in the code
	ip.src = [4]byte{192,168,1,0}
	ip.dst = [4]byte{192,168,0,2}

	payload = NewCOARequest(payload_header)
	udp_pkt = udp_packet(ip, udp, payload)
	ip_pkt = ip_header(ip)

	var wire []byte

	for i:=0; i<len(ip_pkt); i++{
		wire = append(wire,ip_pkt[i])
	}
	for i:=0; i<len(udp_pkt); i++{
			wire = append(wire, udp_pkt[i])
	}
	for i:=0; i<len(payload); i++{
			wire = append(wire, payload[i])
	}
	fmt.Println("Total size of IP Packet: ", len(wire))
	// fmt.Printf("wire = %#v\n", wire)

	// Workign code for sending ONLY PAYLOAD in UDP packet.
	// conn, err := net.Dial(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
	// check(err)
	// numSend, err := conn.Write(BS)
	// check (err)
	// if numSend != len(BS){
	// 	log.Fatalf("Sended %d/%d bytes\n", numSend, len(BS))
	// }
	// conn.Close()

	//working code for sending IP/UDP/Payload data
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	check(err)
	err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	addr := unix.SockaddrInet4{ Port: 0, Addr:[4]byte{255,255,255,254}}

	for i:=1; i<=1; i++{
		println(i)
		err = unix.Sendto(fd, wire, 0, &addr)
		check(err)
	}



}

// func handleRequest(conn net.Conn) {
// }