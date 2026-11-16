// Independent sing-quic Gecko relay for local interoperability tests only.
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/sagernet/sing-quic/hysteria2"
)

func main() {
	if len(os.Args) != 4 {
		panic("expected backend address, minimum and maximum packet size")
	}
	min, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(err)
	}
	max, err := strconv.Atoi(os.Args[3])
	if err != nil {
		panic(err)
	}
	outer, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer outer.Close()
	gecko := hysteria2.NewGeckoConn(outer, []byte("pathchord-obfuscation"), min, max)
	backend, err := net.Dial("udp", os.Args[1])
	if err != nil {
		panic(err)
	}
	defer backend.Close()
	fmt.Println(outer.LocalAddr())

	var lock sync.Mutex
	var client net.Addr
	go func() {
		packet := make([]byte, 65535)
		for {
			n, err := backend.Read(packet)
			if err != nil {
				return
			}
			lock.Lock()
			address := client
			lock.Unlock()
			if address != nil {
				_, _ = gecko.WriteTo(packet[:n], address)
			}
		}
	}()
	packet := make([]byte, 65535)
	for {
		n, address, err := gecko.ReadFrom(packet)
		if err != nil {
			return
		}
		lock.Lock()
		client = address
		lock.Unlock()
		if _, err := backend.Write(packet[:n]); err != nil {
			return
		}
	}
}
