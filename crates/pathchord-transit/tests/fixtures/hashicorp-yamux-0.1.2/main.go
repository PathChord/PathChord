// Independent test peer. Build locally and set PATHCHORD_TEST_GO_YAMUX_SERVER.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/hashicorp/yamux"
)

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(2)
	}
	defer listener.Close()
	fmt.Println(listener.Addr().String())
	conn, err := listener.Accept()
	if err != nil {
		os.Exit(3)
	}
	config := yamux.DefaultConfig()
	config.LogOutput = io.Discard
	config.StreamCloseTimeout = 5 * time.Second
	config.StreamOpenTimeout = 5 * time.Second
	session, err := yamux.Server(conn, config)
	if err != nil {
		os.Exit(4)
	}
	stream, err := session.Accept()
	if err != nil {
		os.Exit(5)
	}
	if _, err = io.Copy(stream, stream); err != nil {
		os.Exit(6)
	}
	if err = stream.Close(); err != nil {
		os.Exit(7)
	}
	<-session.CloseChan()
}
