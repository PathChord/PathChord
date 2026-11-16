package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
)

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Println(listener.Addr().String())
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("test-user:test-password")) {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		mode := os.Getenv("PATHCHORD_HTTP_PEER_MODE")
		if (mode == "path" && r.RequestURI != "/token/part%3Fx=1") || (mode == "host" && r.RequestURI != "target.test:443") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		connection, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			panic(err)
		}
		defer connection.Close()
		_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffer.Flush()
		_, _ = io.Copy(connection, buffer)
	})}
	_ = server.Serve(listener)
}
