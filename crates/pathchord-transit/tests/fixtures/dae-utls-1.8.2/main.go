package main

import (
	utls "github.com/refraction-networking/utls"
	"os"
)

func main() {
	for _, profile := range []struct {
		name string
		id   utls.ClientHelloID
	}{
		{"chrome", utls.HelloChrome_Auto},
		{"ios", utls.HelloIOS_Auto},
		{"edge", utls.HelloEdge_Auto},
		{"qq", utls.HelloQQ_Auto},
		{"firefox", utls.HelloFirefox_Auto},
		{"android", utls.HelloAndroid_11_OkHttp},
		{"360", utls.Hello360_Auto},
	} {
		client := utls.UClient(nil, &utls.Config{ServerName: "tls.pathchord.test", SessionTicketsDisabled: true}, profile.id)
		if err := client.BuildHandshakeState(); err != nil {
			panic(err)
		}
		if err := os.WriteFile(profile.name+".bin", client.HandshakeState.Hello.Raw, 0600); err != nil {
			panic(err)
		}
	}
}
