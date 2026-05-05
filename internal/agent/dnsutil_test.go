package agent

import (
	"net"
	"testing"
)

type testAddr struct {
	network string
	value   string
}

func (a testAddr) Network() string { return a.network }
func (a testAddr) String() string  { return a.value }

func TestIsUDP(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want bool
	}{
		{name: "nil addr", addr: nil, want: false},
		{name: "udp", addr: testAddr{network: "udp", value: "127.0.0.1:53"}, want: true},
		{name: "udp4", addr: testAddr{network: "udp4", value: "127.0.0.1:53"}, want: true},
		{name: "tcp", addr: testAddr{network: "tcp", value: "127.0.0.1:53"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isUDP(tt.addr); got != tt.want {
				t.Fatalf("isUDP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRemote(t *testing.T) {
	tests := []struct {
		name     string
		addr     net.Addr
		wantHost string
		wantPort int
	}{
		{name: "nil addr", addr: nil, wantHost: "", wantPort: 0},
		{name: "ipv4", addr: testAddr{network: "tcp", value: "192.0.2.10:5300"}, wantHost: "192.0.2.10", wantPort: 5300},
		{name: "ipv6", addr: testAddr{network: "tcp", value: "[2001:db8::1]:8053"}, wantHost: "2001:db8::1", wantPort: 8053},
		{name: "missing port", addr: testAddr{network: "udp", value: "192.0.2.10"}, wantHost: "192.0.2.10", wantPort: 0},
		{name: "invalid port", addr: testAddr{network: "udp", value: "192.0.2.10:notnum"}, wantHost: "192.0.2.10", wantPort: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port := remote(tt.addr)
			if host != tt.wantHost || port != tt.wantPort {
				t.Fatalf("remote() = (%q, %d), want (%q, %d)", host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}
