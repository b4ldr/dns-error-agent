package agent

import (
	"net"
	"strconv"
	"strings"
)

func isUDP(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	return strings.HasPrefix(strings.ToLower(addr.Network()), "udp")
}

func remote(addr net.Addr) (string, int) {
	if addr == nil {
		return "", 0
	}
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String(), 0
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil {
		parsedPort = 0
	}
	return host, parsedPort
}
