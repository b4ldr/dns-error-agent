package agent

import (
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

func hasDNSCookie(msg *dns.Msg) bool {
	opt := msg.IsEdns0()
	if opt == nil {
		return false
	}
	for _, option := range opt.Option {
		if option.Option() == dns.EDNS0COOKIE {
			return true
		}
	}
	return false
}

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
