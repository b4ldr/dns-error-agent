package agent

import "time"

// Runtime mode constants.
const (
	ModeDNS    = "dns"
	ModeDNSTap = "dnstap"
)

// DNSTap network constants.
const (
	DNSTapNetworkUnix = "unix"
	DNSTapNetworkTCP  = "tcp"
)

type Config struct {
	// General
	Mode      string
	Verbosity int

	// DNS mode
	AgentDomain string
	UDPAddr     string
	TCPAddr     string
	TXTResponse string

	// DNSTap mode
	DNSTapNetwork string
	DNSTapAddress string
	DNSTapTimeout time.Duration

	// Metrics
	MetricsAddr           string
	MetricsPath           string
	MetricsZoneLabelDepth int
}

type Report struct {
	ClientIP   string `json:"client_ip"`
	ClientPort int    `json:"client_port"`
	QName      string `json:"qname"`
	QueryType  string `json:"query_type"`
	EDECode    int    `json:"ede_code"`
	Agent      string `json:"agent_domain"`
}
