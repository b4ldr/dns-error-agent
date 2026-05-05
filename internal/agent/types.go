package agent

import "time"

type Config struct {
	Mode                  string
	AgentDomain           string
	UDPAddr               string
	TCPAddr               string
	DNSTapNetwork         string
	DNSTapAddress         string
	DNSTapTimeout         time.Duration
	TXTResponse           string
	Verbosity             int
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
