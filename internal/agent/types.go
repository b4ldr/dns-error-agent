package agent

type Config struct {
	AgentDomain           string
	UDPAddr               string
	TCPAddr               string
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
