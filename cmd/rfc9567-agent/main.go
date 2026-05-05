package main

import (
	"flag"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"dns-error-agent/internal/agent"
)

type verbosityFlag int

func (v *verbosityFlag) String() string {
	return strconv.Itoa(int(*v))
}

func (v *verbosityFlag) Set(value string) error {
	switch value {
	case "", "true":
		*v++
		return nil
	case "false":
		return nil
	default:
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		*v += verbosityFlag(parsed)
		return nil
	}
}

func (v *verbosityFlag) IsBoolFlag() bool {
	return true
}

func expandCompactVerbosityArgs(args []string) []string {
	expanded := make([]string, 0, len(args))
	for _, arg := range args {
		if len(arg) >= 3 && strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
			compact := arg[1:]
			allV := true
			for _, c := range compact {
				if c != 'v' {
					allV = false
					break
				}
			}
			if allV {
				for i := 0; i < len(compact); i++ {
					expanded = append(expanded, "-v")
				}
				continue
			}
		}
		expanded = append(expanded, arg)
	}
	return expanded
}

func main() {
	var (
		mode                  = flag.String("mode", "dns", "runtime mode: dns or dnstap")
		agentDomain           = flag.String("agent-domain", "agent.example.", "RFC9567 agent domain")
		udpAddr               = flag.String("udp", ":8053", "UDP listen address")
		tcpAddr               = flag.String("tcp", ":8053", "TCP listen address")
		dnstapNetwork         = flag.String("dnstap-network", "unix", "dnstap listen network: unix or tcp")
		dnstapAddress         = flag.String("dnstap-address", "/tmp/dns-error-agent.sock", "dnstap listen address or unix socket path")
		dnstapTimeout         = flag.Duration("dnstap-timeout", 0, "framestream I/O timeout for dnstap socket connections")
		txtResponse           = flag.String("txt", "ok", "TXT payload returned for accepted reports")
		metricsAddr           = flag.String("metrics-addr", ":9100", "Prometheus metrics HTTP listen address")
		metricsPath           = flag.String("metrics-path", "/metrics", "Prometheus metrics path")
		metricsZoneLabelDepth = flag.Int("metrics-zone-label-depth", 2, "number of rightmost labels used for metrics error_zone")
		verbosity             verbosityFlag
	)
	flag.Var(&verbosity, "v", "increase verbosity (repeatable: -v, -vv, -v -v)")
	_ = flag.CommandLine.Parse(expandCompactVerbosityArgs(os.Args[1:]))

	cfg := agent.Config{
		Mode:                  *mode,
		AgentDomain:           *agentDomain,
		UDPAddr:               *udpAddr,
		TCPAddr:               *tcpAddr,
		DNSTapNetwork:         *dnstapNetwork,
		DNSTapAddress:         *dnstapAddress,
		DNSTapTimeout:         time.Duration(*dnstapTimeout),
		TXTResponse:           *txtResponse,
		Verbosity:             int(verbosity),
		MetricsAddr:           *metricsAddr,
		MetricsPath:           *metricsPath,
		MetricsZoneLabelDepth: *metricsZoneLabelDepth,
	}

	logger := log.New(os.Stdout, "", log.LstdFlags)
	if err := agent.Run(cfg, logger); err != nil {
		log.Fatalf("agent failed: %v", err)
	}
}
