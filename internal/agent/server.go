package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type logger interface {
	Printf(format string, v ...any)
}

type Server struct {
	mode        string // normalized: ModeDNS or ModeDNSTap
	dnstapNet   string // normalized: DNSTapNetworkUnix or DNSTapNetworkTCP
	agentDomain string
	txtResponse string
	verbosity   int
	logger      logger
	metrics     *metrics
}

func NewServer(cfg Config, lg logger) (*Server, error) {
	normalizedAgent := dns.Fqdn(cfg.AgentDomain)
	if normalizedAgent == "." {
		return nil, errors.New("agent-domain must not be the root label")
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = ModeDNS
	}
	if mode != ModeDNS && mode != ModeDNSTap {
		return nil, errors.New("mode must be one of: dns, dnstap")
	}

	dnstapNet := ""
	if mode == ModeDNSTap {
		dnstapNet = strings.ToLower(strings.TrimSpace(cfg.DNSTapNetwork))
		if dnstapNet == "" {
			dnstapNet = DNSTapNetworkUnix
		}
		if dnstapNet != DNSTapNetworkUnix && dnstapNet != DNSTapNetworkTCP {
			return nil, errors.New("dnstap-network must be one of: unix, tcp")
		}
		if strings.TrimSpace(cfg.DNSTapAddress) == "" {
			return nil, errors.New("dnstap-address must not be empty in dnstap mode")
		}
	}

	if lg == nil {
		lg = log.New(os.Stdout, "", log.LstdFlags)
	}
	return &Server{
		mode:        mode,
		dnstapNet:   dnstapNet,
		agentDomain: normalizedAgent,
		txtResponse: cfg.TXTResponse,
		verbosity:   cfg.Verbosity,
		logger:      lg,
		metrics:     newMetrics(prometheus.DefaultRegisterer, cfg.MetricsZoneLabelDepth),
	}, nil
}

func (s *Server) logAt(level int, format string, args ...any) {
	if s.verbosity >= level {
		s.logger.Printf(format, args...)
	}
}

func Run(cfg Config, lg logger) error {
	srv, err := NewServer(cfg, lg)
	if err != nil {
		return err
	}

	metricsPath := cfg.MetricsPath
	if metricsPath == "" {
		metricsPath = "/metrics"
	}
	metricsServer := newMetricsHTTPServer(cfg.MetricsAddr, metricsPath)
	startMetricsServer(metricsServer, cfg.MetricsAddr, metricsPath, srv.logger)

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigch)

	switch srv.mode {
	case ModeDNSTap:
		return runDNSTap(cfg, srv, metricsServer, sigch)
	default:
		return runDNS(cfg, srv, metricsServer, sigch)
	}
}

func runDNS(cfg Config, srv *Server, metricsServer *http.Server, sigch <-chan os.Signal) error {
	udpServer := &dns.Server{Addr: cfg.UDPAddr, Net: "udp", Handler: srv}
	tcpServer := &dns.Server{Addr: cfg.TCPAddr, Net: "tcp", Handler: srv}

	go func() {
		srv.logger.Printf("rfc9567 agent listening udp=%s agent=%s", cfg.UDPAddr, srv.agentDomain)
		if serveErr := udpServer.ListenAndServe(); serveErr != nil {
			srv.logger.Printf("udp server failed: %v", serveErr)
		}
	}()

	go func() {
		srv.logger.Printf("rfc9567 agent listening tcp=%s agent=%s", cfg.TCPAddr, srv.agentDomain)
		if serveErr := tcpServer.ListenAndServe(); serveErr != nil {
			srv.logger.Printf("tcp server failed: %v", serveErr)
		}
	}()

	<-sigch

	_ = udpServer.Shutdown()
	_ = tcpServer.Shutdown()
	stopMetricsServer(metricsServer)
	return nil
}

func newMetricsHTTPServer(addr, path string) *http.Server {
	if addr == "" {
		return nil
	}
	metricsMux := http.NewServeMux()
	metricsMux.Handle(path, promhttp.Handler())
	return &http.Server{Addr: addr, Handler: metricsMux}
}

func startMetricsServer(metricsServer *http.Server, addr, path string, lg logger) {
	if metricsServer == nil {
		return
	}
	go func() {
		lg.Printf("prometheus metrics listening http=%s path=%s", addr, path)
		if serveErr := metricsServer.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			lg.Printf("metrics server failed: %v", serveErr)
		}
	}()
}

func stopMetricsServer(metricsServer *http.Server) {
	if metricsServer == nil {
		return
	}
	_ = metricsServer.Shutdown(context.Background())
}

func (s *Server) writeReply(w dns.ResponseWriter, m *dns.Msg) {
	if err := w.WriteMsg(m); err != nil {
		s.logAt(1, "write reply failed remote=%s: %v", w.RemoteAddr(), err)
	}
}

func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 {
		s.logAt(1, "dropping malformed query: no question section")
		s.metrics.observeReportEvent("malformed_query")
		m.Rcode = dns.RcodeFormatError
		s.metrics.observeResponse("unknown", m.Rcode, m.Truncated)
		s.writeReply(w, m)
		return
	}

	q := r.Question[0]
	transport := "tcp"
	if isUDP(w.RemoteAddr()) {
		transport = "udp"
	}
	s.metrics.observeRequest(transport, q.Qtype)
	s.logAt(3, "received query remote=%s qname=%s qtype=%d", w.RemoteAddr(), q.Name, q.Qtype)

	if isUDP(w.RemoteAddr()) {
		s.logAt(2, "udp query challenged with tc=1 remote=%s qname=%s", w.RemoteAddr(), q.Name)
		s.metrics.observeReportEvent("challenged_udp")
		m.Truncated = true
		m.Answer = nil
		m.Rcode = dns.RcodeSuccess
		s.metrics.observeResponse(transport, m.Rcode, m.Truncated)
		s.writeReply(w, m)
		return
	}

	_, ok := s.processReportQuestion(q, w.RemoteAddr())

	if !ok {
		m.Rcode = dns.RcodeNameError
		s.metrics.observeResponse(transport, m.Rcode, m.Truncated)
		s.writeReply(w, m)
		return
	}

	if q.Qtype == dns.TypeTXT || q.Qtype == dns.TypeANY {
		rr := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			Txt: []string{s.txtResponse},
		}
		m.Answer = append(m.Answer, rr)
	}

	m.Rcode = dns.RcodeSuccess
	s.metrics.observeResponse(transport, m.Rcode, m.Truncated)
	s.logAt(3, "response sent remote=%s qname=%s rcode=%d answers=%d", w.RemoteAddr(), q.Name, m.Rcode, len(m.Answer))
	s.writeReply(w, m)
}

func (s *Server) processReportMessage(msg *dns.Msg, transport string, remoteAddr net.Addr) {
	if len(msg.Question) == 0 {
		s.logAt(1, "dropping malformed dnstap query: no question section")
		s.metrics.observeReportEvent("malformed_query")
		return
	}

	q := msg.Question[0]
	s.metrics.observeRequest(transport, q.Qtype)
	s.logAt(3, "received dnstap query remote=%s qname=%s qtype=%d", remoteAddr, q.Name, q.Qtype)
	s.processReportQuestion(q, remoteAddr)
}

func (s *Server) processReportQuestion(q dns.Question, remoteAddr net.Addr) (Report, bool) {
	parsed, ok := ParseReportQName(q.Name, s.agentDomain)
	if !ok {
		s.logAt(2, "invalid report qname remote=%s qname=%s", remoteAddr, q.Name)
		s.metrics.observeReportEvent("invalid_qname")
		return Report{}, false
	}

	parsed.ClientIP, parsed.ClientPort = remote(remoteAddr)
	parsed.QueryType = FormatQTypeLabel(parsed.QueryType)
	s.metrics.observeReportEvent("valid")
	s.metrics.observeValidReport(parsed)

	payload, err := json.Marshal(parsed)
	if err == nil {
		s.logAt(1, "%s", payload)
	}

	return parsed, true
}
