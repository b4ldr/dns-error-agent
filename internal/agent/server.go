package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type logger interface {
	Printf(format string, v ...any)
}

type Server struct {
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
	if lg == nil {
		lg = log.New(os.Stdout, "", log.LstdFlags)
	}
	return &Server{
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

	udpServer := &dns.Server{Addr: cfg.UDPAddr, Net: "udp", Handler: srv}
	tcpServer := &dns.Server{Addr: cfg.TCPAddr, Net: "tcp", Handler: srv}
	metricsPath := cfg.MetricsPath
	if metricsPath == "" {
		metricsPath = "/metrics"
	}
	var metricsServer *http.Server
	if cfg.MetricsAddr != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle(metricsPath, promhttp.Handler())
		metricsServer = &http.Server{Addr: cfg.MetricsAddr, Handler: metricsMux}
	}

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

	if metricsServer != nil {
		go func() {
			srv.logger.Printf("prometheus metrics listening http=%s path=%s", cfg.MetricsAddr, metricsPath)
			if serveErr := metricsServer.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				srv.logger.Printf("metrics server failed: %v", serveErr)
			}
		}()
	}

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)
	<-sigch

	_ = udpServer.Shutdown()
	_ = tcpServer.Shutdown()
	if metricsServer != nil {
		_ = metricsServer.Shutdown(context.Background())
	}
	return nil
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
		_ = w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	transport := "tcp"
	if isUDP(w.RemoteAddr()) {
		transport = "udp"
	}
	s.metrics.observeRequest(transport, q.Qtype)
	s.logAt(3, "received query remote=%s qname=%s qtype=%d", w.RemoteAddr(), q.Name, q.Qtype)
	parsed, ok := ParseReportQName(q.Name, s.agentDomain)

	if isUDP(w.RemoteAddr()) && !hasDNSCookie(r) {
		s.logAt(2, "udp query without dns cookie challenged with tc=1 remote=%s qname=%s", w.RemoteAddr(), q.Name)
		s.metrics.observeReportEvent("challenged_no_cookie")
		m.Truncated = true
		m.Answer = nil
		m.Rcode = dns.RcodeSuccess
		s.metrics.observeResponse(transport, m.Rcode, m.Truncated)
		_ = w.WriteMsg(m)
		return
	}

	if !ok {
		s.logAt(2, "invalid report qname remote=%s qname=%s", w.RemoteAddr(), q.Name)
		s.metrics.observeReportEvent("invalid_qname")
		m.Rcode = dns.RcodeNameError
		s.metrics.observeResponse(transport, m.Rcode, m.Truncated)
		_ = w.WriteMsg(m)
		return
	}

	parsed.ClientIP, parsed.ClientPort = remote(w.RemoteAddr())
	parsed.QueryType = FormatQTypeLabel(parsed.QueryType)
	s.metrics.observeReportEvent("valid")
	s.metrics.observeValidReport(parsed)

	payload, err := json.Marshal(parsed)
	if err == nil {
		s.logAt(1, "%s", payload)
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
	_ = w.WriteMsg(m)
}
