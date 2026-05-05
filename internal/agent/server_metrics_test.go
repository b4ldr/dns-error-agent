package agent

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestServeDNSMetricsValidReport(t *testing.T) {
	srv := &Server{
		agentDomain: "agent.example.",
		txtResponse: "ok",
		verbosity:   0,
		logger:      noopLogger{},
		metrics:     newMetrics(prometheus.NewRegistry(), 2),
	}

	req := new(dns.Msg)
	req.SetQuestion("_er.1.broken.test.7._er.agent.example.", dns.TypeTXT)
	w := &mockWriter{remote: mockAddr{network: "tcp", value: "192.0.2.1:53000"}}

	srv.ServeDNS(w, req)

	if got := testutil.ToFloat64(srv.metrics.dnsRequestsTotal.WithLabelValues("tcp", "TXT")); got != 1 {
		t.Fatalf("dnsRequestsTotal tcp/TXT = %v, want 1", got)
	}
	if got := testutil.ToFloat64(srv.metrics.dnsResponsesTotal.WithLabelValues("tcp", "NOERROR", "false")); got != 1 {
		t.Fatalf("dnsResponsesTotal tcp/NOERROR/false = %v, want 1", got)
	}
	if got := testutil.ToFloat64(srv.metrics.reportEventsTotal.WithLabelValues("valid")); got != 1 {
		t.Fatalf("reportEventsTotal valid = %v, want 1", got)
	}
	if got := testutil.ToFloat64(srv.metrics.reportsByEDETotal.WithLabelValues("7", "A", "broken.test")); got != 1 {
		t.Fatalf("reportsByEDETotal ede=7 qtype=A zone=broken.test = %v, want 1", got)
	}
}

func TestServeDNSMetricsInvalidAndChallenged(t *testing.T) {
	srv := &Server{
		agentDomain: "agent.example.",
		txtResponse: "ok",
		verbosity:   0,
		logger:      noopLogger{},
		metrics:     newMetrics(prometheus.NewRegistry(), 2),
	}

	invalidReq := new(dns.Msg)
	invalidReq.SetQuestion("invalid.agent.example.", dns.TypeTXT)
	invalidWriter := &mockWriter{remote: mockAddr{network: "tcp", value: "192.0.2.1:53000"}}
	srv.ServeDNS(invalidWriter, invalidReq)

	challengedReq := new(dns.Msg)
	challengedReq.SetQuestion("_er.1.broken.test.7._er.agent.example.", dns.TypeTXT)
	challengedWriter := &mockWriter{remote: mockAddr{network: "udp", value: "192.0.2.1:53000"}}
	srv.ServeDNS(challengedWriter, challengedReq)

	if got := testutil.ToFloat64(srv.metrics.reportEventsTotal.WithLabelValues("invalid_qname")); got != 1 {
		t.Fatalf("reportEventsTotal invalid_qname = %v, want 1", got)
	}
	if got := testutil.ToFloat64(srv.metrics.reportEventsTotal.WithLabelValues("challenged_no_cookie")); got != 1 {
		t.Fatalf("reportEventsTotal challenged_no_cookie = %v, want 1", got)
	}
	if got := testutil.ToFloat64(srv.metrics.dnsResponsesTotal.WithLabelValues("tcp", "NXDOMAIN", "false")); got != 1 {
		t.Fatalf("dnsResponsesTotal tcp/NXDOMAIN/false = %v, want 1", got)
	}
	if got := testutil.ToFloat64(srv.metrics.dnsResponsesTotal.WithLabelValues("udp", "NOERROR", "true")); got != 1 {
		t.Fatalf("dnsResponsesTotal udp/NOERROR/true = %v, want 1", got)
	}
}
