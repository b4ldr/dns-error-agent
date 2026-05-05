package agent

import (
	"net"
	"testing"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/protobuf/proto"
)

func TestProcessDNSTapFrameValidReport(t *testing.T) {
	srv := &Server{
		agentDomain: "agent.example.",
		txtResponse: "ok",
		logger:      noopLogger{},
		metrics:     newMetrics(prometheus.NewRegistry(), 2),
	}

	frame := marshalDNSTapFrame(t, buildDNSTapQuery(t, "_er.1.broken.test.7._er.agent.example.", dns.TypeTXT, "udp", "192.0.2.55", 5300))
	srv.processDNSTapFrame(frame)

	if got := testutil.ToFloat64(srv.metrics.dnsRequestsTotal.WithLabelValues("udp", "TXT")); got != 1 {
		t.Fatalf("dnsRequestsTotal udp/TXT = %v, want 1", got)
	}
	if got := testutil.ToFloat64(srv.metrics.reportEventsTotal.WithLabelValues("valid")); got != 1 {
		t.Fatalf("reportEventsTotal valid = %v, want 1", got)
	}
	if got := testutil.ToFloat64(srv.metrics.reportsByEDETotal.WithLabelValues("7", "A", "broken.test")); got != 1 {
		t.Fatalf("reportsByEDETotal ede=7 qtype=A zone=broken.test = %v, want 1", got)
	}
}

func TestProcessDNSTapFrameInvalidReport(t *testing.T) {
	srv := &Server{
		agentDomain: "agent.example.",
		txtResponse: "ok",
		logger:      noopLogger{},
		metrics:     newMetrics(prometheus.NewRegistry(), 2),
	}

	frame := marshalDNSTapFrame(t, buildDNSTapQuery(t, "invalid.agent.example.", dns.TypeTXT, "tcp", "192.0.2.55", 5300))
	srv.processDNSTapFrame(frame)

	if got := testutil.ToFloat64(srv.metrics.dnsRequestsTotal.WithLabelValues("tcp", "TXT")); got != 1 {
		t.Fatalf("dnsRequestsTotal tcp/TXT = %v, want 1", got)
	}
	if got := testutil.ToFloat64(srv.metrics.reportEventsTotal.WithLabelValues("invalid_qname")); got != 1 {
		t.Fatalf("reportEventsTotal invalid_qname = %v, want 1", got)
	}
}

func TestProcessDNSTapFrameIgnoresResponses(t *testing.T) {
	srv := &Server{
		agentDomain: "agent.example.",
		txtResponse: "ok",
		logger:      noopLogger{},
		metrics:     newMetrics(prometheus.NewRegistry(), 2),
	}

	msg := buildDNSTapQuery(t, "_er.1.broken.test.7._er.agent.example.", dns.TypeTXT, "udp", "192.0.2.55", 5300)
	msg.Message.Type = enumMessageType(dnstap.Message_CLIENT_RESPONSE)
	frame := marshalDNSTapFrame(t, msg)
	srv.processDNSTapFrame(frame)

	if got := testutil.ToFloat64(srv.metrics.reportEventsTotal.WithLabelValues("valid")); got != 0 {
		t.Fatalf("reportEventsTotal valid = %v, want 0", got)
	}
	if got := testutil.ToFloat64(srv.metrics.dnsRequestsTotal.WithLabelValues("udp", "TXT")); got != 0 {
		t.Fatalf("dnsRequestsTotal udp/TXT = %v, want 0", got)
	}
}

func TestDNSTapRemoteAddr(t *testing.T) {
	msg := &dnstap.Message{
		SocketProtocol: enumSocketProtocol(dnstap.SocketProtocol_UDP),
		QueryAddress:   net.ParseIP("192.0.2.99"),
		QueryPort:      uint32Ptr(5353),
	}

	addr := dnstapRemoteAddr(msg)
	if addr == nil {
		t.Fatal("expected remote addr")
	}
	if addr.Network() != "udp" {
		t.Fatalf("network = %q, want udp", addr.Network())
	}
	if addr.String() != "192.0.2.99:5353" {
		t.Fatalf("string = %q, want 192.0.2.99:5353", addr.String())
	}
}

func buildDNSTapQuery(t *testing.T, qname string, qtype uint16, transport, ip string, port uint32) *dnstap.Dnstap {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(qname, qtype)
	payload, err := req.Pack()
	if err != nil {
		t.Fatalf("pack dns message: %v", err)
	}

	protocol := dnstap.SocketProtocol_TCP
	if transport == "udp" {
		protocol = dnstap.SocketProtocol_UDP
	}

	return &dnstap.Dnstap{
		Type: enumDnstapType(dnstap.Dnstap_MESSAGE),
		Message: &dnstap.Message{
			Type:           enumMessageType(dnstap.Message_CLIENT_QUERY),
			SocketProtocol: enumSocketProtocol(protocol),
			QueryAddress:   net.ParseIP(ip),
			QueryPort:      uint32Ptr(port),
			QueryMessage:   payload,
		},
	}
}

func marshalDNSTapFrame(t *testing.T, msg *dnstap.Dnstap) []byte {
	t.Helper()
	frame, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal dnstap frame: %v", err)
	}
	return frame
}

func enumDnstapType(v dnstap.Dnstap_Type) *dnstap.Dnstap_Type           { return &v }
func enumMessageType(v dnstap.Message_Type) *dnstap.Message_Type        { return &v }
func enumSocketProtocol(v dnstap.SocketProtocol) *dnstap.SocketProtocol { return &v }
func uint32Ptr(v uint32) *uint32                                        { return &v }
