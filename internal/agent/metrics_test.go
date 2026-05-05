package agent

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsObserveRequest(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := newMetrics(registry, 2)

	m.observeRequest("udp", dns.TypeTXT)
	m.observeRequest("udp", dns.TypeTXT)
	m.observeRequest("tcp", 65000)

	if got := testutil.ToFloat64(m.dnsRequestsTotal.WithLabelValues("udp", "TXT")); got != 2 {
		t.Fatalf("udp TXT requests = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.dnsRequestsTotal.WithLabelValues("tcp", "65000")); got != 1 {
		t.Fatalf("tcp unknown qtype requests = %v, want 1", got)
	}
}

func TestMetricsObserveResponse(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := newMetrics(registry, 2)

	m.observeResponse("udp", dns.RcodeSuccess, true)
	m.observeResponse("udp", dns.RcodeSuccess, true)
	m.observeResponse("tcp", dns.RcodeNameError, false)

	if got := testutil.ToFloat64(m.dnsResponsesTotal.WithLabelValues("udp", "NOERROR", "true")); got != 2 {
		t.Fatalf("udp NOERROR truncated responses = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.dnsResponsesTotal.WithLabelValues("tcp", "NXDOMAIN", "false")); got != 1 {
		t.Fatalf("tcp NXDOMAIN non-truncated responses = %v, want 1", got)
	}
}

func TestMetricsObserveReportEvents(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := newMetrics(registry, 2)

	m.observeReportEvent("valid")
	m.observeReportEvent("invalid_qname")
	m.observeReportEvent("valid")

	if got := testutil.ToFloat64(m.reportEventsTotal.WithLabelValues("valid")); got != 2 {
		t.Fatalf("valid report events = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.reportEventsTotal.WithLabelValues("invalid_qname")); got != 1 {
		t.Fatalf("invalid_qname report events = %v, want 1", got)
	}
}

func TestMetricsObserveValidReport(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := newMetrics(registry, 2)

	m.observeValidReport(Report{EDECode: 7, QueryType: "1(A)", QName: "a.broken.test."})
	m.observeValidReport(Report{EDECode: 7, QueryType: "1(A)", QName: "b.broken.test."})
	m.observeValidReport(Report{EDECode: 9, QueryType: "1(A)-28(AAAA)", QName: "broken.example."})
	m.observeValidReport(Report{EDECode: 10, QueryType: "1-28", QName: "broken.example."})

	if got := testutil.ToFloat64(m.reportsByEDETotal.WithLabelValues("7", "A", "broken.test")); got != 2 {
		t.Fatalf("reports ede=7 qtype=A zone=broken.test = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.reportsByEDETotal.WithLabelValues("9", "A-AAAA", "broken.example")); got != 1 {
		t.Fatalf("reports ede=9 qtype=A-AAAA zone=broken.example = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.reportsByEDETotal.WithLabelValues("10", "A-AAAA", "broken.example")); got != 1 {
		t.Fatalf("reports ede=10 qtype=A-AAAA zone=broken.example = %v, want 1", got)
	}
}

func TestMetricsNilReceiverNoPanic(t *testing.T) {
	var m *metrics

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("expected nil receiver methods not to panic, got %v", recovered)
		}
	}()

	m.observeRequest("udp", dns.TypeTXT)
	m.observeResponse("udp", dns.RcodeSuccess, false)
	m.observeReportEvent("valid")
	m.observeValidReport(Report{EDECode: 7, QueryType: "1(A)"})
}

func TestDNSTypeLabel(t *testing.T) {
	if got := dnsTypeLabel(dns.TypeA); got != "A" {
		t.Fatalf("dnsTypeLabel(TypeA) = %q, want %q", got, "A")
	}
	if got := dnsTypeLabel(65001); got != "65001" {
		t.Fatalf("dnsTypeLabel(65001) = %q, want %q", got, "65001")
	}
}

func TestNormalizeQueryTypeForMetric(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "formatted single", in: "1(A)", want: "A"},
		{name: "formatted multi", in: "1(A)-28(AAAA)", want: "A-AAAA"},
		{name: "numeric single", in: "1", want: "A"},
		{name: "numeric multi", in: "1-28", want: "A-AAAA"},
		{name: "already named", in: "A", want: "A"},
		{name: "unknown numeric", in: "65000", want: "65000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeQueryTypeForMetric(tt.in); got != tt.want {
				t.Fatalf("normalizeQueryTypeForMetric(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeErrorZoneForMetric(t *testing.T) {
	tests := []struct {
		name  string
		qname string
		depth int
		want  string
	}{
		{name: "depth 2", qname: "www.broken.test.", depth: 2, want: "broken.test"},
		{name: "depth 1", qname: "www.broken.test.", depth: 1, want: "test"},
		{name: "short name", qname: "test.", depth: 2, want: "test"},
		{name: "empty qname", qname: "", depth: 2, want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeErrorZoneForMetric(tt.qname, tt.depth); got != tt.want {
				t.Fatalf("normalizeErrorZoneForMetric(%q, %d) = %q, want %q", tt.qname, tt.depth, got, tt.want)
			}
		})
	}
}
