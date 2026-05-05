package agent

import (
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

type metrics struct {
	dnsRequestsTotal  *prometheus.CounterVec
	dnsResponsesTotal *prometheus.CounterVec
	reportEventsTotal *prometheus.CounterVec
	reportsByEDETotal *prometheus.CounterVec
	zoneLabelDepth    int
}

func newMetrics(registry prometheus.Registerer, zoneLabelDepth int) *metrics {
	if zoneLabelDepth <= 0 {
		zoneLabelDepth = 2
	}

	m := &metrics{
		dnsRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dns_error_agent_dns_requests_total",
			Help: "Total number of DNS requests received by transport and qtype.",
		}, []string{"transport", "qtype"}),
		dnsResponsesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dns_error_agent_dns_responses_total",
			Help: "Total number of DNS responses by transport, rcode, and truncated bit.",
		}, []string{"transport", "rcode", "truncated"}),
		reportEventsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dns_error_agent_report_events_total",
			Help: "Total report processing outcomes (valid, invalid_qname, challenged_no_cookie, malformed_query).",
		}, []string{"result"}),
		reportsByEDETotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dns_error_agent_reports_by_ede_total",
			Help: "Total valid reports grouped by EDE code, query type, and bounded error zone.",
		}, []string{"ede_code", "query_type", "error_zone"}),
		zoneLabelDepth: zoneLabelDepth,
	}

	registry.MustRegister(
		m.dnsRequestsTotal,
		m.dnsResponsesTotal,
		m.reportEventsTotal,
		m.reportsByEDETotal,
	)

	return m
}

func (m *metrics) observeRequest(transport string, qtype uint16) {
	if m == nil {
		return
	}
	m.dnsRequestsTotal.WithLabelValues(transport, dnsTypeLabel(qtype)).Inc()
}

func (m *metrics) observeResponse(transport string, rcode int, truncated bool) {
	if m == nil {
		return
	}
	m.dnsResponsesTotal.WithLabelValues(transport, dns.RcodeToString[rcode], strconv.FormatBool(truncated)).Inc()
}

func (m *metrics) observeReportEvent(result string) {
	if m == nil {
		return
	}
	m.reportEventsTotal.WithLabelValues(result).Inc()
}

func (m *metrics) observeValidReport(parsed Report) {
	if m == nil {
		return
	}
	m.reportsByEDETotal.WithLabelValues(
		strconv.Itoa(parsed.EDECode),
		normalizeQueryTypeForMetric(parsed.QueryType),
		normalizeErrorZoneForMetric(parsed.QName, m.zoneLabelDepth),
	).Inc()
}

func dnsTypeLabel(qtype uint16) string {
	if name, ok := dns.TypeToString[qtype]; ok {
		return name
	}
	return strconv.Itoa(int(qtype))
}

func normalizeQueryTypeForMetric(raw string) string {
	parts := strings.Split(raw, "-")
	normalized := make([]string, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if open := strings.Index(part, "("); open > 0 && strings.HasSuffix(part, ")") {
			name := part[open+1 : len(part)-1]
			if name != "" {
				normalized = append(normalized, name)
				continue
			}
		}

		if n, err := strconv.Atoi(part); err == nil {
			normalized = append(normalized, dnsTypeLabel(uint16(n)))
			continue
		}

		normalized = append(normalized, part)
	}

	if len(normalized) == 0 {
		return raw
	}

	return strings.Join(normalized, "-")
}

func normalizeErrorZoneForMetric(qname string, depth int) string {
	fqdn := strings.TrimSuffix(strings.ToLower(dns.Fqdn(qname)), ".")
	if fqdn == "" {
		return "unknown"
	}

	labels := strings.Split(fqdn, ".")
	if len(labels) <= depth {
		return fqdn
	}

	return strings.Join(labels[len(labels)-depth:], ".")
}
