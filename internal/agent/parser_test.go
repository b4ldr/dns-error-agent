package agent

import (
	"strings"
	"testing"
)

func TestParseReportQName(t *testing.T) {
	tests := []struct {
		name      string
		qname     string
		agent     string
		wantOK    bool
		wantQName string
		wantQType string
		wantEDE   int
	}{
		{
			name:      "valid single qtype",
			qname:     "_er.1.broken.test.7._er.agent.example.",
			agent:     "agent.example.",
			wantOK:    true,
			wantQName: "broken.test.",
			wantQType: "1",
			wantEDE:   7,
		},
		{
			name:      "valid multi qtype",
			qname:     "_er.1-28.broken.test.9._er.agent.example.",
			agent:     "agent.example.",
			wantOK:    true,
			wantQName: "broken.test.",
			wantQType: "1-28",
			wantEDE:   9,
		},
		{
			name:   "missing leading er label",
			qname:  "1.broken.test.7._er.agent.example.",
			agent:  "agent.example.",
			wantOK: false,
		},
		{
			name:   "malformed er placement",
			qname:  "_er.1.broken.test.7.agent.example._er.",
			agent:  "agent.example.",
			wantOK: false,
		},
		{
			name:   "bad ede",
			qname:  "_er.1.broken.test.x._er.agent.example.",
			agent:  "agent.example.",
			wantOK: false,
		},
		{
			name:   "bad qtype",
			qname:  "_er.a.broken.test.7._er.agent.example.",
			agent:  "agent.example.",
			wantOK: false,
		},
		{
			name:   "wrong agent",
			qname:  "_er.1.broken.test.7._er.other.example.",
			agent:  "agent.example.",
			wantOK: false,
		},
		{
			name: "qname exceeds 255 octets",
			qname: "_er.1." +
				strings.Repeat("a", 63) + "." +
				strings.Repeat("b", 63) + "." +
				strings.Repeat("c", 63) + "." +
				strings.Repeat("d", 63) +
				".7._er.agent.example.",
			agent:  "agent.example.",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, ok := ParseReportQName(tt.qname, tt.agent)
			if ok != tt.wantOK {
				t.Fatalf("ParseReportQName() ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if report.QName != tt.wantQName {
				t.Fatalf("QName = %q, want %q", report.QName, tt.wantQName)
			}
			if report.QueryType != tt.wantQType {
				t.Fatalf("QueryType = %q, want %q", report.QueryType, tt.wantQType)
			}
			if report.EDECode != tt.wantEDE {
				t.Fatalf("EDECode = %d, want %d", report.EDECode, tt.wantEDE)
			}
		})
	}
}

func TestFormatQTypeLabel(t *testing.T) {
	got := FormatQTypeLabel("1-28")
	if got != "1(A)-28(AAAA)" {
		t.Fatalf("unexpected label: %s", got)
	}
}
