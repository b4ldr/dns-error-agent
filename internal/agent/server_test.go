package agent

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type mockAddr struct {
	network string
	value   string
}

func (m mockAddr) Network() string { return m.network }
func (m mockAddr) String() string  { return m.value }

type mockWriter struct {
	remote net.Addr
	msg    *dns.Msg
}

func (m *mockWriter) LocalAddr() net.Addr                { return mockAddr{network: "udp", value: "127.0.0.1:8053"} }
func (m *mockWriter) RemoteAddr() net.Addr               { return m.remote }
func (m *mockWriter) WriteMsg(msg *dns.Msg) error        { m.msg = msg; return nil }
func (m *mockWriter) Write([]byte) (int, error)          { return 0, nil }
func (m *mockWriter) Close() error                       { return nil }
func (m *mockWriter) TsigStatus() error                  { return nil }
func (m *mockWriter) TsigTimersOnly(bool)                {}
func (m *mockWriter) Hijack()                            {}
func (m *mockWriter) Context() context.Context           { return context.Background() }
func (m *mockWriter) Msg() *dns.Msg                      { return m.msg }
func (m *mockWriter) SetWriteDeadline(_ time.Time) error { return nil }

type noopLogger struct{}

func (noopLogger) Printf(string, ...any) {}

func TestServeDNSResponseMatrix(t *testing.T) {
	srv, err := NewServer(Config{AgentDomain: "agent.example.", TXTResponse: "ok"}, noopLogger{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name        string
		network     string
		qname       string
		qtype       uint16
		withCookie  bool
		wantTC      bool
		wantRcode   int
		wantAnswers int
	}{
		{
			name:        "udp no cookie returns tc",
			network:     "udp",
			qname:       "_er.1.broken.test.7._er.agent.example.",
			qtype:       dns.TypeTXT,
			withCookie:  false,
			wantTC:      true,
			wantRcode:   dns.RcodeSuccess,
			wantAnswers: 0,
		},
		{
			name:        "udp with cookie valid report returns txt",
			network:     "udp",
			qname:       "_er.1.broken.test.7._er.agent.example.",
			qtype:       dns.TypeTXT,
			withCookie:  true,
			wantTC:      false,
			wantRcode:   dns.RcodeSuccess,
			wantAnswers: 1,
		},
		{
			name:        "tcp invalid report returns nxdomain",
			network:     "tcp",
			qname:       "invalid.agent.example.",
			qtype:       dns.TypeTXT,
			withCookie:  false,
			wantTC:      false,
			wantRcode:   dns.RcodeNameError,
			wantAnswers: 0,
		},
		{
			name:        "tcp valid any returns txt",
			network:     "tcp",
			qname:       "_er.1.broken.test.7._er.agent.example.",
			qtype:       dns.TypeANY,
			withCookie:  false,
			wantTC:      false,
			wantRcode:   dns.RcodeSuccess,
			wantAnswers: 1,
		},
		{
			name:        "tcp valid type a returns noerror without answers",
			network:     "tcp",
			qname:       "_er.1.broken.test.7._er.agent.example.",
			qtype:       dns.TypeA,
			withCookie:  false,
			wantTC:      false,
			wantRcode:   dns.RcodeSuccess,
			wantAnswers: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(tt.qname, tt.qtype)
			if tt.withCookie {
				opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
				opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0123456789abcdef"})
				req.Extra = append(req.Extra, opt)
			}

			w := &mockWriter{remote: mockAddr{network: tt.network, value: "192.0.2.1:53000"}}
			srv.ServeDNS(w, req)

			if w.msg == nil {
				t.Fatalf("expected response")
			}
			if w.msg.Truncated != tt.wantTC {
				t.Fatalf("Truncated = %v, want %v", w.msg.Truncated, tt.wantTC)
			}
			if w.msg.Rcode != tt.wantRcode {
				t.Fatalf("Rcode = %d, want %d", w.msg.Rcode, tt.wantRcode)
			}
			if len(w.msg.Answer) != tt.wantAnswers {
				t.Fatalf("answers = %d, want %d", len(w.msg.Answer), tt.wantAnswers)
			}
		})
	}
}
