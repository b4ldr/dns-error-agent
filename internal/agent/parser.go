package agent

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

func ParseReportQName(inputName, agentDomain string) (Report, bool) {
	normalizedInput := dns.Fqdn(inputName)
	if len(normalizedInput) > 255 {
		return Report{}, false
	}

	full := strings.TrimSuffix(strings.ToLower(normalizedInput), ".")
	agent := strings.TrimSuffix(strings.ToLower(dns.Fqdn(agentDomain)), ".")

	suffix := "._er." + agent
	if !strings.HasSuffix(full, suffix) {
		return Report{}, false
	}

	prefix := strings.TrimSuffix(full, suffix)
	labels := strings.Split(prefix, ".")
	if len(labels) < 3 {
		return Report{}, false
	}
	if labels[0] != "_er" {
		return Report{}, false
	}

	qtypePart := labels[1]
	edePart := labels[len(labels)-1]
	faulty := labels[2 : len(labels)-1]

	if len(faulty) == 0 {
		return Report{}, false
	}

	if _, err := strconv.Atoi(edePart); err != nil {
		return Report{}, false
	}

	if !validQTypeLabel(qtypePart) {
		return Report{}, false
	}

	ede, _ := strconv.Atoi(edePart)

	return Report{
		QName:     strings.Join(faulty, ".") + ".",
		QueryType: qtypePart,
		EDECode:   ede,
		Agent:     dns.Fqdn(agentDomain),
	}, true
}

func FormatQTypeLabel(raw string) string {
	parts := strings.Split(raw, "-")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			out = append(out, p)
			continue
		}
		if t, ok := dns.TypeToString[uint16(n)]; ok {
			out = append(out, fmt.Sprintf("%d(%s)", n, t))
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, "-")
}

func validQTypeLabel(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}
	return true
}
