// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package dns

import (
	"fmt"
	"log"
	"strings"

	mdns "github.com/miekg/dns"
)

// TryAXFR attempts a zone transfer (AXFR) against all authoritative nameservers.
// Returns the first successful transfer, or nil if all refuse.
func TryAXFR(domain string) *AXFRResult {
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	nameservers := findAllAuthNS(domain)
	if len(nameservers) == 0 {
		log.Printf("[warn] AXFR: no nameservers found for %s", domain)
		return nil
	}

	for _, ns := range nameservers {
		result := attemptAXFR(domain, ns)
		if result != nil && result.Allowed {
			return result
		}
	}

	return &AXFRResult{Allowed: false}
}

func findAllAuthNS(domain string) []string {
	c := &mdns.Client{Net: "tcp", Timeout: nsecWalkTimeout}
	m := new(mdns.Msg)
	m.SetQuestion(domain, mdns.TypeNS)
	m.SetEdns0(4096, true)

	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return nil
	}

	var servers []string
	for _, rr := range r.Answer {
		if ns, ok := rr.(*mdns.NS); ok {
			servers = append(servers, ns.Ns+":53")
		}
	}
	if len(servers) == 0 {
		for _, rr := range r.Ns {
			if ns, ok := rr.(*mdns.NS); ok {
				servers = append(servers, ns.Ns+":53")
			}
		}
	}
	return servers
}

func attemptAXFR(domain, ns string) *AXFRResult {
	t := new(mdns.Transfer)
	m := new(mdns.Msg)
	m.SetAxfr(domain)

	ch, err := t.In(m, ns)
	if err != nil {
		log.Printf("[info] AXFR refused by %s: %v", ns, err)
		return nil
	}

	result := &AXFRResult{
		Nameserver: strings.TrimSuffix(ns, ":53"),
	}

	seen := make(map[string]bool)

	for envelope := range ch {
		if envelope.Error != nil {
			if result.RecordCount == 0 {
				log.Printf("[info] AXFR error from %s: %v", ns, envelope.Error)
				return nil
			}
			break
		}

		for _, rr := range envelope.RR {
			result.RecordCount++

			name := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
			rrType := mdns.TypeToString[rr.Header().Rrtype]
			value := extractRRValue(rr)

			result.Records = append(result.Records, AXFRRecord{
				Name:  name,
				Type:  rrType,
				TTL:   rr.Header().Ttl,
				Value: value,
			})

			if !seen[name] {
				seen[name] = true
				result.Names = append(result.Names, name)
			}
		}
	}

	result.Allowed = result.RecordCount > 0

	if result.Allowed {
		log.Printf("[!] AXFR succeeded on %s — %d records, %d unique names",
			ns, result.RecordCount, len(result.Names))
	}

	return result
}

func extractRRValue(rr mdns.RR) string {
	full := rr.String()
	parts := strings.SplitN(full, "\t", 5)
	if len(parts) >= 5 {
		return parts[4]
	}

	switch v := rr.(type) {
	case *mdns.A:
		return v.A.String()
	case *mdns.AAAA:
		return v.AAAA.String()
	case *mdns.CNAME:
		return v.Target
	case *mdns.MX:
		return fmt.Sprintf("%d %s", v.Preference, v.Mx)
	case *mdns.NS:
		return v.Ns
	case *mdns.TXT:
		return strings.Join(v.Txt, " ")
	case *mdns.SOA:
		return fmt.Sprintf("%s %s %d", v.Ns, v.Mbox, v.Serial)
	case *mdns.SRV:
		return fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, v.Target)
	case *mdns.PTR:
		return v.Ptr
	default:
		return rr.String()
	}
}
