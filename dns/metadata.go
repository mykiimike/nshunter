// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package dns

import (
	"log"
	"regexp"
	"sort"
	"strings"

	mdns "github.com/miekg/dns"
)

var spfIncludeRe = regexp.MustCompile(`include:(\S+)`)
var spfRedirectRe = regexp.MustCompile(`redirect=(\S+)`)

// CollectMetadata gathers SOA, NS, MX, and TXT records for passive reconnaissance.
func CollectMetadata(domain, ns string) *ZoneMetadata {
	meta := &ZoneMetadata{}

	c := &mdns.Client{Net: "tcp", Timeout: nsecWalkTimeout}

	// SOA
	if r, err := exchange(c, domain, mdns.TypeSOA, ns); err == nil {
		for _, rr := range r.Answer {
			if soa, ok := rr.(*mdns.SOA); ok {
				meta.SOA = soa.String()
				break
			}
		}
	}

	// NS
	if r, err := exchange(c, domain, mdns.TypeNS, ns); err == nil {
		for _, rr := range r.Answer {
			if nsRec, ok := rr.(*mdns.NS); ok {
				name := strings.TrimSuffix(nsRec.Ns, ".")
				meta.NSRecords = append(meta.NSRecords, name)
			}
		}
	}
	meta.Provider = detectProvider(meta.NSRecords)

	// MX
	if r, err := exchange(c, domain, mdns.TypeMX, ns); err == nil {
		for _, rr := range r.Answer {
			if mx, ok := rr.(*mdns.MX); ok {
				meta.MXRecords = append(meta.MXRecords, strings.TrimSuffix(mx.Mx, "."))
			}
		}
	}

	// TXT — look for SPF includes, DMARC, interesting strings
	if r, err := exchange(c, domain, mdns.TypeTXT, ns); err == nil {
		for _, rr := range r.Answer {
			if txt, ok := rr.(*mdns.TXT); ok {
				joined := strings.Join(txt.Txt, "")
				meta.TXTHints = append(meta.TXTHints, extractTXTHints(joined)...)
			}
		}
	}

	// _dmarc TXT
	if r, err := exchange(c, "_dmarc."+domain, mdns.TypeTXT, ns); err == nil {
		for _, rr := range r.Answer {
			if txt, ok := rr.(*mdns.TXT); ok {
				joined := strings.Join(txt.Txt, "")
				if strings.Contains(joined, "v=DMARC") {
					meta.TXTHints = append(meta.TXTHints, "DMARC: "+joined)
				}
			}
		}
	}

	log.Printf("[debug] metadata: SOA=%v, NS=%v, MX=%v, TXT hints=%d, provider=%s",
		meta.SOA != "", meta.NSRecords, meta.MXRecords, len(meta.TXTHints), meta.Provider)

	return meta
}

func exchange(c *mdns.Client, name string, qtype uint16, ns string) (*mdns.Msg, error) {
	m := new(mdns.Msg)
	m.SetQuestion(name, qtype)
	m.SetEdns0(4096, true)
	r, _, err := c.Exchange(m, ns)
	return r, err
}

func extractTXTHints(txt string) []string {
	var hints []string

	if strings.HasPrefix(txt, "v=spf1") {
		for _, m := range spfIncludeRe.FindAllStringSubmatch(txt, -1) {
			hints = append(hints, "SPF include: "+m[1])
		}
		for _, m := range spfRedirectRe.FindAllStringSubmatch(txt, -1) {
			hints = append(hints, "SPF redirect: "+m[1])
		}
		if len(hints) == 0 {
			hints = append(hints, "SPF: "+txt)
		}
	}

	if strings.Contains(txt, "google-site-verification") ||
		strings.Contains(txt, "ms=") ||
		strings.Contains(txt, "facebook-domain-verification") ||
		strings.Contains(txt, "apple-domain-verification") ||
		strings.Contains(txt, "docusign") ||
		strings.Contains(txt, "atlassian-domain-verification") {
		hints = append(hints, "verification: "+txt)
	}

	return hints
}

// HostnamesUnderZone returns NS and MX targets that are proper subdomains of zone
// (e.g. ns1.example.com when zone is example.com). Apex and out-of-zone targets are omitted.
func HostnamesUnderZone(zone string, meta *ZoneMetadata) []string {
	if meta == nil {
		return nil
	}
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	if zone == "" {
		return nil
	}
	suffix := "." + zone
	seen := make(map[string]bool)
	var out []string
	add := func(host string) {
		host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
		if host == "" || host == zone || seen[host] {
			return
		}
		if strings.HasSuffix(host, suffix) {
			seen[host] = true
			out = append(out, host)
		}
	}
	for _, h := range meta.NSRecords {
		add(h)
	}
	for _, h := range meta.MXRecords {
		add(h)
	}
	sort.Strings(out)
	return out
}

func detectProvider(nsRecords []string) string {
	for _, ns := range nsRecords {
		lower := strings.ToLower(ns)
		switch {
		case strings.Contains(lower, "cloudflare"):
			return "Cloudflare"
		case strings.Contains(lower, "akam"):
			return "Akamai"
		case strings.Contains(lower, "awsdns"):
			return "AWS Route53"
		case strings.Contains(lower, "azure-dns"):
			return "Azure DNS"
		case strings.Contains(lower, "googledomains") || strings.Contains(lower, "google"):
			return "Google Cloud DNS"
		case strings.Contains(lower, "ns.ovh"):
			return "OVH"
		case strings.Contains(lower, "hetzner"):
			return "Hetzner"
		case strings.Contains(lower, "digitalocean"):
			return "DigitalOcean"
		case strings.Contains(lower, "gandi"):
			return "Gandi"
		case strings.Contains(lower, "domaincontrol"):
			return "GoDaddy"
		case strings.Contains(lower, "anycast.me"):
			return "Gandi (anycast)"
		}
	}
	return ""
}
