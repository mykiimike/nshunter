// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package dns

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/mykiimike/nshunter/logx"
)

const (
	nsecWalkTimeout = 5 * time.Second
)

var NSECWalkMaxQueries = 10000

func CollectDNSSEC(domain string) (*DNSSECResult, error) {
	return CollectDNSSECWithOptions(domain, nil)
}

func CollectDNSSECWithOptions(domain string, opts *CollectOptions) (*DNSSECResult, error) {
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	log.Printf("[debug] resolving authoritative NS for %s", domain)
	ns, err := findAuthNS(domain)
	if err != nil {
		return nil, fmt.Errorf("finding nameservers: %w", err)
	}
	if ns == "" {
		return nil, fmt.Errorf("no authoritative nameserver found for %s", domain)
	}
	log.Printf("[debug] using NS %s", ns)

	result := &DNSSECResult{Domain: strings.TrimSuffix(domain, ".")}

	if opts != nil && opts.DisableAXFR {
		log.Printf("[debug] AXFR disabled by option")
	} else {
		log.Printf("[debug] attempting AXFR zone transfer")
		result.AXFR = TryAXFR(domain)
	}

	log.Printf("[debug] querying DNSKEY records")
	collectDNSKEY(domain, ns, result)
	log.Printf("[debug] DNSKEY: %d keys, %d RRSIG", result.DNSKEYCount, result.RRSIGCount)

	log.Printf("[debug] querying NSEC3PARAM")
	collectNSEC3Param(domain, ns, result)

	disableNSEC3 := opts != nil && opts.DisableNSEC3
	disableNSEC := opts != nil && opts.DisableNSEC

	if result.NSEC3Params != nil {
		if disableNSEC3 {
			log.Printf("[debug] NSEC3 detected but NSEC3 walk disabled by option")
			if !disableNSEC {
				log.Printf("[debug] attempting NSEC chain walk despite NSEC3 presence")
				walkNSECChain(domain, ns, result)
				log.Printf("[debug] NSEC walk done: %d records, %d names, blacklies=%v",
					len(result.NSECRecords), len(result.EnumeratedNames), result.BlackLies)
			}
		} else {
			log.Printf("[debug] NSEC3 detected: algo=%d iter=%d salt=%q flags=%d — starting NSEC3 walk (budget=%d)",
				result.NSEC3Params.Algorithm, result.NSEC3Params.Iterations,
				result.NSEC3Params.SaltHex, result.NSEC3Params.Flags, NSECWalkMaxQueries)
			walkResult := WalkNSEC3Zone(domain, ns, NSECWalkMaxQueries)
			result.NSEC3Records = walkResult.Records
			result.NSEC3Walk = walkResult
			if walkResult.OptOut {
				result.NSEC3Params.Flags |= 1
			}
			log.Printf("[debug] NSEC3 walk done: %d queries, %d hashes, %d chain entries, saturated=%v",
				walkResult.Queries, len(walkResult.Hashes), len(walkResult.Records), walkResult.FullyCover)
		}
	} else if disableNSEC {
		log.Printf("[debug] NSEC walk disabled by option")
	} else {
		log.Printf("[debug] no NSEC3PARAM — trying NSEC chain walk")
		walkNSECChain(domain, ns, result)
		log.Printf("[debug] NSEC walk done: %d records, %d names, blacklies=%v",
			len(result.NSECRecords), len(result.EnumeratedNames), result.BlackLies)
	}

	// Merge AXFR names into enumerated names if AXFR succeeded
	if result.AXFR != nil && result.AXFR.Allowed {
		seen := make(map[string]bool)
		for _, n := range result.EnumeratedNames {
			seen[n] = true
		}
		for _, n := range result.AXFR.Names {
			if !seen[n] {
				result.EnumeratedNames = append(result.EnumeratedNames, n)
				seen[n] = true
			}
		}
	}

	result.HasDNSSEC = result.DNSKEYCount > 0

	// Collect zone metadata (SOA, NS, MX, TXT) regardless of DNSSEC
	log.Printf("[debug] collecting zone metadata (SOA, NS, MX, TXT)")
	result.Metadata = CollectMetadata(domain, ns)

	// CT log enumeration — passive, works without DNSSEC
	if opts != nil && opts.DisableRegistry {
		log.Printf("[debug] Certificate Transparency registry lookups disabled by option")
	} else {
		log.Printf("[debug] passive registries: see per-source [registry ...] lines — crt.sh (always), Cert Spotter (SSLMate), Censys (optional API ID+secret)")
		merged, breakdown := CollectRegistryNames(strings.TrimSuffix(domain, "."))
		result.CTNames = merged
		result.Registry = &breakdown
	}

	// Merge all discovered names (NSEC*, then optionally in-zone NS/MX hostnames, then CT)
	seen := make(map[string]bool)
	for _, n := range result.EnumeratedNames {
		seen[n] = true
	}
	var metaHosts []string
	if opts != nil && opts.DisableMetaHosts {
		log.Printf("[debug] NS/MX host merge into enumeration disabled by option")
	} else {
		metaHosts = HostnamesUnderZone(strings.TrimSuffix(domain, "."), result.Metadata)
		for _, n := range metaHosts {
			if !seen[n] {
				result.EnumeratedNames = append(result.EnumeratedNames, n)
				seen[n] = true
			}
		}
		if len(metaHosts) > 0 {
			log.Printf("[debug] merged %d in-zone hostnames from NS/MX records into enumeration", len(metaHosts))
		}
	}
	for _, n := range result.CTNames {
		if !seen[n] {
			result.EnumeratedNames = append(result.EnumeratedNames, n)
			seen[n] = true
		}
	}

	log.Printf("[debug] collection complete: dnssec=%v, nsec3=%d, nsec=%d, ct=%d, meta_hosts=%d, enumerated=%d",
		result.HasDNSSEC, len(result.NSEC3Records), len(result.NSECRecords),
		len(result.CTNames), len(metaHosts), len(result.EnumeratedNames))

	return result, nil
}

func findAuthNS(domain string) (string, error) {
	c := &mdns.Client{Net: "tcp", Timeout: nsecWalkTimeout}
	m := new(mdns.Msg)
	m.SetQuestion(domain, mdns.TypeNS)
	m.SetEdns0(4096, true)

	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return "", err
	}

	var nsNames []string
	for _, rr := range r.Answer {
		if ns, ok := rr.(*mdns.NS); ok {
			nsNames = append(nsNames, ns.Ns)
		}
	}
	if len(nsNames) == 0 {
		for _, rr := range r.Ns {
			if ns, ok := rr.(*mdns.NS); ok {
				nsNames = append(nsNames, ns.Ns)
			}
		}
	}
	if len(nsNames) == 0 {
		z := strings.TrimSuffix(domain, ".")
		switch r.Rcode {
		case mdns.RcodeNameError:
			return "", fmt.Errorf("NXDOMAIN: %q is not registered in DNS", z)
		case mdns.RcodeSuccess:
			return "", fmt.Errorf("no NS records for %q (not a delegated zone: registry returned no NS / NODATA)", z)
		default:
			rc := mdns.RcodeToString[r.Rcode]
			if rc == "" {
				rc = fmt.Sprintf("rcode %d", r.Rcode)
			}
			return "", fmt.Errorf("NS query failed: %s", rc)
		}
	}

	log.Printf("[debug] found %d NS hostnames: %v", len(nsNames), nsNames)

	// Resolve NS hostname to an IP via 8.8.8.8 (avoid local resolver issues)
	for _, nsName := range nsNames {
		ip, err := resolveNSToIP(c, nsName)
		if err == nil {
			log.Printf("[debug] resolved %s → %s", nsName, ip)
			return ip + ":53", nil
		}
		log.Printf("[debug] failed to resolve %s: %v", nsName, err)
	}

	log.Printf("[warn] could not resolve any NS to IP, falling back to hostname %s", nsNames[0])
	return nsNames[0] + ":53", nil
}

func resolveNSToIP(c *mdns.Client, nsName string) (string, error) {
	m := new(mdns.Msg)
	m.SetQuestion(nsName, mdns.TypeA)

	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return "", err
	}
	for _, rr := range r.Answer {
		if a, ok := rr.(*mdns.A); ok {
			return a.A.String(), nil
		}
	}
	return "", fmt.Errorf("no A record for %s", nsName)
}

func collectDNSKEY(domain, ns string, result *DNSSECResult) {
	r, err := queryTCPWithUDPFallback(domain, mdns.TypeDNSKEY, ns)
	if err != nil {
		log.Printf("[warn] DNSKEY query to %s failed: %v (domain may not have DNSSEC)", ns, err)
		return
	}

	for _, rr := range r.Answer {
		switch rr.(type) {
		case *mdns.DNSKEY:
			result.DNSKEYCount++
		case *mdns.RRSIG:
			result.RRSIGCount++
		}
	}
}

func collectNSEC3Param(domain, ns string, result *DNSSECResult) {
	r, err := queryTCPWithUDPFallback(domain, mdns.TypeNSEC3PARAM, ns)
	if err != nil {
		log.Printf("[warn] NSEC3PARAM query to %s failed: %v", ns, err)
		return
	}

	for _, rr := range r.Answer {
		if p, ok := rr.(*mdns.NSEC3PARAM); ok {
			result.NSEC3Params = &NSEC3Params{
				Algorithm:  p.Hash,
				Flags:      p.Flags,
				Iterations: p.Iterations,
				SaltHex:    hex.EncodeToString([]byte(p.Salt)),
			}
			break
		}
	}
}

func queryTCPWithUDPFallback(name string, qtype uint16, ns string) (*mdns.Msg, error) {
	m := new(mdns.Msg)
	m.SetQuestion(name, qtype)
	m.SetEdns0(4096, true)

	c := &mdns.Client{Net: "tcp", Timeout: nsecWalkTimeout}
	r, _, err := c.Exchange(m, ns)
	if err == nil {
		return r, nil
	}

	c.Net = "udp"
	r, _, err = c.Exchange(m, ns)
	if err != nil {
		return nil, fmt.Errorf("tcp and udp both failed for %s %d: %w", name, qtype, err)
	}
	return r, nil
}

// walkNSECChain follows the NSEC chain to enumerate all names in the zone.
// It queries each name to obtain its NSEC record (which contains NextDomain),
// then advances to NextDomain until the chain wraps back to the apex.
func walkNSECChain(domain, ns string, result *DNSSECResult) {
	c := &mdns.Client{Net: "tcp", Timeout: nsecWalkTimeout}
	seen := make(map[string]bool)
	current := domain
	stale := 0

	for i := 0; i < NSECWalkMaxQueries; i++ {
		nsecRecs := queryNSECAt(c, current, domain, ns)
		if len(nsecRecs) == 0 {
			log.Printf("[debug] NSEC walk: no NSEC at %s after %d queries, stopping", current, i)
			break
		}

		best := pickBestNSEC(nsecRecs, current)
		if best == nil {
			best = nsecRecs[0]
		}

		owner := strings.ToLower(best.Header().Name)
		next := strings.ToLower(best.NextDomain)

		if isBlackLiesPattern(owner, next) {
			log.Printf("[info] NSEC black lies detected (anti-walking countermeasure)")
			result.BlackLies = true
			break
		}

		if seen[owner] {
			stale++
			if stale > 5 {
				log.Printf("[debug] NSEC walk: stagnated at %s, stopping", owner)
				break
			}
			continue
		}
		seen[owner] = true
		stale = 0

		if !isValidDNSName(owner) || !isValidDNSName(next) {
			current = next
			continue
		}

		rec := NSECRecord{
			Owner:     owner,
			NextOwner: next,
		}
		for _, t := range best.TypeBitMap {
			rec.Types = append(rec.Types, t)
		}
		result.NSECRecords = append(result.NSECRecords, rec)
		result.EnumeratedNames = append(result.EnumeratedNames, strings.TrimSuffix(owner, "."))
		logx.SuperDebugf("nsec walk hit: owner=%s next=%s", strings.TrimSuffix(owner, "."), strings.TrimSuffix(next, "."))

		if mdns.CanonicalName(next) == mdns.CanonicalName(domain) {
			log.Printf("[debug] NSEC walk: chain wrapped back to apex after %d queries, %d names",
				i+1, len(result.EnumeratedNames))
			break
		}

		current = next

		if (i+1)%500 == 0 {
			log.Printf("[info] NSEC walk: %d queries, %d names so far", i+1, len(result.EnumeratedNames))
		}
	}
}

// queryNSECAt tries multiple strategies to obtain NSEC records at a given name:
//  1. TypeNSEC query (most direct — NSEC appears in Answer)
//  2. TypeA query (NSEC may appear in Authority for NODATA, or alongside Answer)
//  3. Probe a non-existent child under `name` to trigger an NXDOMAIN with covering NSEC
func queryNSECAt(c *mdns.Client, name, domain, ns string) []*mdns.NSEC {
	if recs := dnsQueryCollectNSEC(c, name, mdns.TypeNSEC, ns); len(recs) > 0 {
		return recs
	}

	if recs := dnsQueryCollectNSEC(c, name, mdns.TypeA, ns); len(recs) > 0 {
		return recs
	}

	probe := "zz--nshunter-probe." + name
	if recs := dnsQueryCollectNSEC(c, probe, mdns.TypeA, ns); len(recs) > 0 {
		return filterNSECForDomain(recs, domain)
	}

	return nil
}

func dnsQueryCollectNSEC(c *mdns.Client, name string, qtype uint16, ns string) []*mdns.NSEC {
	m := new(mdns.Msg)
	m.SetQuestion(name, qtype)
	m.SetEdns0(4096, true)

	r, _, err := c.Exchange(m, ns)
	if err != nil {
		return nil
	}

	var recs []*mdns.NSEC
	for _, rr := range r.Answer {
		if nsec, ok := rr.(*mdns.NSEC); ok {
			recs = append(recs, nsec)
		}
	}
	for _, rr := range r.Ns {
		if nsec, ok := rr.(*mdns.NSEC); ok {
			recs = append(recs, nsec)
		}
	}
	return recs
}

// filterNSECForDomain keeps only NSEC records whose owner is within the target domain.
func filterNSECForDomain(recs []*mdns.NSEC, domain string) []*mdns.NSEC {
	suffix := mdns.CanonicalName(domain)
	var out []*mdns.NSEC
	for _, r := range recs {
		owner := mdns.CanonicalName(r.Header().Name)
		if owner == suffix || strings.HasSuffix(owner, "."+suffix) {
			out = append(out, r)
		}
	}
	if len(out) > 0 {
		return out
	}
	return recs
}

// pickBestNSEC selects the NSEC record whose owner matches the target name.
// Falls back to the first non-wildcard record.
func pickBestNSEC(recs []*mdns.NSEC, target string) *mdns.NSEC {
	targetCanon := mdns.CanonicalName(target)

	for _, rec := range recs {
		if mdns.CanonicalName(rec.Header().Name) == targetCanon {
			return rec
		}
	}

	for _, rec := range recs {
		if !strings.HasPrefix(rec.Header().Name, "*.") {
			return rec
		}
	}
	return nil
}

// isValidDNSName filters out names with null bytes, non-printable chars,
// or wire-format artifacts from NSEC walking (e.g. Cloudflare black lies).
func isValidDNSName(name string) bool {
	if len(name) == 0 || len(name) > 255 {
		return false
	}
	if strings.Contains(name, "\\000") || strings.Contains(name, "\\00") {
		return false
	}
	for _, c := range name {
		if c == 0 || (c < 32 && c != '-') {
			return false
		}
	}
	return true
}

// isBlackLiesPattern detects Cloudflare-style NSEC "black lies" where
// the server synthesizes fake NSEC records with incrementing null-byte names.
func isBlackLiesPattern(owner, next string) bool {
	if strings.Contains(next, "\\000") || strings.Contains(next, "\\00") {
		return true
	}
	for _, c := range next {
		if c == 0 {
			return true
		}
	}
	return false
}

// probeNSEC3 sends a few NXDOMAIN probes to collect NSEC3 denial records.
func probeNSEC3(domain, ns string, result *DNSSECResult) {
	probes := []string{
		fmt.Sprintf("_nshunter-probe-1.%s", domain),
		fmt.Sprintf("_nshunter-probe-2.%s", domain),
		fmt.Sprintf("aaaa-nshunter.%s", domain),
		fmt.Sprintf("zzzz-nshunter.%s", domain),
	}

	c := &mdns.Client{Net: "tcp", Timeout: nsecWalkTimeout}

	for _, probe := range probes {
		m := new(mdns.Msg)
		m.SetQuestion(probe, mdns.TypeA)
		m.SetEdns0(4096, true)

		r, _, err := c.Exchange(m, ns)
		if err != nil {
			continue
		}

		for _, rr := range r.Ns {
			switch rec := rr.(type) {
			case *mdns.NSEC3:
				n3 := NSEC3Record{
					HashedOwner: extractNSEC3Hash(rec.Header().Name),
					NextHashed:  rec.NextDomain,
					Zone:        domain,
				}
				for _, t := range rec.TypeBitMap {
					n3.Types = append(n3.Types, t)
				}
				result.NSEC3Records = append(result.NSEC3Records, n3)
			case *mdns.RRSIG:
				result.RRSIGCount++
			}
		}
	}
}

func extractNSEC3Hash(name string) string {
	parts := strings.SplitN(name, ".", 2)
	if len(parts) > 0 {
		return strings.ToUpper(parts[0])
	}
	return name
}
