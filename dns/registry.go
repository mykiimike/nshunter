// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// RegistryBreakdown holds hostnames discovered per passive registry source (before cross-source dedup).
type RegistryBreakdown struct {
	CRTSH       []string `json:"crtsh,omitempty"`
	CertSpotter []string `json:"certspotter,omitempty"`
	Censys      []string `json:"censys,omitempty"`
}

const (
	envCertSpotterKey = "CERTSPOTTER_API_KEY"
	envCensysID       = "CENSYS_API_ID"
	envCensysSecret   = "CENSYS_API_SECRET"

	certSpotterBaseURL = "https://api.certspotter.com/v1/issuances"
	censysSearchURL    = "https://search.censys.io/api/v2/certificates/search"

	maxCertSpotterPages = 80
	maxCensysPages      = 50
)

// CollectRegistryNames queries passive certificate registries and returns deduplicated names under zone.
// Sources: crt.sh (always), Cert Spotter (optional API key), Censys certificates (optional API ID+secret).
func CollectRegistryNames(domain string) (merged []string, breakdown RegistryBreakdown) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return nil, breakdown
	}

	log.Printf("[debug] registry: passive certificate lookups for zone %q — order: (1) crt.sh → (2) Cert Spotter (SSLMate) → (3) Censys certs if API credentials are set", domain)

	breakdown.CRTSH = QueryCTLogs(domain)

	key := strings.TrimSpace(os.Getenv(envCertSpotterKey))
	if key != "" {
		log.Printf("[debug] registry [Cert Spotter]: will use %s (Bearer) against api.certspotter.com", envCertSpotterKey)
	} else {
		log.Printf("[debug] registry [Cert Spotter]: no %s — calling unauthenticated quota (limited); set the key for higher rate limits", envCertSpotterKey)
	}
	breakdown.CertSpotter = queryCertSpotter(domain, key)

	id := strings.TrimSpace(os.Getenv(envCensysID))
	sec := strings.TrimSpace(os.Getenv(envCensysSecret))
	if id != "" && sec != "" {
		breakdown.Censys = queryCensysCertificates(domain, id, sec)
	} else {
		log.Printf("[debug] registry [Censys]: skipped — set %s and %s to query search.censys.io certificate index for this zone", envCensysID, envCensysSecret)
	}

	seen := make(map[string]bool)
	var out []string
	add := func(list []string) {
		for _, n := range list {
			if n == "" || seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, n)
		}
	}
	add(breakdown.CRTSH)
	add(breakdown.CertSpotter)
	add(breakdown.Censys)
	sort.Strings(out)
	return out, breakdown
}

// --- Cert Spotter (SSLMate) -------------------------------------------------

type certSpotterIssuance struct {
	ID       string   `json:"id"`
	DNSNames []string `json:"dns_names"`
}

func queryCertSpotter(domain, apiKey string) []string {
	log.Printf("[debug] registry [Cert Spotter]: querying SSLMate CT Search API — GET %s?domain=%s&include_subdomains&match_wildcards&expand=dns_names (paginated)", certSpotterBaseURL, domain)
	client := &http.Client{Timeout: 45 * time.Second}
	var all []certSpotterIssuance
	after := ""
	for page := 0; page < maxCertSpotterPages; page++ {
		q := url.Values{}
		q.Set("domain", domain)
		q.Set("include_subdomains", "true")
		q.Set("match_wildcards", "true")
		q.Set("expand", "dns_names")
		if after != "" {
			q.Set("after", after)
		}
		raw := certSpotterBaseURL + "?" + q.Encode()
		part, lastID, ok := fetchCertSpotterPage(client, raw, apiKey)
		if !ok {
			break
		}
		if len(part) == 0 {
			break
		}
		all = append(all, part...)
		after = lastID
	}

	names := namesUnderZoneFromStrings(domain, extractDNSNamesFromIssuances(all))
	log.Printf("[debug] registry [Cert Spotter]: done — %d unique hostnames under zone from %d issuance rows", len(names), len(all))
	return names
}

func extractDNSNamesFromIssuances(all []certSpotterIssuance) []string {
	var raw []string
	for _, iss := range all {
		for _, n := range iss.DNSNames {
			raw = append(raw, n)
		}
	}
	return raw
}

func fetchCertSpotterPage(client *http.Client, rawURL, apiKey string) ([]certSpotterIssuance, string, bool) {
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*2) * time.Second)
		}
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			log.Printf("[warn] registry [Cert Spotter]: %v", err)
			return nil, "", false
		}
		req.Header.Set("User-Agent", ctUserAgent)
		req.Header.Set("Accept", "application/json")
		if apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[warn] registry [Cert Spotter]: %v", err)
			return nil, "", false
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil {
			log.Printf("[warn] registry [Cert Spotter]: read body: %v", err)
			return nil, "", false
		}

		switch resp.StatusCode {
		case http.StatusOK:
			var issuances []certSpotterIssuance
			if err := json.Unmarshal(body, &issuances); err != nil {
				log.Printf("[warn] registry [Cert Spotter]: JSON: %v", err)
				return nil, "", false
			}
			lastID := ""
			if len(issuances) > 0 {
				lastID = issuances[len(issuances)-1].ID
			}
			return issuances, lastID, true
		case http.StatusTooManyRequests, http.StatusServiceUnavailable:
			log.Printf("[debug] registry [Cert Spotter]: HTTP %d — retry", resp.StatusCode)
			continue
		case http.StatusUnauthorized, http.StatusPaymentRequired:
			log.Printf("[warn] registry [Cert Spotter]: HTTP %d — check API key / plan", resp.StatusCode)
			return nil, "", false
		default:
			log.Printf("[warn] registry [Cert Spotter]: HTTP %d", resp.StatusCode)
			return nil, "", false
		}
	}
	log.Printf("[warn] registry [Cert Spotter]: gave up after retries")
	return nil, "", false
}

// --- Censys Search API v2 (certificates) ------------------------------------

type censysSearchRequest struct {
	Q       string   `json:"q"`
	PerPage int      `json:"per_page"`
	Cursor  string   `json:"cursor,omitempty"`
	Fields  []string `json:"fields,omitempty"`
}

type censysSearchResponse struct {
	Code   int    `json:"code"`
	Status string `json:"status"`
	Result *struct {
		Hits  []json.RawMessage `json:"hits"`
		Links struct {
			Next string `json:"next"`
		} `json:"links"`
	} `json:"result"`
}

func queryCensysCertificates(domain, apiID, apiSecret string) []string {
	client := &http.Client{Timeout: 60 * time.Second}
	// Censys Search Language — certificate SANs matching apex or wildcard under zone.
	q := fmt.Sprintf(`(parsed.names: "%s" or parsed.names: "*.%s")`, domain, domain)

	log.Printf("[debug] registry [Censys]: querying certificate search — POST %s (Search API v2, Basic auth, fields=parsed.names)", censysSearchURL)
	log.Printf("[debug] registry [Censys]: Censys query string: %s", q)

	var rawNames []string
	cursor := ""
	for page := 0; page < maxCensysPages; page++ {
		body, err := json.Marshal(censysSearchRequest{
			Q:       q,
			PerPage: 100,
			Cursor:  cursor,
			Fields:  []string{"parsed.names"},
		})
		if err != nil {
			log.Printf("[warn] registry [Censys]: %v", err)
			break
		}
		req, err := http.NewRequest(http.MethodPost, censysSearchURL, bytes.NewReader(body))
		if err != nil {
			log.Printf("[warn] registry [Censys]: %v", err)
			break
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", ctUserAgent)
		req.SetBasicAuth(apiID, apiSecret)

		if page == 0 {
			log.Printf("[debug] registry [Censys]: request page 1 (cursor empty)")
		} else {
			log.Printf("[debug] registry [Censys]: request page %d (next cursor)", page+1)
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[warn] registry [Censys]: %v", err)
			break
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if err != nil {
			log.Printf("[warn] registry [Censys]: read: %v", err)
			break
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("[warn] registry [Censys]: HTTP %d: %s", resp.StatusCode, truncateForLog(b, 200))
			break
		}

		var parsed censysSearchResponse
		if err := json.Unmarshal(b, &parsed); err != nil {
			log.Printf("[warn] registry [Censys]: JSON: %v", err)
			break
		}
		if parsed.Result == nil || len(parsed.Result.Hits) == 0 {
			break
		}
		for _, hit := range parsed.Result.Hits {
			rawNames = append(rawNames, extractNamesFromCensysHit(hit)...)
		}
		if parsed.Result.Links.Next == "" {
			break
		}
		cursor = parsed.Result.Links.Next
	}

	names := namesUnderZoneFromStrings(domain, rawNames)
	log.Printf("[debug] registry [Censys]: done — %d unique hostnames under zone from certificate SANs in search hits", len(names))
	return names
}

func extractNamesFromCensysHit(hit json.RawMessage) []string {
	var top struct {
		Parsed *struct {
			Names []string `json:"names"`
		} `json:"parsed"`
	}
	if err := json.Unmarshal(hit, &top); err != nil {
		return nil
	}
	if top.Parsed == nil {
		return nil
	}
	return top.Parsed.Names
}

func truncateForLog(b []byte, max int) string {
	s := string(b)
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// namesUnderZoneFromStrings applies the same hostname rules as crt.sh parsing (concrete names under zone).
func namesUnderZoneFromStrings(zone string, raw []string) []string {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	seen := make(map[string]bool)
	var out []string
	for _, s := range raw {
		for _, name := range strings.Split(s, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimSuffix(name, ".")
			if name == "" || seen[name] {
				continue
			}
			name = strings.TrimPrefix(name, "*.")
			if name == zone {
				continue
			}
			if !strings.HasSuffix(name, "."+zone) && name != zone {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
