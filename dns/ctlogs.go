// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package dns

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type crtEntry struct {
	NameValue string `json:"name_value"`
}

const ctUserAgent = "nshunter/1.0 (defensive zone audit)"

// QueryCTLogs fetches subdomains from Certificate Transparency logs via crt.sh.
// HTTP 404 means no matching rows for that query — we try a second pattern (Identity).
func QueryCTLogs(domain string) []string {
	domain = strings.TrimSuffix(domain, ".")

	client := &http.Client{Timeout: 25 * time.Second}

	log.Printf("[debug] registry [crt.sh]: querying public CT mirror for zone %q — two HTTPS GETs (q=%%.zone + Identity)", domain)

	// q=%.zone — wildcard subdomains (percent encoded once in query string)
	wildcardQ := "%." + domain
	u1 := fmt.Sprintf("https://crt.sh/?q=%s&output=json", url.QueryEscape(wildcardQ))
	u2 := fmt.Sprintf("https://crt.sh/?Identity=%s&output=json", url.QueryEscape(domain))

	var all []crtEntry
	for i, rawURL := range []string{u1, u2} {
		label := "wildcard %.zone"
		if i == 1 {
			label = "Identity=apex"
		}
		log.Printf("[debug] registry [crt.sh]: request %d/2 (%s) → %s", i+1, label, rawURL)
		part := fetchCTEntries(client, rawURL)
		all = append(all, part...)
	}

	seen := make(map[string]bool)
	var names []string

	for _, e := range all {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimSuffix(name, ".")
			if name == "" || seen[name] {
				continue
			}
			if strings.HasPrefix(name, "*.") {
				name = name[2:]
			}
			if name == domain || seen[name] {
				continue
			}
			if !strings.HasSuffix(name, "."+domain) && name != domain {
				continue
			}
			seen[name] = true
			names = append(names, name)
		}
	}

	sort.Strings(names)
	if len(names) == 0 && len(all) > 0 {
		log.Printf("[debug] registry [crt.sh]: 0 concrete subdomains under %q from %d cert rows (apex and *.zone SANs skipped)", domain, len(all))
	} else {
		log.Printf("[debug] registry [crt.sh]: done — %d unique hostnames under zone from %d certificate rows", len(names), len(all))
	}
	return names
}

// fetchCTEntries retries on 429/503; treats 404 as empty result.
func fetchCTEntries(client *http.Client, rawURL string) []crtEntry {
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			wait := time.Duration(attempt*2) * time.Second
			log.Printf("[debug] registry [crt.sh]: retry %d after %s", attempt, wait)
			time.Sleep(wait)
		}

		entries, code, err := fetchCTOnce(client, rawURL)
		if err != nil {
			log.Printf("[warn] registry [crt.sh]: %v", err)
			return nil
		}
		switch code {
		case 200:
			return entries
		case 404:
			log.Printf("[debug] registry [crt.sh]: HTTP 404 — no rows for this query pattern")
			return nil
		case 429, 503:
			log.Printf("[debug] registry [crt.sh]: HTTP %d — will retry", code)
			continue
		default:
			log.Printf("[warn] registry [crt.sh]: HTTP %d", code)
			return nil
		}
	}
	log.Printf("[warn] registry [crt.sh]: gave up after retries for host %s", hostOnly(rawURL))
	return nil
}

func hostOnly(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "crt.sh"
	}
	return u.Host
}

func fetchCTOnce(client *http.Client, rawURL string) ([]crtEntry, int, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", ctUserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}

	code := resp.StatusCode
	if code == 404 {
		return nil, 404, nil
	}
	if code != 200 {
		return nil, code, nil
	}

	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, code, fmt.Errorf("JSON: %w", err)
	}
	return entries, 200, nil
}
