// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package engine

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func loadCorpus(path string) ([]string, error) {
	if path == "" {
		return defaultCorpus(), nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var labels []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			labels = append(labels, line)
		}
	}
	return labels, sc.Err()
}

// LoadCorpus returns either the built-in corpus or a custom one from file.
func LoadCorpus(path string) ([]string, error) {
	return loadCorpus(path)
}

func defaultCorpus() []string {
	// Static labels: subdomains + common SLDs
	seeds := []string{
		"www", "mail", "mx", "ns1", "ns2", "ns3", "ns4", "ftp", "smtp", "pop", "imap",
		"webmail", "autodiscover", "autoconfig", "vpn", "remote", "owa",
		"api", "dev", "staging", "test", "beta", "alpha", "admin", "portal",
		"blog", "shop", "store", "cdn", "static", "assets", "media",
		"app", "m", "mobile", "secure", "login", "auth", "sso",
		"docs", "wiki", "help", "support", "status", "monitor",
		"db", "database", "redis", "elastic", "kibana", "grafana",
		"ci", "jenkins", "gitlab", "git", "registry", "docker",
		"k8s", "kube", "prometheus", "alertmanager", "vault",
		"_dmarc", "_domainkey", "_spf", "_acme-challenge",
		"www2", "www3", "proxy", "gateway", "gw", "relay", "edge",
		"backup", "bak", "old", "new", "web", "web1", "web2",
		"mail2", "mail3", "mx1", "mx2", "mx3", "pop3", "imap4",
		"exchange", "outlook", "office", "teams", "meet",
		"intranet", "extranet", "internal", "external", "dmz",
		"dns1", "dns2", "ntp", "time", "syslog", "log", "logs",
		"ldap", "ad", "dc", "dc1", "dc2", "pdc", "kdc",
		"radius", "tacacs", "noc", "soc",
		"dev1", "dev2", "qa", "uat", "pre", "preprod", "prod",
		"stage", "sandbox", "demo", "lab", "labs",
		"repo", "svn", "hg", "bitbucket", "github", "codecommit",
		"jira", "confluence", "slack", "mattermost",
		"s3", "storage", "nas", "san", "nfs", "cifs", "smb",
		"cloud", "aws", "azure", "gcp", "oracle",
		"node1", "node2", "node3", "worker1", "worker2", "master",
		// Common SLDs for TLD analysis
		"google", "facebook", "amazon", "apple", "microsoft", "netflix", "twitter",
		"instagram", "linkedin", "youtube", "wikipedia", "reddit",
		"yahoo", "bing", "baidu", "alibaba", "tencent", "samsung", "sony",
		"ibm", "cisco", "intel", "amd", "nvidia", "dell", "hp",
		"adobe", "salesforce", "vmware", "sap", "siemens", "bosch",
		"disney", "spotify", "uber", "airbnb", "paypal", "stripe", "visa",
		"mastercard", "chase", "citi", "hsbc", "barclays", "goldman",
		"ford", "toyota", "bmw", "mercedes", "audi", "tesla", "honda",
		"pfizer", "johnson", "roche", "novartis", "merck", "abbott",
		"boeing", "airbus", "lockheed", "raytheon", "northrop",
		"att", "verizon", "comcast", "sprint", "tmobile", "vodafone",
		"cloudflare", "akamai", "fastly",
		"godaddy", "namecheap", "gandi", "ovh", "hetzner", "digitalocean",
		"heroku", "vercel", "netlify",
		"wordpress", "blogger", "medium", "substack",
		"shopify", "magento", "woocommerce",
		"zoom", "webex", "skype", "signal", "telegram", "whatsapp",
		"dropbox", "box", "onedrive", "icloud",
		"security", "secure", "ssl", "tls", "cert", "pki",
		"bank", "finance", "invest", "trade", "crypto", "bitcoin",
		"health", "medical", "pharma", "hospital", "clinic",
		"university", "school", "college", "academy",
		"government", "state", "federal", "city", "county",
		"news", "press", "tv", "radio", "podcast",
		"sport", "game", "play", "music", "video", "photo",
		"travel", "hotel", "flight", "booking", "trip",
		"food", "restaurant", "delivery", "order",
		"email", "chat", "forum", "community",
		"jobs", "career", "hire", "talent", "recruit",
		"data", "analytics", "ai", "deep", "learn",
		"iot", "smart", "auto", "robot",
		"open", "free", "public", "private", "premium",
		"example", "sample", "temp",
		"info", "about", "contact", "home", "main", "index",
		"site", "online", "tech", "digital", "cyber",
		"server", "host", "domain", "dns",
		"android", "ios", "swift", "kotlin",
		"python", "java", "golang", "rust", "react",
		"linux", "windows", "macos", "unix", "debian", "ubuntu",
		"kubernetes", "terraform", "ansible", "puppet",
	}

	return generateCorpus(seeds)
}

func generateCorpus(seeds []string) []string {
	seen := make(map[string]bool)
	var all []string

	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		all = append(all, s)
	}

	for _, s := range seeds {
		add(s)
	}

	// Numeric labels: 0-9999
	for i := 0; i < 10000; i++ {
		add(fmt.Sprintf("%d", i))
	}

	// Common patterns with numbers
	bases := []string{
		"ns", "dns", "mx", "mail", "web", "www", "ftp", "vpn", "api",
		"app", "db", "dev", "srv", "host", "node", "server", "dc",
		"gw", "fw", "lb", "proxy", "cache", "cdn", "pop", "imap",
		"smtp", "ntp", "log", "mon", "test", "stage", "prod",
	}
	for _, b := range bases {
		for i := 0; i <= 20; i++ {
			add(fmt.Sprintf("%s%d", b, i))
		}
	}

	// 2-letter combinations (aa-zz)
	for c1 := byte('a'); c1 <= 'z'; c1++ {
		for c2 := byte('a'); c2 <= 'z'; c2++ {
			add(string([]byte{c1, c2}))
		}
	}

	// 3-letter combinations (common)
	for c1 := byte('a'); c1 <= 'z'; c1++ {
		for c2 := byte('a'); c2 <= 'z'; c2++ {
			for c3 := byte('a'); c3 <= 'z'; c3++ {
				add(string([]byte{c1, c2, c3}))
			}
		}
	}

	return all
}
