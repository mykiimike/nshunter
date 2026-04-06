// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package dns

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mykiimike/nshunter/logx"
)

const bruteConcurrency = 50

// BruteSubdomains tests a list of candidate labels as subdomains, keeping those
// that resolve to at least one A/AAAA record. Pure DNS resolution, no DNSSEC needed.
func BruteSubdomains(domain string, labels []string) []string {
	domain = strings.TrimSuffix(domain, ".")

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.DialTimeout("tcp", "8.8.8.8:53", 3*time.Second)
		},
	}

	var mu sync.Mutex
	var found []string
	var tested atomic.Int64

	sem := make(chan struct{}, bruteConcurrency)
	var wg sync.WaitGroup

	for _, label := range labels {
		sem <- struct{}{}
		wg.Add(1)
		go func(l string) {
			defer wg.Done()
			defer func() { <-sem }()

			fqdn := l + "." + domain
			addrs, err := resolver.LookupHost(context.Background(), fqdn)
			n := tested.Add(1)

			if err == nil && len(addrs) > 0 {
				mu.Lock()
				found = append(found, fqdn)
				mu.Unlock()
				logx.SuperDebugf("bruteforce hit: %s", fqdn)
			}

			if n%1000 == 0 {
				mu.Lock()
				log.Printf("[debug] bruteforce: %d/%d tested, %d found", n, len(labels), len(found))
				mu.Unlock()
			}
		}(label)
	}

	wg.Wait()

	log.Printf("[debug] bruteforce: %d/%d labels resolved", len(found), len(labels))
	return found
}
