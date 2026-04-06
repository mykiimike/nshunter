// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package dns

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"strings"
	"sync"
	"sync/atomic"

	mdns "github.com/miekg/dns"
)

// NSEC3WalkResult holds the outcome of an NSEC3 zone walk.
type NSEC3WalkResult struct {
	Hashes     map[string]bool // all unique hashes discovered (owner + next)
	Records    []NSEC3Record
	Coverage   float64
	Queries    int
	FullyCover bool
	OptOut     bool // true if any NSEC3 record had the opt-out flag
}

const walkConcurrency = 20

// WalkNSEC3Zone performs NSEC3 zone walking via concurrent random-probe enumeration.
// Each NXDOMAIN response reveals NSEC3 hash chain entries. Over many queries,
// the chain fills up, exposing hashes that can be cracked against a dictionary.
func WalkNSEC3Zone(domain, ns string, maxQueries int) *NSEC3WalkResult {
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	// Find all authoritative nameservers for round-robin
	nameservers := resolveAllNS(domain, ns)
	if len(nameservers) == 0 {
		nameservers = []string{ns}
	}
	log.Printf("[debug] NSEC3 walk: %d nameservers for round-robin: %v", len(nameservers), nameservers)

	result := &NSEC3WalkResult{
		Hashes: make(map[string]bool),
	}

	var mu sync.Mutex
	seenPairs := make(map[string]bool)
	chainCount := 0

	type nsec3Hit struct {
		owner string
		next  string
		rec   *mdns.NSEC3
	}

	addRecord := func(owner, next string, rec *mdns.NSEC3) bool {
		ownerUp := strings.ToUpper(owner)
		nextUp := strings.ToUpper(next)
		key := ownerUp + "|" + nextUp
		mu.Lock()
		defer mu.Unlock()
		if seenPairs[key] {
			return false
		}
		seenPairs[key] = true
		result.Hashes[ownerUp] = true
		result.Hashes[nextUp] = true
		chainCount++

		if rec.Flags&1 != 0 {
			result.OptOut = true
		}

		n3 := NSEC3Record{
			HashedOwner: ownerUp,
			NextHashed:  nextUp,
			Zone:        domain,
		}
		for _, t := range rec.TypeBitMap {
			n3.Types = append(n3.Types, t)
		}
		result.Records = append(result.Records, n3)
		return true
	}

	var queryCount atomic.Int64
	var staleCount atomic.Int64

	var wg sync.WaitGroup
	sem := make(chan struct{}, walkConcurrency)

	for queryCount.Load() < int64(maxQueries) && staleCount.Load() < 100 {
		sem <- struct{}{}
		if queryCount.Load() >= int64(maxQueries) || staleCount.Load() >= 100 {
			<-sem
			break
		}

		wg.Add(1)
		nsIdx := int(queryCount.Load()) % len(nameservers)
		targetNS := nameservers[nsIdx]
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()

			c := &mdns.Client{Net: "tcp", Timeout: nsecWalkTimeout}
			probe := randomSubdomain(domain)
			records := queryNSEC3(c, probe, target)
			q := queryCount.Add(1)

			foundNew := false
			for _, rec := range records {
				owner := extractNSEC3Hash(rec.Header().Name)
				if addRecord(owner, rec.NextDomain, rec) {
					foundNew = true
				}
			}

			if foundNew {
				staleCount.Store(0)
			} else {
				staleCount.Add(1)
			}

			if q%500 == 0 {
				mu.Lock()
				log.Printf("[info] NSEC3 walk: %d queries, %d unique hashes, %d chain entries",
					q, len(result.Hashes), chainCount)
				mu.Unlock()
			}
		}(targetNS)
	}

	wg.Wait()

	result.Queries = int(queryCount.Load())
	mu.Lock()
	result.Coverage = float64(chainCount)
	if staleCount.Load() >= 100 {
		result.FullyCover = true
		log.Printf("[debug] NSEC3 walk: chain saturated after %d stale queries", staleCount.Load())
	}
	mu.Unlock()

	return result
}

func resolveAllNS(domain, fallbackNS string) []string {
	c := &mdns.Client{Net: "tcp", Timeout: nsecWalkTimeout}
	m := new(mdns.Msg)
	m.SetQuestion(domain, mdns.TypeNS)
	r, _, err := c.Exchange(m, fallbackNS)
	if err != nil {
		return nil
	}

	var nsList []string
	for _, rr := range r.Answer {
		if ns, ok := rr.(*mdns.NS); ok {
			nsList = append(nsList, ns.Ns)
		}
	}
	if len(nsList) == 0 {
		for _, rr := range r.Ns {
			if ns, ok := rr.(*mdns.NS); ok {
				nsList = append(nsList, ns.Ns)
			}
		}
	}

	var addrs []string
	for _, nsName := range nsList {
		m2 := new(mdns.Msg)
		m2.SetQuestion(nsName, mdns.TypeA)
		r2, _, err := c.Exchange(m2, "8.8.8.8:53")
		if err != nil {
			continue
		}
		for _, rr := range r2.Answer {
			if a, ok := rr.(*mdns.A); ok {
				addrs = append(addrs, a.A.String()+":53")
			}
		}
	}
	return addrs
}

func queryNSEC3(c *mdns.Client, name, ns string) []*mdns.NSEC3 {
	m := new(mdns.Msg)
	m.SetQuestion(name, mdns.TypeA)
	m.SetEdns0(4096, true)

	r, _, err := c.Exchange(m, ns)
	if err != nil {
		return nil
	}

	var records []*mdns.NSEC3
	for _, rr := range r.Ns {
		if rec, ok := rr.(*mdns.NSEC3); ok {
			records = append(records, rec)
		}
	}
	return records
}

func randomSubdomain(domain string) string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b) + "." + domain
}
