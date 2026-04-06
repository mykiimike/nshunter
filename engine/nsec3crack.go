// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package engine

import (
	"log"
	"runtime"
	"sort"
	"sync"

	"github.com/mykiimike/nshunter/metal"
)

const minCorpusParallel = 512
const minCorpusGPU = 1024

// crackNSEC3Corpus hashes every corpus label with NSEC3Hash (same work as `benchmark` CPU)
// and returns FQDNs whose hash appears in observed. Uses all CPUs when the corpus is large enough.
func crackNSEC3Corpus(observed map[string]bool, corpus []string, domain string, iterations uint16, saltHex string) []string {
	n := len(corpus)
	if n == 0 {
		return nil
	}
	if runtime.GOOS == "darwin" && n >= minCorpusGPU {
		if out, device, err := crackNSEC3CorpusGPU(observed, corpus, domain, iterations, saltHex); err == nil {
			log.Printf("[debug] NSEC3 cracking backend: %s", device)
			return out
		} else {
			log.Printf("[debug] NSEC3 GPU crack unavailable (%v); falling back to CPU", err)
		}
	}
	if n < minCorpusParallel {
		return crackNSEC3CorpusSequential(observed, corpus, domain, iterations, saltHex)
	}
	return crackNSEC3CorpusParallel(observed, corpus, domain, iterations, saltHex)
}

func crackNSEC3CorpusSequential(observed map[string]bool, corpus []string, domain string, iterations uint16, saltHex string) []string {
	nh, err := newNSEC3Hasher(domain, iterations, saltHex)
	if err != nil {
		return nil
	}
	var out []string
	for _, label := range corpus {
		if observed[nh.Hash(label)] {
			out = append(out, label+"."+domain)
		}
	}
	return out
}

func crackNSEC3CorpusParallel(observed map[string]bool, corpus []string, domain string, iterations uint16, saltHex string) []string {
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	n := len(corpus)
	chunk := (n + workers - 1) / workers
	if chunk < 1 {
		chunk = 1
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []string

	for start := 0; start < n; start += chunk {
		end := start + chunk
		if end > n {
			end = n
		}
		part := corpus[start:end]
		wg.Add(1)
		go func(labels []string) {
			defer wg.Done()
			nh, err := newNSEC3Hasher(domain, iterations, saltHex)
			if err != nil {
				return
			}
			var local []string
			for _, label := range labels {
				if observed[nh.Hash(label)] {
					local = append(local, label+"."+domain)
				}
			}
			if len(local) == 0 {
				return
			}
			mu.Lock()
			out = append(out, local...)
			mu.Unlock()
		}(part)
	}

	wg.Wait()
	sort.Strings(out)
	return out
}

func crackNSEC3CorpusGPU(observed map[string]bool, corpus []string, domain string, iterations uint16, saltHex string) ([]string, string, error) {
	hashes, device, err := metal.HashBatch(corpus, domain, iterations, saltHex)
	if err != nil {
		return nil, "", err
	}
	out := make([]string, 0, len(corpus)/10)
	for _, label := range corpus {
		if observed[hashes[label]] {
			out = append(out, label+"."+domain)
		}
	}
	sort.Strings(out)
	return out, device, nil
}
