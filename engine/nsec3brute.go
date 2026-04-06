// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package engine

import (
	"fmt"
	"log"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const bruteAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789-"

func bruteforceCount(maxLen int) uint64 {
	n := uint64(len(bruteAlphabet))
	total := uint64(0)
	p := uint64(1)
	for l := 1; l <= maxLen; l++ {
		p *= n
		total += p
	}
	return total
}

// crackNSEC3Bruteforce tries every combination of bruteAlphabet up to maxLen.
// Workers generate and hash in-place without intermediate buffers.
func crackNSEC3Bruteforce(observed map[string]bool, domain string, iterations uint16, saltHex string, maxLen int) []string {
	total := bruteforceCount(maxLen)
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}

	log.Printf("[debug] NSEC3 bruteforce: alphabet=%d chars, max_len=%d, combinations=%d, workers=%d",
		len(bruteAlphabet), maxLen, total, workers)

	remaining := make(map[string]bool, len(observed))
	for h := range observed {
		remaining[h] = true
	}

	alpha := []byte(bruteAlphabet)
	alphaLen := len(alpha)

	var mu sync.Mutex
	var allMatches []string
	var tested atomic.Int64
	start := time.Now()

	for length := 1; length <= maxLen; length++ {
		mu.Lock()
		done := len(remaining) == 0
		mu.Unlock()
		if done {
			log.Printf("[debug] NSEC3 bruteforce: all hashes cracked, stopping early at length %d", length)
			break
		}

		combos := 1
		for i := 0; i < length; i++ {
			combos *= alphaLen
		}

		chunkSize := (combos + workers - 1) / workers
		var wg sync.WaitGroup

		for w := 0; w < workers; w++ {
			lo := w * chunkSize
			hi := lo + chunkSize
			if hi > combos {
				hi = combos
			}
			if lo >= combos {
				break
			}

			wg.Add(1)
			go func(lo, hi, length int) {
				defer wg.Done()
				nh, err := newNSEC3Hasher(domain, iterations, saltHex)
				if err != nil {
					return
				}

				// Take a read-only snapshot to avoid locking on every hash
				mu.Lock()
				snap := make(map[string]bool, len(remaining))
				for h := range remaining {
					snap[h] = true
				}
				mu.Unlock()

				buf := make([]byte, length)
				var local []struct {
					fqdn string
					hash string
				}

				for idx := lo; idx < hi; idx++ {
					v := idx
					for pos := length - 1; pos >= 0; pos-- {
						buf[pos] = alpha[v%alphaLen]
						v /= alphaLen
					}

					h := nh.HashBytes(buf)
					if snap[h] {
						local = append(local, struct {
							fqdn string
							hash string
						}{string(buf) + "." + domain, h})
					}
				}

				tested.Add(int64(hi - lo))

				if len(local) > 0 {
					mu.Lock()
					for _, hit := range local {
						if remaining[hit.hash] {
							delete(remaining, hit.hash)
							allMatches = append(allMatches, hit.fqdn)
						}
					}
					mu.Unlock()
				}
			}(lo, hi, length)
		}
		wg.Wait()

		mu.Lock()
		rem := len(remaining)
		mu.Unlock()
		log.Printf("[debug] NSEC3 bruteforce: length %d done (%d tested), %d matches so far, %d hashes remaining",
			length, combos, len(allMatches), rem)
	}

	elapsed := time.Since(start)
	rate := float64(0)
	if elapsed.Seconds() > 0 {
		rate = float64(tested.Load()) / elapsed.Seconds()
	}
	log.Printf("[debug] NSEC3 bruteforce: %d matches in %s (%d combinations, %.2e/s)",
		len(allMatches), elapsed.Round(time.Millisecond), total, rate)

	sort.Strings(allMatches)
	return allMatches
}

func formatBruteCount(n uint64) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1fB", float64(n)/1e9)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1_000:
		return fmt.Sprintf("%.1fK", float64(n)/1e3)
	default:
		return fmt.Sprintf("%d", n)
	}
}
