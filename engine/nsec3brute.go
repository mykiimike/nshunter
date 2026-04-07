// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package engine

import (
	"fmt"
	"log"
	"math"
	"runtime"
	"sort"
	"strings"
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
	return crackNSEC3BruteforceCore(observed, domain, iterations, saltHex, maxLen, 0)
}

func crackNSEC3BruteforceTimeout(observed map[string]bool, domain string, iterations uint16, saltHex string, ttl time.Duration) []string {
	return crackNSEC3BruteforceCore(observed, domain, iterations, saltHex, 0, ttl)
}

func crackNSEC3BruteforceCore(observed map[string]bool, domain string, iterations uint16, saltHex string, maxLen int, ttl time.Duration) []string {
	var total uint64
	if maxLen > 0 {
		total = bruteforceCount(maxLen)
	}
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}

	if ttl > 0 {
		log.Printf("[debug] NSEC3 bruteforce: alphabet=%d chars, timeout=%s, workers=%d",
			len(bruteAlphabet), ttl.Round(time.Second), workers)
	} else {
		log.Printf("[debug] NSEC3 bruteforce: alphabet=%d chars, max_len=%d, combinations=%d, workers=%d",
			len(bruteAlphabet), maxLen, total, workers)
	}

	remaining := make(map[string]bool, len(observed))
	for h := range observed {
		remaining[h] = true
	}

	alpha := []byte(bruteAlphabet)
	alphaLen := len(alpha)

	var mu sync.Mutex
	var allMatches []string
	var tested atomic.Uint64
	start := time.Now()
	deadline := time.Time{}
	if ttl > 0 {
		deadline = start.Add(ttl)
	}

	for length := 1; ; length++ {
		if maxLen > 0 && length > maxLen {
			break
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			log.Printf("[debug] NSEC3 bruteforce: timeout reached before starting length %d", length)
			break
		}
		mu.Lock()
		done := len(remaining) == 0
		mu.Unlock()
		if done {
			log.Printf("[debug] NSEC3 bruteforce: all hashes cracked, stopping early at length %d", length)
			break
		}

		combos := 1
		for i := 0; i < length; i++ {
			if combos > math.MaxInt/alphaLen {
				log.Printf("[warn] NSEC3 bruteforce: stopping at length %d (combinations overflow host integer size)", length)
				length = maxLen + 1
				combos = 0
				break
			}
			combos *= alphaLen
		}
		if combos == 0 {
			break
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
				var localTested uint64

				for idx := lo; idx < hi; idx++ {
					if !deadline.IsZero() && idx%1024 == 0 && time.Now().After(deadline) {
						break
					}
					v := idx
					for pos := length - 1; pos >= 0; pos-- {
						buf[pos] = alpha[v%alphaLen]
						v /= alphaLen
					}

					h := nh.HashBytes(buf)
					localTested++
					if snap[h] {
						local = append(local, struct {
							fqdn string
							hash string
						}{string(buf) + "." + domain, h})
					}
				}

				tested.Add(localTested)

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
		if !deadline.IsZero() {
			left := time.Until(deadline)
			if left < 0 {
				left = 0
			}
			log.Printf("[debug] NSEC3 bruteforce: length %d done, %d matches so far, %d hashes remaining, %s left",
				length, len(allMatches), rem, left.Round(time.Second))
			if left == 0 {
				break
			}
		} else {
			log.Printf("[debug] NSEC3 bruteforce: length %d done (%d tested), %d matches so far, %d hashes remaining",
				length, combos, len(allMatches), rem)
		}
	}

	elapsed := time.Since(start)
	rate := float64(0)
	if elapsed.Seconds() > 0 {
		rate = float64(tested.Load()) / elapsed.Seconds()
	}
	if ttl > 0 {
		log.Printf("[debug] NSEC3 bruteforce: %d matches in %s (%s tested, %.2e/s, timeout=%s)",
			len(allMatches), elapsed.Round(time.Millisecond), formatBruteCount(tested.Load()), rate, ttl.Round(time.Second))
	} else {
		log.Printf("[debug] NSEC3 bruteforce: %d matches in %s (%d combinations, %.2e/s)",
			len(allMatches), elapsed.Round(time.Millisecond), total, rate)
	}

	sort.Strings(allMatches)
	return allMatches
}

func formatBruteCount(n uint64) string {
	if n == 0 {
		return "0"
	}
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

func formatBruteConfig(maxLen int, ttl time.Duration) string {
	if ttl > 0 {
		return "timeout " + strings.TrimSpace(ttl.String())
	}
	if maxLen > 0 {
		return fmt.Sprintf("len 1-%d", maxLen)
	}
	return "disabled"
}
