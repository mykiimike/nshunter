// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package engine

import (
	"fmt"
	"log"
	"strings"

	"github.com/mykiimike/nshunter/dns"
	"github.com/mykiimike/nshunter/logx"
	"github.com/mykiimike/nshunter/model"
)

func Analyze(result *dns.DNSSECResult, opts *Options) (*AnalysisResult, error) {
	var analysis *AnalysisResult
	var err error
	disableNSEC3 := opts != nil && opts.DisableNSEC3
	disableNSEC := opts != nil && opts.DisableNSEC

	if !result.HasDNSSEC {
		analysis = &AnalysisResult{
			DNSSECType:      "NONE",
			EnumeratedNames: result.EnumeratedNames,
			Risk: model.Risk{
				Level:     "HIGH",
				Rationale: []string{"no DNSSEC deployed"},
			},
		}
	} else if result.NSEC3Params != nil && !disableNSEC3 {
		analysis, err = analyzeNSEC3(result, opts)
		if err != nil {
			return nil, err
		}
	} else if (len(result.NSECRecords) > 0 || result.BlackLies) && !disableNSEC {
		analysis, err = analyzeNSEC(result, opts)
		if err != nil {
			return nil, err
		}
	} else {
		rationale := "DNSSEC present but no NSEC/NSEC3 records observed"
		if result.NSEC3Params != nil && disableNSEC3 {
			rationale = "DNSSEC NSEC3 detected but NSEC3 analysis disabled by option"
		} else if (len(result.NSECRecords) > 0 || result.BlackLies) && disableNSEC {
			rationale = "DNSSEC NSEC detected but NSEC analysis disabled by option"
		}
		analysis = &AnalysisResult{
			DNSSECType: "UNKNOWN",
			Risk: model.Risk{
				Level:     "MEDIUM",
				Rationale: []string{rationale},
			},
		}
	}

	if opts == nil || !opts.DisableAXFR {
		applyAXFR(result, analysis)
	}
	applyMetadata(result, analysis)
	if opts == nil || !opts.DisableRegistry {
		applyCT(result, analysis)
	}

	return analysis, nil
}

func applyAXFR(result *dns.DNSSECResult, analysis *AnalysisResult) {
	if result.AXFR == nil || !result.AXFR.Allowed {
		return
	}

	analysis.AXFRInfo = &model.AXFRInfo{
		Allowed:     true,
		Nameserver:  strings.TrimSuffix(result.AXFR.Nameserver, "."),
		RecordCount: result.AXFR.RecordCount,
		NameCount:   len(result.AXFR.Names),
	}

	analysis.Risk.Level = raiseLevel(analysis.Risk.Level, "CRITICAL")
	analysis.Risk.Rationale = append(analysis.Risk.Rationale,
		fmt.Sprintf("AXFR zone transfer allowed by %s (%d records, %d names)",
			result.AXFR.Nameserver, result.AXFR.RecordCount, len(result.AXFR.Names)))

	// AXFR gives complete zone — override enumerated names
	if len(result.AXFR.Names) > len(analysis.EnumeratedNames) {
		analysis.EnumeratedNames = result.EnumeratedNames
		analysis.Metrics.CoveragePercent = 100.0
		analysis.Metrics.CoverageDefinition = "AXFR zone transfer provides complete zone content"
		analysis.Metrics.CorpusSize = len(result.AXFR.Names)
		analysis.Metrics.MatchedLabels = len(result.AXFR.Names)
	}
}

func analyzeNSEC3(result *dns.DNSSECResult, opts *Options) (*AnalysisResult, error) {
	params := result.NSEC3Params

	corpus, err := loadCorpus(opts.CorpusPath)
	if err != nil {
		return nil, fmt.Errorf("loading corpus: %w", err)
	}
	log.Printf("[debug] loaded corpus: %d labels", len(corpus))

	// Collect all unique hashes from NSEC3 walk
	observedHashes := make(map[string]bool)
	if result.NSEC3Walk != nil {
		for h := range result.NSEC3Walk.Hashes {
			observedHashes[h] = true
		}
	}
	for _, rec := range result.NSEC3Records {
		observedHashes[strings.ToUpper(rec.HashedOwner)] = true
		observedHashes[strings.ToUpper(rec.NextHashed)] = true
	}
	log.Printf("[debug] %d unique NSEC3 hashes to crack", len(observedHashes))

	// Same SHA-1+NSEC3 primitive as `benchmark` (CPU); parallelized over the corpus when large.
	crackedNames := crackNSEC3Corpus(observedHashes, corpus, result.Domain, params.Iterations, params.SaltHex)
	for _, fqdn := range crackedNames {
		logx.SuperDebugf("nsec3 cracked: %s", fqdn)
	}
	for i, fqdn := range crackedNames {
		if i >= 20 {
			log.Printf("[debug] cracked: ... and %d more matches", len(crackedNames)-20)
			break
		}
		log.Printf("[debug] cracked: %s", fqdn)
	}

	// Remove already-cracked hashes before brute-force
	crackedSet := make(map[string]bool, len(crackedNames))
	for _, name := range crackedNames {
		crackedSet[name] = true
	}

	// Exhaustive brute-force (a-z0-9-, length 1..N) if requested
	bruteLen := 0
	if opts != nil {
		bruteLen = opts.BruteforceLen
	}
	var bruteNames []string
	if bruteLen > 0 && len(observedHashes) > 0 {
		remainingHashes := make(map[string]bool)
		for h := range observedHashes {
			remainingHashes[h] = true
		}
		nh, err := newNSEC3Hasher(result.Domain, params.Iterations, params.SaltHex)
		if err == nil {
			for _, label := range corpus {
				delete(remainingHashes, nh.Hash(label))
			}
		}
		if len(remainingHashes) > 0 {
			log.Printf("[debug] NSEC3 bruteforce: %d hashes remaining after corpus, brute-forcing up to length %d (%s combinations)",
				len(remainingHashes), bruteLen, formatBruteCount(bruteforceCount(bruteLen)))
			bruteNames = crackNSEC3Bruteforce(remainingHashes, result.Domain, params.Iterations, params.SaltHex, bruteLen)
			for _, fqdn := range bruteNames {
				logx.SuperDebugf("nsec3 brute hit: %s", fqdn)
			}
			for i, fqdn := range bruteNames {
				if i >= 20 {
					log.Printf("[debug] brute-forced: ... and %d more matches", len(bruteNames)-20)
					break
				}
				log.Printf("[debug] brute-forced: %s", fqdn)
			}
		} else {
			log.Printf("[debug] NSEC3 bruteforce: all hashes already cracked by corpus, skipping")
		}
	}

	allCracked := append(crackedNames, bruteNames...)

	totalHashes := len(observedHashes)
	matched := len(allCracked)
	log.Printf("[debug] cracking done: %d/%d hashes matched (%d corpus + %d brute-force)",
		matched, totalHashes, len(crackedNames), len(bruteNames))

	coverage := 0.0
	if totalHashes > 0 {
		coverage = float64(matched) / float64(totalHashes) * 100
	}

	var rationale []string
	level := "LOW"

	walkInfo := ""
	if result.NSEC3Walk != nil {
		walkInfo = fmt.Sprintf("%d queries, %d unique hashes collected",
			result.NSEC3Walk.Queries, totalHashes)
		rationale = append(rationale, walkInfo)
	}

	if matched > 0 {
		if len(bruteNames) > 0 {
			rationale = append(rationale,
				fmt.Sprintf("%d/%d hashes cracked (%d corpus + %d brute-force len 1–%d)",
					matched, totalHashes, len(crackedNames), len(bruteNames), bruteLen))
		} else {
			rationale = append(rationale,
				fmt.Sprintf("%d/%d hashes cracked from corpus (%d labels tested)",
					matched, totalHashes, len(corpus)))
		}
		if coverage > 10 {
			level = raiseLevel(level, "HIGH")
		} else if coverage > 1 {
			level = raiseLevel(level, "MEDIUM")
		}
	}

	if params.Iterations == 0 {
		rationale = append(rationale, "iterations=0 (RFC 9276 compliant, but hashes are trivially computed)")
	} else if params.Iterations < 10 {
		rationale = append(rationale, fmt.Sprintf("iterations=%d (very low)", params.Iterations))
	}

	if params.SaltHex == "" {
		rationale = append(rationale, "empty salt (RFC 9276 compliant)")
	}

	if params.Flags&1 != 0 {
		rationale = append(rationale, "NSEC3 opt-out enabled — only signed delegations appear in hash chain")
	}

	if len(rationale) == 0 {
		rationale = append(rationale, "configuration appears reasonable")
	}

	return &AnalysisResult{
		DNSSECType: "NSEC3",
		NSEC3Params: &model.NSEC3Params{
			Algorithm:  params.Algorithm,
			Iterations: params.Iterations,
			SaltHex:    params.SaltHex,
			OptOut:     params.Flags&1 != 0,
		},
		Metrics: model.Metrics{
			CoveragePercent:    coverage,
			CoverageDefinition: "fraction of observed NSEC3 hashes cracked from corpus",
			CorpusSize:         len(corpus),
			MatchedLabels:      matched,
		},
		Risk:            model.Risk{Level: level, Rationale: rationale},
		EnumeratedNames: allCracked,
	}, nil
}

func analyzeNSEC(result *dns.DNSSECResult, _ *Options) (*AnalysisResult, error) {
	names := result.EnumeratedNames

	if result.BlackLies {
		level := "LOW"
		rationale := []string{
			"NSEC black lies detected (Cloudflare-style anti-walking countermeasure)",
			"zone walking is effectively blocked — names cannot be enumerated via NSEC",
		}
		return &AnalysisResult{
			DNSSECType: "NSEC (black lies)",
			Metrics: model.Metrics{
				CoveragePercent:    0,
				CoverageDefinition: "black lies prevent NSEC zone enumeration",
			},
			Risk: model.Risk{
				Level:     level,
				Rationale: rationale,
			},
		}, nil
	}

	rationale := []string{
		"NSEC records allow trivial zone enumeration",
		fmt.Sprintf("%d names enumerated via NSEC chain walking", len(names)),
	}

	return &AnalysisResult{
		DNSSECType: "NSEC",
		Metrics: model.Metrics{
			CoveragePercent:    100.0,
			CoverageDefinition: "NSEC zone walking enumerates all names in the zone",
			CorpusSize:         len(names),
			MatchedLabels:      len(names),
		},
		Risk: model.Risk{
			Level:     "HIGH",
			Rationale: rationale,
		},
		EnumeratedNames: names,
	}, nil
}

func applyMetadata(result *dns.DNSSECResult, analysis *AnalysisResult) {
	if result.Metadata == nil {
		return
	}
	analysis.ZoneInfo = &model.ZoneInfo{
		Provider: result.Metadata.Provider,
		NS:       result.Metadata.NSRecords,
		MX:       result.Metadata.MXRecords,
		TXTHints: result.Metadata.TXTHints,
	}
}

func applyCT(result *dns.DNSSECResult, analysis *AnalysisResult) {
	if analysis.Sources == nil {
		analysis.Sources = &model.EnumerationSources{}
	}
	if len(result.CTNames) > 0 {
		analysis.Sources.CT = len(result.CTNames)
		analysis.Risk.Rationale = append(analysis.Risk.Rationale,
			fmt.Sprintf("%d subdomains discovered via Certificate Transparency logs", len(result.CTNames)))

		// Merge CT names
		seen := make(map[string]bool)
		for _, n := range analysis.EnumeratedNames {
			seen[n] = true
		}
		for _, n := range result.CTNames {
			if !seen[n] {
				analysis.EnumeratedNames = append(analysis.EnumeratedNames, n)
				seen[n] = true
			}
		}
	}

	if len(result.BruteNames) > 0 {
		analysis.Sources.Bruteforce = len(result.BruteNames)
		analysis.Risk.Rationale = append(analysis.Risk.Rationale,
			fmt.Sprintf("%d subdomains confirmed via DNS brute-force probes", len(result.BruteNames)))

		seen := make(map[string]bool)
		for _, n := range analysis.EnumeratedNames {
			seen[n] = true
		}
		for _, n := range result.BruteNames {
			if !seen[n] {
				analysis.EnumeratedNames = append(analysis.EnumeratedNames, n)
				seen[n] = true
			}
		}
	}
}

func raiseLevel(current, candidate string) string {
	order := map[string]int{"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
	if order[candidate] > order[current] {
		return candidate
	}
	return current
}
