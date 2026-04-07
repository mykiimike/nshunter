// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package cli

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mykiimike/nshunter/dns"
	"github.com/mykiimike/nshunter/engine"
	"github.com/mykiimike/nshunter/logx"
	"github.com/mykiimike/nshunter/metal"
	"github.com/mykiimike/nshunter/model"
	"github.com/mykiimike/nshunter/store"
	"github.com/spf13/cobra"
)

var analyzeDomain string
var corpusPath string
var maxBudget uint64
var maxWalk int
var noAXFR bool
var noNSEC bool
var noNSEC3 bool
var noRegistry bool
var noMetaHosts bool
var bruteforceLen int
var bruteforceTimeoutRaw string
var bruteforceTimeout time.Duration
var bruteSubdomains bool

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze DNSSEC configuration for a domain you own",
	RunE:  runAnalyze,
}

func init() {
	analyzeCmd.Flags().StringVar(&analyzeDomain, "domain", "", "domain to analyze (required)")
	analyzeCmd.Flags().StringVar(&corpusPath, "corpus", "", "path to label corpus file (one label per line)")
	analyzeCmd.Flags().Uint64Var(&maxBudget, "max-budget", 1<<32, "max hash attempts per NSEC3 hole")
	analyzeCmd.Flags().IntVar(&maxWalk, "max-walk", 10000, "max NSEC walk queries (0 = unlimited)")
	analyzeCmd.Flags().BoolVar(&noAXFR, "no-axfr", false, "disable AXFR attempt")
	analyzeCmd.Flags().BoolVar(&noNSEC, "no-nsec", false, "disable NSEC chain walk analysis")
	analyzeCmd.Flags().BoolVar(&noNSEC3, "no-nsec3", false, "disable NSEC3 walk/cracking analysis")
	analyzeCmd.Flags().BoolVar(&noRegistry, "no-registry", false, "disable passive certificate registry scans (crt.sh; optional Cert Spotter, Censys via env)")
	analyzeCmd.Flags().BoolVar(&noMetaHosts, "no-meta-hosts", false, "do not add in-zone NS/MX hostnames to enumerated names")
	analyzeCmd.Flags().IntVar(&bruteforceLen, "bruteforce-len", 0, "exhaustive NSEC3 brute-force: max label length (0=off, recommended 5–6)")
	analyzeCmd.Flags().StringVar(&bruteforceTimeoutRaw, "bruteforce-timeout", "", "time budget for NSEC3 brute-force (e.g. 60s, 15m, 2h, 1d); overrides --bruteforce-len")
	analyzeCmd.Flags().BoolVar(&bruteSubdomains, "brute-subdomains", false, "actively brute-force candidate subdomains via DNS A/AAAA lookups")
	_ = analyzeCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(analyzeCmd)
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	timeout, err := parseBruteforceTimeout(bruteforceTimeoutRaw)
	if err != nil {
		return err
	}
	bruteforceTimeout = timeout

	runOpts := buildRunOptions()

	// ── Banner + config ──────────────────────────────────
	uiBanner()
	fmt.Println()
	uiTag("TARGET", analyzeDomain)
	fmt.Println()
	printConfigPanel(runOpts)

	st, err := store.Open(resolveDataDir())
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer st.Close()

	if maxWalk > 0 {
		dns.NSECWalkMaxQueries = maxWalk
	}

	// ── Collection phase ─────────────────────────────────
	uiPhase("COLLECTION")

	start := time.Now()
	result, err := dns.CollectDNSSECWithOptions(analyzeDomain, &dns.CollectOptions{
		DisableAXFR:      noAXFR,
		DisableNSEC:      noNSEC,
		DisableNSEC3:     noNSEC3,
		DisableRegistry:  noRegistry,
		DisableMetaHosts: noMetaHosts,
	})
	if err != nil {
		return fmt.Errorf("DNS collection: %w", err)
	}

	printCollectionResults(result)
	uiTimer(fmt.Sprintf("collection took %s", time.Since(start).Round(time.Millisecond)))

	// ── Brute-force phase (optional) ─────────────────────
	if bruteSubdomains {
		uiPhase("BRUTE-FORCE")
		labels, err := engine.LoadCorpus(corpusPath)
		if err != nil {
			return fmt.Errorf("loading corpus for DNS brute-force: %w", err)
		}
		uiTag("BRUTE", fmt.Sprintf("testing %d candidate labels via DNS A/AAAA", len(labels)))
		result.BruteNames = dns.BruteSubdomains(analyzeDomain, labels)
		if len(result.BruteNames) > 0 {
			seen := make(map[string]bool)
			for _, n := range result.EnumeratedNames {
				seen[n] = true
			}
			for _, n := range result.BruteNames {
				if !seen[n] {
					result.EnumeratedNames = append(result.EnumeratedNames, n)
					seen[n] = true
				}
			}
		}
		uiTagOK("BRUTE", fmt.Sprintf("confirmed %d subdomains", len(result.BruteNames)))
	}

	if len(result.EnumeratedNames) > 0 {
		uiTag("ENUM", fmt.Sprintf("total enumerated: %d names", len(result.EnumeratedNames)))
	}

	// ── Analysis phase ───────────────────────────────────
	uiPhase("ANALYSIS")

	uiTag("ENGINE", "running analysis engine...")
	analysisStart := time.Now()
	analysis, err := engine.Analyze(result, &engine.Options{
		CorpusPath:      corpusPath,
		MaxBudget:       maxBudget,
		DisableAXFR:     noAXFR,
		DisableNSEC:     noNSEC,
		DisableNSEC3:    noNSEC3,
		DisableRegistry: noRegistry,
		BruteforceLen:   bruteforceLen,
		BruteforceTTL:   bruteforceTimeout,
	})
	if err != nil {
		return fmt.Errorf("analysis: %w", err)
	}
	uiTimer(fmt.Sprintf("engine took %s", time.Since(analysisStart).Round(time.Millisecond)))

	printEnumeratedNames(analysis)

	// ── Verdict ──────────────────────────────────────────
	uiPhase("VERDICT")

	report := model.Report{
		Zone:            analyzeDomain,
		AnalyzedAt:      time.Now().UTC(),
		RunOptions:      runOpts,
		DNSSECType:      analysis.DNSSECType,
		NSEC3Params:     analysis.NSEC3Params,
		AXFR:            analysis.AXFRInfo,
		ZoneInfo:        analysis.ZoneInfo,
		Sources:         analysis.Sources,
		Metrics:         analysis.Metrics,
		Risk:            analysis.Risk,
		EnumeratedNames: analysis.EnumeratedNames,
	}

	if err := st.SaveReport(&report); err != nil {
		return fmt.Errorf("saving report: %w", err)
	}

	riskColor := cGreen
	switch analysis.Risk.Level {
	case "HIGH":
		riskColor = cRed
	case "MEDIUM":
		riskColor = cYellow
	case "CRITICAL":
		riskColor = cRed + cBold
	}

	uiTagStar("RISK", fmt.Sprintf("%s%s%s (%.1f%% coverage)",
		riskColor, analysis.Risk.Level, cReset,
		analysis.Metrics.CoveragePercent))
	for _, r := range analysis.Risk.Rationale {
		fmt.Printf("              → %s\n", r)
	}
	fmt.Println()
	uiTagOK("STORED", fmt.Sprintf("report saved (%s total)", time.Since(start).Round(time.Millisecond)))
	fmt.Println()

	return nil
}

// ── Config panel ─────────────────────────────────────────

func printConfigPanel(opts *model.RunOptions) {
	uiPanelOpen("RUNTIME")
	uiPanelRow("verbosity", verbosityLabel(verboseCount))
	uiPanelRow("profile", profileLabel(opts))
	uiPanelRow("data-dir", opts.DataDir)
	uiPanelRow("max-walk", fmt.Sprintf("%d", opts.MaxWalk))
	uiPanelRow("max-budget", fmt.Sprintf("%d", opts.MaxBudget))
	if opts.CorpusPath == "" {
		uiPanelRow("corpus", "default")
	} else {
		uiPanelRow("corpus", opts.CorpusPath)
	}
	uiPanelRow("bruteforce-len", fmt.Sprintf("%d", opts.BruteforceLen))
	if opts.BruteforceTimeout == "" {
		uiPanelRow("bruteforce-timeout", "off")
	} else {
		uiPanelRow("bruteforce-timeout", opts.BruteforceTimeout)
	}
	uiPanelRowToggle("brute-subdomains", opts.BruteSubdomains)

	uiPanelSep("COMPUTE")
	uiPanelRow("CPU", cpuComputeLabel())
	uiPanelRow("GPU", gpuComputeLabel())

	uiPanelSep("FEATURES")
	uiPanelRowToggle("AXFR probe", !opts.DisableAXFR)
	uiPanelRowToggle("NSEC walk", !opts.DisableNSEC)
	uiPanelRowToggle("NSEC3 walk/crack", !opts.DisableNSEC3)
	uiPanelRow("NSEC3 corpus", nsec3CorpusBackendLabel())
	uiPanelRow("NSEC3 brute", nsec3BruteEngineLabel())
	uiPanelRowToggle("Passive registries", !opts.DisableRegistry)
	uiPanelRowToggle("NS/MX host merge", !opts.DisableMetaHost)
	uiPanelClose()
}

// ── Collection results ───────────────────────────────────

func printCollectionResults(result *dns.DNSSECResult) {
	if noAXFR {
		uiTag("AXFR", "disabled by option")
	} else if result.AXFR != nil && result.AXFR.Allowed {
		uiTagDanger("AXFR", fmt.Sprintf("zone transfer ALLOWED by %s", result.AXFR.Nameserver))
		uiTagDanger("AXFR", fmt.Sprintf("%d records, %d unique names obtained",
			result.AXFR.RecordCount, len(result.AXFR.Names)))
	} else {
		uiTag("AXFR", "zone transfer refused (expected)")
	}

	uiTag("DNSSEC", fmt.Sprintf("NSEC3=%d  NSEC=%d",
		len(result.NSEC3Records), len(result.NSECRecords)))
	printExecutionState(result)

	if result.NSEC3Params != nil {
		saltDisplay := result.NSEC3Params.SaltHex
		if saltDisplay == "" {
			saltDisplay = "(empty)"
		}
		uiTag("NSEC3", fmt.Sprintf("algo=%d  iter=%d  salt=%s  flags=%d",
			result.NSEC3Params.Algorithm, result.NSEC3Params.Iterations,
			saltDisplay, result.NSEC3Params.Flags))
		if result.NSEC3Params.Flags&1 != 0 {
			uiTagWarn("NSEC3", "opt-out enabled — only signed delegations in chain")
		}
	}

	if result.NSEC3Walk != nil {
		uiTag("NSEC3", fmt.Sprintf("walk: %d queries, %d unique hashes",
			result.NSEC3Walk.Queries, len(result.NSEC3Walk.Hashes)))
	}

	if result.BlackLies {
		uiTagWarn("NSEC", "black lies detected — zone walking blocked (Cloudflare-style)")
	}

	if result.Metadata != nil {
		if result.Metadata.Provider != "" {
			uiTag("META", fmt.Sprintf("provider: %s", result.Metadata.Provider))
		}
		if len(result.Metadata.MXRecords) > 0 {
			for _, mx := range result.Metadata.MXRecords {
				uiTag("META", fmt.Sprintf("MX: %s", mx))
			}
		}
		if len(result.Metadata.TXTHints) > 0 {
			for _, h := range result.Metadata.TXTHints {
				uiTag("META", fmt.Sprintf("TXT: %s", h))
			}
		}
	}

	if noMetaHosts {
		uiTag("META", "NS/MX host merge disabled by option")
	}

	if noRegistry {
		uiTag("REGISTRY", "disabled by --no-registry")
	} else if result.Registry != nil {
		uiTag("REGISTRY", fmt.Sprintf("%d hostnames after merge — crt.sh (public CT mirror): %d · Cert Spotter (SSLMate API): %d · Censys (cert index): %d",
			len(result.CTNames),
			len(result.Registry.CRTSH),
			len(result.Registry.CertSpotter),
			len(result.Registry.Censys)))
	}
}

func printExecutionState(result *dns.DNSSECResult) {
	if !result.HasDNSSEC {
		uiTagWarn("CHECKS", "no DNSKEY on authoritative NS (DNSSEC not deployed)")
		if !noNSEC3 {
			uiTag("CHECKS", "NSEC3 crack path enabled but not applicable (no DNSSEC)")
		}
		if !noNSEC {
			uiTag("CHECKS", "NSEC walk enabled but no signed denial chain observed")
		}
		return
	}

	if noNSEC3 {
		uiTag("CHECKS", "NSEC3 path disabled by option")
	} else if result.NSEC3Params != nil {
		hashes := 0
		if result.NSEC3Walk != nil {
			hashes = len(result.NSEC3Walk.Hashes)
		}
		uiTagOK("CHECKS", fmt.Sprintf("NSEC3 path executed (%d records, %d hashes)", len(result.NSEC3Records), hashes))
	} else {
		uiTag("CHECKS", "NSEC3 not advertised (NSEC3PARAM absent)")
	}

	if noNSEC {
		uiTag("CHECKS", "NSEC walk disabled by option")
		return
	}
	if result.NSEC3Params != nil {
		uiTag("CHECKS", "NSEC walk skipped (zone uses NSEC3)")
		return
	}
	if result.BlackLies {
		uiTagWarn("CHECKS", "NSEC black lies detected (anti-walking)")
		return
	}
	uiTag("CHECKS", fmt.Sprintf("NSEC walk attempted (%d records)", len(result.NSECRecords)))
}

// ── Enumerated names ─────────────────────────────────────

func printEnumeratedNames(analysis *engine.AnalysisResult) {
	if len(analysis.EnumeratedNames) == 0 {
		return
	}

	const maxDisplay = 50
	label := "enumerated"
	if analysis.DNSSECType == "NSEC3" {
		label = "cracked"
	}
	uiTag("RESULT", fmt.Sprintf("%s names (%d):", label, len(analysis.EnumeratedNames)))
	for i, name := range analysis.EnumeratedNames {
		if i >= maxDisplay {
			fmt.Printf("              %s... and %d more (use 'report' for full list)%s\n",
				cGray, len(analysis.EnumeratedNames)-maxDisplay, cReset)
			break
		}
		fmt.Printf("              %s\n", name)
	}

	if logx.IsSuperDebug() {
		for _, name := range analysis.EnumeratedNames {
			uiTagSuper("FOUND", name)
		}
	}
}

// ── Helpers ──────────────────────────────────────────────

func resolveDataDir() string {
	if dataDir != "" {
		return dataDir
	}
	return store.DefaultDataDir()
}

func buildRunOptions() *model.RunOptions {
	return &model.RunOptions{
		DataDir:       resolveDataDir(),
		Verbosity:     verbosityLabel(verboseCount),
		MaxWalk:       maxWalk,
		MaxBudget:     maxBudget,
		CorpusPath:    corpusPath,
		BruteforceLen: bruteforceLen,
		BruteforceTimeout: func() string {
			if bruteforceTimeout <= 0 {
				return ""
			}
			return bruteforceTimeout.String()
		}(),
		BruteSubdomains: bruteSubdomains,
		DisableAXFR:     noAXFR,
		DisableNSEC:     noNSEC,
		DisableNSEC3:    noNSEC3,
		DisableRegistry: noRegistry,
		DisableMetaHost: noMetaHosts,
	}
}

func verbosityLabel(v int) string {
	switch {
	case v >= 2:
		return "SUPER-DEBUG"
	case v == 1:
		return "DEBUG"
	default:
		return "INFO"
	}
}

func profileLabel(opts *model.RunOptions) string {
	score := 0
	if !opts.DisableAXFR {
		score++
	}
	if !opts.DisableNSEC {
		score++
	}
	if !opts.DisableNSEC3 {
		score++
	}
	if !opts.DisableRegistry {
		score++
	}
	if !opts.DisableMetaHost {
		score++
	}
	if opts.BruteSubdomains {
		score++
	}
	if opts.BruteforceLen > 0 {
		score++
	}
	if opts.BruteforceTimeout != "" {
		score++
	}

	switch {
	case score >= 6:
		return cRed + "AGGRESSIVE" + cReset
	case score >= 4:
		return cYellow + "BALANCED" + cReset
	default:
		return cGreen + "LIGHT" + cReset
	}
}

func nsec3CorpusBackendLabel() string {
	if runtime.GOOS == "darwin" {
		if n := strings.TrimSpace(metal.DefaultDeviceName()); n != "" {
			return "AUTO (>=1024 lbl -> " + n + ")"
		}
		return "AUTO (Metal → CPU)"
	}
	return "CPU only"
}

func nsec3BruteEngineLabel() string {
	return cpuComputeLabel()
}

func parseBruteforceTimeout(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return 0, nil
	}
	if strings.HasSuffix(raw, "d") {
		num := strings.TrimSuffix(raw, "d")
		if strings.TrimSpace(num) == "" {
			return 0, fmt.Errorf("invalid --bruteforce-timeout %q (use values like 60s, 15m, 2h, 1d)", raw)
		}
		days, err := strconv.ParseFloat(num, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid --bruteforce-timeout %q: %w", raw, err)
		}
		if days <= 0 {
			return 0, fmt.Errorf("--bruteforce-timeout must be > 0")
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid --bruteforce-timeout %q (use values like 60s, 15m, 2h, 1d): %w", raw, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("--bruteforce-timeout must be > 0")
	}
	return d, nil
}

func cpuComputeLabel() string {
	return fmt.Sprintf("%s/%s | %d threads", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
}

func gpuComputeLabel() string {
	if runtime.GOOS != "darwin" {
		return "— (Metal is macOS-only)"
	}
	if n := strings.TrimSpace(metal.DefaultDeviceName()); n != "" {
		return n
	}
	return "— (enable CGO for Metal)"
}
