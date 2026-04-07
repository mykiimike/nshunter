// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package cli

import (
	"encoding/json"
	"fmt"

	"github.com/mykiimike/nshunter/model"
	"github.com/mykiimike/nshunter/store"
	"github.com/spf13/cobra"
)

var reportFormat string
var reportDomain string

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate an analysis report",
	RunE:  runReport,
}

func init() {
	reportCmd.Flags().StringVar(&reportFormat, "format", "json", "output format: json, markdown")
	reportCmd.Flags().StringVar(&reportDomain, "domain", "", "domain to report on (latest if empty)")
	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	st, err := store.Open(resolveDataDir())
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer st.Close()

	report, err := st.LatestReport(reportDomain)
	if err != nil {
		return fmt.Errorf("loading report: %w", err)
	}

	switch reportFormat {
	case "json":
		return renderJSON(report)
	case "markdown":
		return renderMarkdown(report)
	default:
		return fmt.Errorf("unsupported format: %s", reportFormat)
	}
}

func renderJSON(r *model.Report) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func renderMarkdown(r *model.Report) error {
	fmt.Printf("# DNSSEC Analysis — %s\n\n", r.Zone)
	fmt.Printf("**Date:** %s\n\n", r.AnalyzedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("**DNSSEC Type:** %s\n\n", r.DNSSECType)
	if r.RunOptions != nil {
		fmt.Println("## Run Options")
		fmt.Printf("| Option | Value |\n|--------|-------|\n")
		fmt.Printf("| Verbosity | `%s` |\n", r.RunOptions.Verbosity)
		fmt.Printf("| Data directory | `%s` |\n", r.RunOptions.DataDir)
		fmt.Printf("| max-walk | `%d` |\n", r.RunOptions.MaxWalk)
		fmt.Printf("| max-budget | `%d` |\n", r.RunOptions.MaxBudget)
		if r.RunOptions.CorpusPath != "" {
			fmt.Printf("| corpus | `%s` |\n", r.RunOptions.CorpusPath)
		}
		fmt.Printf("| bruteforce-len | `%d` |\n", r.RunOptions.BruteforceLen)
		if r.RunOptions.BruteforceTimeout != "" {
			fmt.Printf("| bruteforce-timeout | `%s` |\n", r.RunOptions.BruteforceTimeout)
		}
		fmt.Printf("| brute-subdomains | `%v` |\n", r.RunOptions.BruteSubdomains)
		fmt.Printf("| no-axfr | `%v` |\n", r.RunOptions.DisableAXFR)
		fmt.Printf("| no-nsec | `%v` |\n", r.RunOptions.DisableNSEC)
		fmt.Printf("| no-nsec3 | `%v` |\n", r.RunOptions.DisableNSEC3)
		fmt.Printf("| no-registry | `%v` |\n", r.RunOptions.DisableRegistry)
		fmt.Printf("| no-meta-hosts | `%v` |\n\n", r.RunOptions.DisableMetaHost)
	}

	if r.AXFR != nil {
		fmt.Println("## Zone Transfer (AXFR)")
		if r.AXFR.Allowed {
			fmt.Printf("**CRITICAL:** AXFR allowed by `%s`\n\n", r.AXFR.Nameserver)
			fmt.Printf("| Metric | Value |\n|--------|-------|\n")
			fmt.Printf("| Records | %d |\n", r.AXFR.RecordCount)
			fmt.Printf("| Unique Names | %d |\n\n", r.AXFR.NameCount)
		} else {
			fmt.Println("AXFR refused by all nameservers (expected).")
		}
	}

	if r.NSEC3Params != nil {
		fmt.Println("## NSEC3 Parameters")
		fmt.Printf("| Parameter | Value |\n|-----------|-------|\n")
		fmt.Printf("| Algorithm | %d |\n", r.NSEC3Params.Algorithm)
		fmt.Printf("| Iterations | %d |\n", r.NSEC3Params.Iterations)
		fmt.Printf("| Salt | `%s` |\n", r.NSEC3Params.SaltHex)
		fmt.Printf("| Opt-Out | %v |\n\n", r.NSEC3Params.OptOut)
	}

	fmt.Println("## Risk Assessment")
	fmt.Printf("| Metric | Value |\n|--------|-------|\n")
	fmt.Printf("| Coverage | %.1f%% |\n", r.Metrics.CoveragePercent)
	fmt.Printf("| Risk Level | **%s** |\n", r.Risk.Level)
	if len(r.Risk.Rationale) > 0 {
		fmt.Println("\n### Rationale")
		for _, reason := range r.Risk.Rationale {
			fmt.Printf("- %s\n", reason)
		}
	}

	if len(r.EnumeratedNames) > 0 {
		fmt.Printf("\n## Enumerated Names (%d)\n\n", len(r.EnumeratedNames))
		for _, name := range r.EnumeratedNames {
			fmt.Printf("- `%s`\n", name)
		}
	}

	return nil
}
