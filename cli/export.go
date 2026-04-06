// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/mykiimike/nshunter/store"
	"github.com/spf13/cobra"
)

var exportDomain string
var exportOutput string

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export stored reports from SQLite to JSON",
	RunE:  runExport,
}

func init() {
	exportCmd.Flags().StringVar(&exportDomain, "domain", "", "filter reports by domain (empty = all domains)")
	exportCmd.Flags().StringVar(&exportOutput, "output", "", "output JSON file path (default: stdout)")
	rootCmd.AddCommand(exportCmd)
}

func runExport(cmd *cobra.Command, args []string) error {
	st, err := store.Open(resolveDataDir())
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer st.Close()

	reports, err := st.ListReports(exportDomain)
	if err != nil {
		return fmt.Errorf("loading reports: %w", err)
	}

	data, err := json.MarshalIndent(reports, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding export JSON: %w", err)
	}

	if exportOutput == "" {
		fmt.Println(string(data))
		return nil
	}
	if err := os.WriteFile(exportOutput, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("writing export file: %w", err)
	}
	fmt.Printf("[+] exported %d report(s) to %s\n", len(reports), exportOutput)
	return nil
}
