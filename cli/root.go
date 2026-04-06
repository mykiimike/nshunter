// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package cli

import (
	"github.com/mykiimike/nshunter/logx"
	"github.com/spf13/cobra"
)

const (
	legalCopyright = "Copyright (c) 2026 Michael VERGOZ"
	legalSPDX      = "SPDX-License-Identifier: MIT"
)

var dataDir string
var verboseCount int

var rootCmd = &cobra.Command{
	Use:   "nshunter",
	Short: "nshunter — DNSSEC zone exposure analyzer",
	Long: `nshunter — DNSSEC zone exposure analyzer

Assess how much of your DNS zone content is discoverable through
DNSSEC side-channels (NSEC/NSEC3 walking), zone transfers (AXFR),
and passive certificate registries (CT via crt.sh; optional Cert Spotter, Censys).

Data is stored in ~/.nshunter/ by default.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logx.Init(verboseCount)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&dataDir, "data-dir", "", "override data directory (default: ~/.nshunter)")
	rootCmd.PersistentFlags().CountVarP(&verboseCount, "verbose", "v", "increase log verbosity (-v=debug, -vv=super-debug)")
}

func Execute() error {
	return rootCmd.Execute()
}
