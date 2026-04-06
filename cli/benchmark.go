// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package cli

import (
	"fmt"
	"runtime"
	"time"

	"github.com/mykiimike/nshunter/engine"
	"github.com/spf13/cobra"
)

var useGPU bool

var benchmarkCmd = &cobra.Command{
	Use:   "benchmark",
	Short: "Benchmark NSEC3 hash throughput (CPU or GPU)",
	RunE:  runBenchmark,
}

func init() {
	benchmarkCmd.Flags().BoolVar(&useGPU, "gpu", false, "use Metal GPU acceleration")
	rootCmd.AddCommand(benchmarkCmd)
}

func runBenchmark(cmd *cobra.Command, args []string) error {
	mode := "CPU"
	if useGPU {
		if runtime.GOOS != "darwin" {
			return fmt.Errorf("Metal GPU acceleration is only available on macOS")
		}
		mode = "GPU (Metal)"
	}

	uiBanner()
	fmt.Println()
	uiTag("BENCH", fmt.Sprintf("NSEC3 SHA-1 throughput — %s", mode))
	fmt.Println()

	result, err := engine.Benchmark(useGPU)
	if err != nil {
		return fmt.Errorf("benchmark: %w", err)
	}

	uiTagOK("DEVICE", result.Device)
	uiTagOK("SPEED", fmt.Sprintf("%.2e hashes/sec", result.HashesPerSec))
	uiTagOK("TIME", result.Duration.Round(time.Millisecond).String())
	uiTagOK("TOTAL", fmt.Sprintf("%d iterations", result.TotalHashes))
	fmt.Println()
	return nil
}
