// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package engine

import (
	"time"

	"github.com/mykiimike/nshunter/model"
)

type Options struct {
	CorpusPath      string
	MaxBudget       uint64
	UseGPU          bool
	DisableAXFR     bool
	DisableNSEC     bool
	DisableNSEC3    bool
	DisableRegistry bool
	BruteforceLen   int           // max label length for exhaustive brute-force (0 = disabled)
	BruteforceTTL   time.Duration // time budget for brute-force (takes precedence over BruteforceLen)
}

type AnalysisResult struct {
	DNSSECType      string
	NSEC3Params     *model.NSEC3Params
	AXFRInfo        *model.AXFRInfo
	ZoneInfo        *model.ZoneInfo
	Sources         *model.EnumerationSources
	Metrics         model.Metrics
	Risk            model.Risk
	EnumeratedNames []string
}

type BenchmarkResult struct {
	Device       string
	HashesPerSec float64
	Duration     time.Duration
	TotalHashes  uint64
}
