// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package model

import (
	"encoding/json"
	"time"
)

type NSEC3Params struct {
	Algorithm  uint8  `json:"hash_algorithm"`
	Iterations uint16 `json:"iterations"`
	SaltHex    string `json:"salt_hex"`
	OptOut     bool   `json:"opt_out"`
}

type Metrics struct {
	CoveragePercent    float64 `json:"coverage_percent"`
	CoverageDefinition string  `json:"coverage_definition"`
	CorpusSize         int     `json:"corpus_label_count"`
	MatchedLabels      int     `json:"matched_labels"`
}

type Risk struct {
	Level     string   `json:"level"`
	Rationale []string `json:"rationale"`
}

type AXFRInfo struct {
	Allowed     bool   `json:"allowed"`
	Nameserver  string `json:"nameserver,omitempty"`
	RecordCount int    `json:"record_count"`
	NameCount   int    `json:"name_count"`
}

type ZoneInfo struct {
	Provider string   `json:"provider,omitempty"`
	NS       []string `json:"ns,omitempty"`
	MX       []string `json:"mx,omitempty"`
	TXTHints []string `json:"txt_hints,omitempty"`
}

type EnumerationSources struct {
	NSEC       int `json:"nsec,omitempty"`
	NSEC3      int `json:"nsec3_cracked,omitempty"`
	AXFR       int `json:"axfr,omitempty"`
	CT         int `json:"ct_logs,omitempty"`
	Bruteforce int `json:"bruteforce,omitempty"`
}

type RunOptions struct {
	DataDir           string `json:"data_dir"`
	Verbosity         string `json:"verbosity"`
	MaxWalk           int    `json:"max_walk"`
	MaxBudget         uint64 `json:"max_budget"`
	CorpusPath        string `json:"corpus_path,omitempty"`
	BruteforceLen     int    `json:"bruteforce_len"`
	BruteforceTimeout string `json:"bruteforce_timeout,omitempty"`
	BruteSubdomains   bool   `json:"brute_subdomains"`
	DisableAXFR       bool   `json:"disable_axfr"`
	DisableNSEC       bool   `json:"disable_nsec"`
	DisableNSEC3      bool   `json:"disable_nsec3"`
	DisableRegistry   bool   `json:"disable_registry"`
	DisableMetaHost   bool   `json:"disable_meta_hosts"`
}

// UnmarshalJSON accepts legacy stored reports that used "disable_crtsh".
func (r *RunOptions) UnmarshalJSON(data []byte) error {
	type Alias RunOptions
	aux := &struct {
		LegacyDisableCRTSH bool `json:"disable_crtsh"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.LegacyDisableCRTSH {
		r.DisableRegistry = true
	}
	return nil
}

type Report struct {
	Zone            string              `json:"zone"`
	AnalyzedAt      time.Time           `json:"analyzed_at"`
	RunOptions      *RunOptions         `json:"run_options,omitempty"`
	DNSSECType      string              `json:"dnssec_type"`
	NSEC3Params     *NSEC3Params        `json:"nsec3_params,omitempty"`
	AXFR            *AXFRInfo           `json:"axfr,omitempty"`
	ZoneInfo        *ZoneInfo           `json:"zone_info,omitempty"`
	Sources         *EnumerationSources `json:"enumeration_sources,omitempty"`
	Metrics         Metrics             `json:"metrics"`
	Risk            Risk                `json:"risk"`
	EnumeratedNames []string            `json:"enumerated_names,omitempty"`
}
