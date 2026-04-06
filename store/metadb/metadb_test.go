// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package metadb

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mykiimike/nshunter/model"
)

func TestInsertAndRetrieveReport(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.sqlite")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	report := &model.Report{
		Zone:       "example.com",
		AnalyzedAt: time.Now().UTC().Truncate(time.Second),
		RunOptions: &model.RunOptions{
			DataDir:       "/tmp/nshunter",
			Verbosity:     "debug",
			MaxWalk:       123,
			MaxBudget:     999,
			BruteforceLen: 6,
		},
		DNSSECType: "NSEC3",
		NSEC3Params: &model.NSEC3Params{
			Algorithm:  1,
			Iterations: 10,
			SaltHex:    "aabbccdd",
			OptOut:     false,
		},
		Metrics: model.Metrics{
			CoveragePercent:    85.2,
			CoverageDefinition: "test",
			CorpusSize:         1000,
			MatchedLabels:      852,
		},
		Risk: model.Risk{
			Level:     "MEDIUM",
			Rationale: []string{"low iterations"},
		},
	}

	if err := db.InsertReport(report); err != nil {
		t.Fatalf("InsertReport: %v", err)
	}

	got, err := db.LatestReport("example.com")
	if err != nil {
		t.Fatalf("LatestReport: %v", err)
	}

	if got.Zone != report.Zone {
		t.Errorf("zone: %s, want %s", got.Zone, report.Zone)
	}
	if got.DNSSECType != "NSEC3" {
		t.Errorf("type: %s, want NSEC3", got.DNSSECType)
	}
	if got.RunOptions == nil {
		t.Fatal("RunOptions is nil")
	}
	if got.RunOptions.Verbosity != "debug" {
		t.Errorf("verbosity: %s, want debug", got.RunOptions.Verbosity)
	}
	if got.NSEC3Params == nil {
		t.Fatal("NSEC3Params is nil")
	}
	if got.NSEC3Params.Iterations != 10 {
		t.Errorf("iterations: %d, want 10", got.NSEC3Params.Iterations)
	}
	if got.Metrics.CoveragePercent != 85.2 {
		t.Errorf("coverage: %f, want 85.2", got.Metrics.CoveragePercent)
	}
	if got.Risk.Level != "MEDIUM" {
		t.Errorf("risk: %s, want MEDIUM", got.Risk.Level)
	}
}

func TestLatestReport_NoRows(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "empty.sqlite")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	_, err = db.LatestReport("")
	if err == nil {
		t.Fatal("expected error for empty DB")
	}
}

func TestMigrationIdempotent(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "migrate.sqlite")

	db1, err := Open(dbPath)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	db1.Close()

	db2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("second open (re-migrate): %v", err)
	}
	db2.Close()

	_ = os.Remove(dbPath)
}

func TestListReports_WithAndWithoutDomainFilter(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "list.sqlite")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC().Truncate(time.Second)
	reports := []*model.Report{
		{
			Zone:       "example.com",
			AnalyzedAt: now.Add(-2 * time.Hour),
			DNSSECType: "NSEC3",
			Metrics: model.Metrics{
				CoveragePercent:    1.0,
				CoverageDefinition: "test",
			},
			Risk: model.Risk{Level: "LOW"},
		},
		{
			Zone:       "example.org",
			AnalyzedAt: now.Add(-1 * time.Hour),
			DNSSECType: "NSEC",
			Metrics: model.Metrics{
				CoveragePercent:    2.0,
				CoverageDefinition: "test",
			},
			Risk: model.Risk{Level: "MEDIUM"},
		},
		{
			Zone:       "example.com",
			AnalyzedAt: now,
			DNSSECType: "NSEC3",
			Metrics: model.Metrics{
				CoveragePercent:    3.0,
				CoverageDefinition: "test",
			},
			Risk: model.Risk{Level: "HIGH"},
		},
	}
	for _, r := range reports {
		if err := db.InsertReport(r); err != nil {
			t.Fatalf("InsertReport: %v", err)
		}
	}

	all, err := db.ListReports("")
	if err != nil {
		t.Fatalf("ListReports(all): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("all length: got %d want 3", len(all))
	}
	if all[0].Zone != "example.com" || all[0].Risk.Level != "HIGH" {
		t.Fatalf("expected latest report first, got zone=%s risk=%s", all[0].Zone, all[0].Risk.Level)
	}

	filtered, err := db.ListReports("example.com")
	if err != nil {
		t.Fatalf("ListReports(filtered): %v", err)
	}
	if len(filtered) != 2 {
		t.Fatalf("filtered length: got %d want 2", len(filtered))
	}
	for _, r := range filtered {
		if r.Zone != "example.com" {
			t.Fatalf("unexpected zone in filtered results: %s", r.Zone)
		}
	}
}
