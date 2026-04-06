// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package hashdb

import (
	"testing"
)

func TestPutAndGet(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir + "/test.pebble")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	entry := &HashEntry{Label: "www", Zone: "example.com"}
	if err := db.Put("AABBCCDD", entry); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := db.Get("AABBCCDD")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if got.Label != "www" {
		t.Errorf("label: %s, want www", got.Label)
	}
	if got.Zone != "example.com" {
		t.Errorf("zone: %s, want example.com", got.Zone)
	}
}

func TestGetMiss(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir + "/test.pebble")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	got, err := db.Get("NONEXISTENT")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for missing key, got %+v", got)
	}
}

func TestPutBatch(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir + "/test.pebble")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	entries := map[string]*HashEntry{
		"HASH1": {Label: "www", Zone: "example.com"},
		"HASH2": {Label: "mail", Zone: "example.com"},
		"HASH3": {Label: "ftp", Zone: "example.com"},
	}

	if err := db.PutBatch(entries); err != nil {
		t.Fatalf("PutBatch: %v", err)
	}

	for k, want := range entries {
		got, err := db.Get(k)
		if err != nil {
			t.Fatalf("Get(%s): %v", k, err)
		}
		if got == nil || got.Label != want.Label {
			t.Errorf("Get(%s) = %+v, want label=%s", k, got, want.Label)
		}
	}
}

func TestRangeCount(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir + "/test.pebble")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	entries := map[string]*HashEntry{
		"AA": {Label: "a", Zone: "test"},
		"BB": {Label: "b", Zone: "test"},
		"CC": {Label: "c", Zone: "test"},
		"DD": {Label: "d", Zone: "test"},
	}
	if err := db.PutBatch(entries); err != nil {
		t.Fatalf("PutBatch: %v", err)
	}

	count, err := db.RangeCount("AA", "DD")
	if err != nil {
		t.Fatalf("RangeCount: %v", err)
	}
	if count != 3 {
		t.Errorf("RangeCount(AA, DD) = %d, want 3", count)
	}
}
