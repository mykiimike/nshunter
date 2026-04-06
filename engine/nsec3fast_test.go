// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package engine

import "testing"

func TestNSEC3Hasher_Consistency(t *testing.T) {
	nh, err := newNSEC3Hasher("example.com", 0, "")
	if err != nil {
		t.Fatalf("newNSEC3Hasher: %v", err)
	}

	labels := []string{"www", "mail", "api", "ns1", "ftp", "test", "a", "zz"}
	for _, label := range labels {
		h1 := nh.Hash(label)
		h2 := nh.Hash(label)
		if h1 != h2 {
			t.Errorf("label=%q: inconsistent results %s vs %s", label, h1, h2)
		}
		if len(h1) != 32 {
			t.Errorf("label=%q: hash length %d, want 32", label, len(h1))
		}
	}
}

func TestNSEC3Hasher_WithSaltAndIterations(t *testing.T) {
	nh, err := newNSEC3Hasher("example.org", 5, "aabbccdd")
	if err != nil {
		t.Fatalf("newNSEC3Hasher: %v", err)
	}

	h1 := nh.Hash("www")
	h2 := nh.Hash("www")
	if h1 != h2 {
		t.Errorf("inconsistent: %s vs %s", h1, h2)
	}

	hDiff := nh.Hash("mail")
	if hDiff == h1 {
		t.Error("different labels produced same hash")
	}
}

func BenchmarkNSEC3Hash(b *testing.B) {
	nh, _ := newNSEC3Hasher("example.com", 0, "")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nh.Hash("www")
	}
}
