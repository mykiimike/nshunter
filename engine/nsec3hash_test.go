// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package engine

import (
	"strings"
	"testing"
)

// RFC 5155 Appendix B test vectors:
// Zone: example, Hash: SHA-1, Iterations: 12, Salt: aabbccdd
func TestNSEC3Hash_RFC5155(t *testing.T) {
	tests := []struct {
		label string
		zone  string
		want  string
	}{
		{"", "example", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"},
		{"a", "example", "35mthgpgcu1qg68fab165klnsnk3dpvl"},
		{"ns1", "example", "2t7b4g4vsa5smi47k61mv5bv1a22bojr"},
		{"ns2", "example", "q04jkcevqvmu85r014c7dkba38o0ji5r"},
		{"w", "example", "k8udemvp1j2f7eg6jebps17vp3n8i58h"},
		{"*.w", "example", "r53bq7cc2uvmubfu5ocmm6pers9tk9en"},
		{"x.w", "example", "b4um86eghhds6nea196smvmlo4ors995"},
		{"xx", "example", "t644ebqk9bibcna874givr6joj62mlhv"},
	}

	for _, tc := range tests {
		t.Run(tc.label+"."+tc.zone, func(t *testing.T) {
			nh, err := newNSEC3Hasher(tc.zone, 12, "aabbccdd")
			if err != nil {
				t.Fatalf("newNSEC3Hasher error: %v", err)
			}
			label := tc.label
			if label == "" {
				label = tc.zone
				nh2, _ := newNSEC3Hasher("", 12, "aabbccdd")
				got := nh2.HashFQDN(tc.zone)
				want := strings.ToUpper(tc.want)
				if got != want {
					t.Errorf("HashFQDN(%q) = %s, want %s", tc.zone, got, want)
				}
				return
			}
			got := nh.Hash(label)
			want := strings.ToUpper(tc.want)
			if got != want {
				t.Errorf("Hash(%q) = %s, want %s", label, got, want)
			}
		})
	}
}

func TestNSEC3Hash_WithZone(t *testing.T) {
	nh, err := newNSEC3Hasher("example.com", 10, "aabb")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	got := nh.Hash("www")
	if got == "" {
		t.Fatal("empty hash")
	}
	if len(got) != 32 {
		t.Errorf("unexpected hash length: %d (want 32 base32hex chars)", len(got))
	}
}

func TestDefaultCorpus(t *testing.T) {
	corpus := defaultCorpus()
	if len(corpus) == 0 {
		t.Fatal("default corpus is empty")
	}
	seen := make(map[string]bool)
	for _, l := range corpus {
		if l == "" {
			t.Error("empty label in default corpus")
		}
		if seen[l] {
			t.Errorf("duplicate label: %s", l)
		}
		seen[l] = true
	}
}
