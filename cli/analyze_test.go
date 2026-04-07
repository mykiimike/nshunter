// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package cli

import (
	"testing"
	"time"
)

func TestParseBruteforceTimeout(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{in: "", want: 0},
		{in: "60s", want: 60 * time.Second},
		{in: "15m", want: 15 * time.Minute},
		{in: "2h", want: 2 * time.Hour},
		{in: "1d", want: 24 * time.Hour},
		{in: "1.5d", want: 36 * time.Hour},
		{in: "0", wantErr: true},
		{in: "-2m", wantErr: true},
		{in: "abc", wantErr: true},
		{in: "d", wantErr: true},
	}

	for _, tc := range tests {
		got, err := parseBruteforceTimeout(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("parseBruteforceTimeout(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseBruteforceTimeout(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("parseBruteforceTimeout(%q): got %s, want %s", tc.in, got, tc.want)
		}
	}
}
