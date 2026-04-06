// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package dns

import (
	"reflect"
	"testing"
)

func TestNamesUnderZoneFromStrings(t *testing.T) {
	zone := "example.com"
	raw := []string{
		"www.example.com",
		"WWW.EXAMPLE.COM",
		"example.com",
		"*.example.com",
		"other.org",
		"api.example.com\nstaging.example.com",
	}
	got := namesUnderZoneFromStrings(zone, raw)
	want := []string{"api.example.com", "staging.example.com", "www.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
