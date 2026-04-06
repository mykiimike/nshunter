// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package engine

import (
	"reflect"
	"testing"
)

func TestCrackNSEC3CorpusParallelMatchesSequential(t *testing.T) {
	observed := map[string]bool{
		"4BV5GG5GMED5LISP9JL98EFDEA6NL2UH": true,
	}
	domain := "net"
	salt := ""
	iter := uint16(0)

	var corpus []string
	for i := 0; i < 2000; i++ {
		corpus = append(corpus, "zzznonexistentlabel")
	}
	corpus = append(corpus, "google")

	seq := crackNSEC3CorpusSequential(observed, corpus, domain, iter, salt)
	par := crackNSEC3CorpusParallel(observed, corpus, domain, iter, salt)

	if !reflect.DeepEqual(seq, par) {
		t.Fatalf("sequential %v != parallel %v", seq, par)
	}
	if len(seq) != 1 || seq[0] != "google.net" {
		t.Fatalf("unexpected match: %v", seq)
	}
}
