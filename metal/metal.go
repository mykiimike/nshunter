// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package metal

// GPU support: Metal hashing path and benchmark (see kernel.metal, bench_darwin.go).

type Hasher interface {
	// HashBatch computes NSEC3 hashes for a batch of labels.
	// Returns a map of label -> base32hex hash.
	HashBatch(labels []string, zone string, iterations uint16, saltHex string) (map[string]string, error)

	// Available reports whether the Metal GPU backend is usable.
	Available() bool

	// DeviceName returns the GPU device identifier.
	DeviceName() string

	Close()
}

type Stub struct{}

func (s *Stub) HashBatch(_ []string, _ string, _ uint16, _ string) (map[string]string, error) {
	return nil, nil
}

func (s *Stub) Available() bool    { return false }
func (s *Stub) DeviceName() string { return "none (Metal not compiled)" }
func (s *Stub) Close()             {}

func NewStub() Hasher {
	return &Stub{}
}
