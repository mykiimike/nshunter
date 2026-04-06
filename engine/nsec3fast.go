// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package engine

import (
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"hash"
	"strings"
)

var base32HexEncoding = base32.HexEncoding.WithPadding(base32.NoPadding)

// nsec3Hasher is a reusable, zero-alloc-per-hash NSEC3 hasher.
// Pre-computes salt bytes and zone wire suffix once. Each goroutine
// should have its own instance (not thread-safe).
type nsec3Hasher struct {
	salt       []byte
	zoneSuffix []byte // wire-format for ".zone." (without the label prefix)
	iterations uint16
	h          hash.Hash
	wireBuf    []byte // reused buffer for full wire-format name
	digestBuf  [sha1.Size]byte
	encodeBuf  [32]byte
}

func newNSEC3Hasher(zone string, iterations uint16, saltHex string) (*nsec3Hasher, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, err
	}

	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	labels := strings.Split(zone, ".")
	var suffix []byte
	for _, l := range labels {
		suffix = append(suffix, byte(len(l)))
		suffix = append(suffix, l...)
	}
	suffix = append(suffix, 0) // root label

	return &nsec3Hasher{
		salt:       salt,
		zoneSuffix: suffix,
		iterations: iterations,
		h:          sha1.New(),
		wireBuf:    make([]byte, 0, 256),
	}, nil
}

// Hash computes the NSEC3 hash for a single label under the pre-configured zone.
// Returns uppercase base32hex. Minimizes allocations by reusing internal buffers.
func (nh *nsec3Hasher) Hash(label string) string {
	nh.wireBuf = nh.wireBuf[:0]
	if strings.IndexByte(label, '.') < 0 {
		nh.wireBuf = append(nh.wireBuf, byte(len(label)))
		nh.wireBuf = append(nh.wireBuf, label...)
	} else {
		for _, p := range strings.Split(label, ".") {
			nh.wireBuf = append(nh.wireBuf, byte(len(p)))
			nh.wireBuf = append(nh.wireBuf, p...)
		}
	}
	nh.wireBuf = append(nh.wireBuf, nh.zoneSuffix...)
	return nh.digest()
}

// HashBytes hashes a label provided as raw bytes (no dot splitting).
// Avoids string allocation entirely in the hot path.
func (nh *nsec3Hasher) HashBytes(label []byte) string {
	nh.wireBuf = nh.wireBuf[:0]
	nh.wireBuf = append(nh.wireBuf, byte(len(label)))
	nh.wireBuf = append(nh.wireBuf, label...)
	nh.wireBuf = append(nh.wireBuf, nh.zoneSuffix...)
	return nh.digest()
}

// HashFQDN computes the NSEC3 hash for a fully-qualified domain name.
func (nh *nsec3Hasher) HashFQDN(fqdn string) string {
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))
	labels := strings.Split(fqdn, ".")
	nh.wireBuf = nh.wireBuf[:0]
	for _, l := range labels {
		nh.wireBuf = append(nh.wireBuf, byte(len(l)))
		nh.wireBuf = append(nh.wireBuf, l...)
	}
	nh.wireBuf = append(nh.wireBuf, 0)
	return nh.digest()
}

func (nh *nsec3Hasher) digest() string {
	nh.h.Reset()
	nh.h.Write(nh.wireBuf)
	nh.h.Write(nh.salt)
	digest := nh.h.Sum(nh.digestBuf[:0])

	for i := uint16(0); i < nh.iterations; i++ {
		nh.h.Reset()
		nh.h.Write(digest)
		nh.h.Write(nh.salt)
		digest = nh.h.Sum(nh.digestBuf[:0])
	}

	encoded := nh.encodeBuf[:base32HexEncoding.EncodedLen(len(digest))]
	base32HexEncoding.Encode(encoded, digest)
	for i, b := range encoded {
		if b >= 'a' && b <= 'z' {
			encoded[i] = b - 32
		}
	}
	return string(encoded)
}
