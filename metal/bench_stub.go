//go:build !darwin || !cgo

// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package metal

import (
	"fmt"
	"time"
)

// HashBatch is only available on macOS with CGO enabled.
func HashBatch(labels []string, zone string, nsec3Iter uint16, saltHex string) (map[string]string, string, error) {
	_ = labels
	_ = zone
	_ = nsec3Iter
	_ = saltHex
	return nil, "", fmt.Errorf("Metal GPU hashing requires macOS with CGO enabled (export CGO_ENABLED=1)")
}

// RunMetalBenchmark is only available on macOS with CGO enabled (links Metal.framework).
func RunMetalBenchmark(iterations int, zone string, nsec3Iter uint16, saltHex string) (hashesPerSec float64, deviceName string, elapsed time.Duration, total uint64, err error) {
	_ = iterations
	_ = zone
	_ = nsec3Iter
	_ = saltHex
	return 0, "", 0, 0, fmt.Errorf("Metal GPU benchmark requires macOS with CGO enabled (export CGO_ENABLED=1)")
}

// DefaultDeviceName reports the Metal GPU name only when built with darwin && cgo.
func DefaultDeviceName() string {
	return ""
}
