// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package buildinfo

// Version is the semantic version of nshunter.
// It can be overridden at build time with:
//   go build -ldflags "-X github.com/mykiimike/nshunter/internal/buildinfo.Version=1.2.3"
var Version = "1.0.0"
