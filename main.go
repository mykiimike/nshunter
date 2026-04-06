// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"

	"github.com/mykiimike/nshunter/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
