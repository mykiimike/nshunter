// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package store

import (
	"os"
	"path/filepath"
)

func DefaultDataDir() string {
	if env := os.Getenv("NSHUNTER_HOME"); env != "" {
		return env
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".nshunter")
}

func ensureDirs(base string) error {
	dirs := []string{
		filepath.Join(base, "db"),
		filepath.Join(base, "corpus"),
		filepath.Join(base, "reports"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}
