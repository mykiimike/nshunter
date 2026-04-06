// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package hashdb

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"syscall"

	"github.com/cockroachdb/pebble"
)

type HashDB struct {
	db *pebble.DB
}

type HashEntry struct {
	Label string `json:"label,omitempty"`
	Zone  string `json:"zone"`
}

func Open(path string) (*HashDB, error) {
	db, err := pebble.Open(path, &pebble.Options{})
	if err != nil {
		if isPebbleLockBusy(err) {
			return nil, fmt.Errorf("pebble open: database at %s is locked (stop other nshunter instances or use --data-dir): %w", path, err)
		}
		return nil, fmt.Errorf("pebble open: %w", err)
	}
	return &HashDB{db: db}, nil
}

// isPebbleLockBusy reports errno EAGAIN from Pebble's exclusive DB lock (another process has the store open).
func isPebbleLockBusy(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EAGAIN) {
		return true
	}
	// macOS/Linux map EAGAIN to this phrase in err.Error().
	return strings.Contains(err.Error(), "resource temporarily unavailable")
}

func (h *HashDB) Close() error {
	return h.db.Close()
}

func (h *HashDB) Put(hashHex string, entry *HashEntry) error {
	val, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return h.db.Set([]byte(hashHex), val, pebble.Sync)
}

func (h *HashDB) PutBatch(entries map[string]*HashEntry) error {
	batch := h.db.NewBatch()
	defer batch.Close()

	for hashHex, entry := range entries {
		val, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		if err := batch.Set([]byte(hashHex), val, nil); err != nil {
			return err
		}
	}
	return batch.Commit(pebble.Sync)
}

func (h *HashDB) Get(hashHex string) (*HashEntry, error) {
	val, closer, err := h.db.Get([]byte(hashHex))
	if err != nil {
		if err == pebble.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	defer closer.Close()

	var entry HashEntry
	if err := json.Unmarshal(val, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// RangeCount returns how many entries exist in [startHex, endHex).
func (h *HashDB) RangeCount(startHex, endHex string) (int, error) {
	iter, err := h.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte(startHex),
		UpperBound: []byte(endHex),
	})
	if err != nil {
		return 0, err
	}
	defer iter.Close()

	count := 0
	for iter.First(); iter.Valid(); iter.Next() {
		count++
	}
	return count, iter.Error()
}
