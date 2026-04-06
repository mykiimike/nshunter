// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package store

import (
	"fmt"
	"path/filepath"

	"github.com/mykiimike/nshunter/model"
	"github.com/mykiimike/nshunter/store/hashdb"
	"github.com/mykiimike/nshunter/store/metadb"
)

type Store struct {
	HashDB *hashdb.HashDB
	MetaDB *metadb.MetaDB
	base   string
}

func Open(base string) (*Store, error) {
	if err := ensureDirs(base); err != nil {
		return nil, fmt.Errorf("creating data dirs: %w", err)
	}

	hdb, err := hashdb.Open(filepath.Join(base, "db", "hashes.pebble"))
	if err != nil {
		return nil, fmt.Errorf("opening hashdb: %w", err)
	}

	mdb, err := metadb.Open(filepath.Join(base, "db", "meta.sqlite"))
	if err != nil {
		hdb.Close()
		return nil, fmt.Errorf("opening metadb: %w", err)
	}

	return &Store{HashDB: hdb, MetaDB: mdb, base: base}, nil
}

func (s *Store) Close() error {
	var firstErr error
	if err := s.HashDB.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := s.MetaDB.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func (s *Store) SaveReport(r *model.Report) error {
	return s.MetaDB.InsertReport(r)
}

func (s *Store) LatestReport(domain string) (*model.Report, error) {
	return s.MetaDB.LatestReport(domain)
}

func (s *Store) ListReports(domain string) ([]*model.Report, error) {
	return s.MetaDB.ListReports(domain)
}
