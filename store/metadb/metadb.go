// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package metadb

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mykiimike/nshunter/model"

	_ "modernc.org/sqlite"
)

type MetaDB struct {
	db *sql.DB
}

func Open(path string) (*MetaDB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(wal)")
	if err != nil {
		return nil, fmt.Errorf("sqlite open: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migration: %w", err)
	}

	return &MetaDB{db: db}, nil
}

func (m *MetaDB) Close() error {
	return m.db.Close()
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS reports (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			zone        TEXT NOT NULL,
			analyzed_at TEXT NOT NULL,
			dnssec_type TEXT NOT NULL,
			run_options_json TEXT,
			nsec3_params_json TEXT,
			metrics_json TEXT NOT NULL,
			risk_json   TEXT NOT NULL,
			enumerated_names_json TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_reports_zone ON reports(zone);
		CREATE INDEX IF NOT EXISTS idx_reports_time ON reports(analyzed_at DESC);
	`)
	if err != nil {
		return err
	}
	// Backward-compatible migration for existing databases created before
	// run_options_json existed.
	if _, err := db.Exec(`ALTER TABLE reports ADD COLUMN run_options_json TEXT`); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			return err
		}
	}
	return nil
}

func (m *MetaDB) InsertReport(r *model.Report) error {
	var runOptionsJSON []byte
	if r.RunOptions != nil {
		var err error
		runOptionsJSON, err = json.Marshal(r.RunOptions)
		if err != nil {
			return err
		}
	}
	var nsec3JSON []byte
	if r.NSEC3Params != nil {
		var err error
		nsec3JSON, err = json.Marshal(r.NSEC3Params)
		if err != nil {
			return err
		}
	}
	metricsJSON, err := json.Marshal(r.Metrics)
	if err != nil {
		return err
	}
	riskJSON, err := json.Marshal(r.Risk)
	if err != nil {
		return err
	}
	var namesJSON []byte
	if len(r.EnumeratedNames) > 0 {
		namesJSON, err = json.Marshal(r.EnumeratedNames)
		if err != nil {
			return err
		}
	}

	_, err = m.db.Exec(
		`INSERT INTO reports (zone, analyzed_at, dnssec_type, run_options_json, nsec3_params_json, metrics_json, risk_json, enumerated_names_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Zone,
		r.AnalyzedAt.Format(time.RFC3339),
		r.DNSSECType,
		nullString(runOptionsJSON),
		nullString(nsec3JSON),
		string(metricsJSON),
		string(riskJSON),
		nullString(namesJSON),
	)
	return err
}

func (m *MetaDB) LatestReport(domain string) (*model.Report, error) {
	query := `SELECT zone, analyzed_at, dnssec_type, run_options_json, nsec3_params_json, metrics_json, risk_json, enumerated_names_json
	          FROM reports`
	var args []any

	if domain != "" {
		query += ` WHERE zone = ?`
		args = append(args, domain)
	}
	query += ` ORDER BY analyzed_at DESC LIMIT 1`

	var r model.Report
	var analyzedAt string
	var runOptionsRaw, nsec3Raw, namesRaw sql.NullString
	var metricsRaw, riskRaw string

	err := m.db.QueryRow(query, args...).Scan(
		&r.Zone, &analyzedAt, &r.DNSSECType, &runOptionsRaw, &nsec3Raw, &metricsRaw, &riskRaw, &namesRaw,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no reports found")
		}
		return nil, err
	}

	r.AnalyzedAt, _ = time.Parse(time.RFC3339, analyzedAt)

	if runOptionsRaw.Valid {
		r.RunOptions = &model.RunOptions{}
		if err := json.Unmarshal([]byte(runOptionsRaw.String), r.RunOptions); err != nil {
			return nil, err
		}
	}
	if nsec3Raw.Valid {
		r.NSEC3Params = &model.NSEC3Params{}
		if err := json.Unmarshal([]byte(nsec3Raw.String), r.NSEC3Params); err != nil {
			return nil, err
		}
	}
	if err := json.Unmarshal([]byte(metricsRaw), &r.Metrics); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(riskRaw), &r.Risk); err != nil {
		return nil, err
	}
	if namesRaw.Valid {
		if err := json.Unmarshal([]byte(namesRaw.String), &r.EnumeratedNames); err != nil {
			return nil, err
		}
	}

	return &r, nil
}

func (m *MetaDB) ListReports(domain string) ([]*model.Report, error) {
	query := `SELECT zone, analyzed_at, dnssec_type, run_options_json, nsec3_params_json, metrics_json, risk_json, enumerated_names_json
	          FROM reports`
	var args []any
	if domain != "" {
		query += ` WHERE zone = ?`
		args = append(args, domain)
	}
	query += ` ORDER BY analyzed_at DESC`

	rows, err := m.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	reports := make([]*model.Report, 0)
	for rows.Next() {
		var r model.Report
		var analyzedAt string
		var runOptionsRaw, nsec3Raw, namesRaw sql.NullString
		var metricsRaw, riskRaw string

		if err := rows.Scan(
			&r.Zone, &analyzedAt, &r.DNSSECType, &runOptionsRaw, &nsec3Raw, &metricsRaw, &riskRaw, &namesRaw,
		); err != nil {
			return nil, err
		}

		r.AnalyzedAt, _ = time.Parse(time.RFC3339, analyzedAt)
		if runOptionsRaw.Valid {
			r.RunOptions = &model.RunOptions{}
			if err := json.Unmarshal([]byte(runOptionsRaw.String), r.RunOptions); err != nil {
				return nil, err
			}
		}
		if nsec3Raw.Valid {
			r.NSEC3Params = &model.NSEC3Params{}
			if err := json.Unmarshal([]byte(nsec3Raw.String), r.NSEC3Params); err != nil {
				return nil, err
			}
		}
		if err := json.Unmarshal([]byte(metricsRaw), &r.Metrics); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(riskRaw), &r.Risk); err != nil {
			return nil, err
		}
		if namesRaw.Valid {
			if err := json.Unmarshal([]byte(namesRaw.String), &r.EnumeratedNames); err != nil {
				return nil, err
			}
		}

		reportCopy := r
		reports = append(reports, &reportCopy)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return reports, nil
}

func nullString(b []byte) sql.NullString {
	if b == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(b), Valid: true}
}
