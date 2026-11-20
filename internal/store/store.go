// Package store keeps check history and the current state of every check in
// SQLite (pure Go driver, so the binary stays static).
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Juanen47/segwatch/internal/api"
	"github.com/Juanen47/segwatch/internal/policy"
)

const schema = `
CREATE TABLE IF NOT EXISTS results (
	id          INTEGER PRIMARY KEY,
	at          INTEGER NOT NULL,
	probe       TEXT NOT NULL,
	check_id    TEXT NOT NULL,
	outcome     TEXT NOT NULL,
	pass        INTEGER NOT NULL,
	detail      TEXT NOT NULL DEFAULT '',
	duration_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS results_check_at ON results(check_id, at);
CREATE TABLE IF NOT EXISTS state (
	check_id  TEXT PRIMARY KEY,
	probe     TEXT NOT NULL,
	flow      TEXT NOT NULL,
	port      TEXT NOT NULL,
	expect    TEXT NOT NULL,
	outcome   TEXT NOT NULL,
	pass      INTEGER NOT NULL,
	detail    TEXT NOT NULL DEFAULT '',
	since     INTEGER NOT NULL,
	last_seen INTEGER NOT NULL
);`

// Store is a SQLite-backed history.
type Store struct{ db *sql.DB }

// Open opens (or creates) the database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Change is a check whose pass/fail state differs from the previous run.
type Change struct {
	Check    policy.Check
	Previous *api.CheckState // nil when the check is new
	Current  api.CheckState
}

// Record stores a report from probe and returns the checks that changed
// state. checks maps check ID to the check the probe was asked to run;
// results for unknown IDs must be filtered out by the caller.
func (s *Store) Record(ctx context.Context, probe string, at time.Time, checks map[string]policy.Check, results []api.Result) ([]Change, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit

	var changes []Change
	ts := at.Unix()
	for _, r := range results {
		c := checks[r.CheckID]
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO results(at, probe, check_id, outcome, pass, detail, duration_ms) VALUES (?,?,?,?,?,?,?)`,
			ts, probe, r.CheckID, r.Outcome, r.Pass, r.Detail, r.DurationMS); err != nil {
			return nil, err
		}

		prev, err := getState(ctx, tx, r.CheckID)
		if err != nil {
			return nil, err
		}
		cur := api.CheckState{
			CheckID: r.CheckID, Probe: probe, Flow: c.Flow, Port: c.Port.String(),
			Expect: string(c.Expect), Outcome: r.Outcome, Pass: r.Pass, Detail: r.Detail,
			Since: at, Seen: at,
		}
		if prev != nil && prev.Pass == r.Pass {
			cur.Since = prev.Since
		} else if prev != nil || !r.Pass {
			// A new check is only worth reporting when it starts out failing.
			changes = append(changes, Change{Check: c, Previous: prev, Current: cur})
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO state(check_id, probe, flow, port, expect, outcome, pass, detail, since, last_seen)
			VALUES (?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(check_id) DO UPDATE SET probe=excluded.probe, flow=excluded.flow, port=excluded.port,
				expect=excluded.expect, outcome=excluded.outcome, pass=excluded.pass, detail=excluded.detail,
				since=excluded.since, last_seen=excluded.last_seen`,
			cur.CheckID, cur.Probe, cur.Flow, cur.Port, cur.Expect, cur.Outcome, cur.Pass, cur.Detail,
			cur.Since.Unix(), ts); err != nil {
			return nil, err
		}
	}
	return changes, tx.Commit()
}

// Status returns every known check. A check not seen for staleAfter is stale.
func (s *Store) Status(ctx context.Context, now time.Time, staleAfter time.Duration) (api.Status, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT check_id, probe, flow, port, expect, outcome, pass, detail, since, last_seen
		FROM state ORDER BY flow, check_id`)
	if err != nil {
		return api.Status{}, err
	}
	defer rows.Close()
	st := api.Status{Generated: now}
	for rows.Next() {
		var cs api.CheckState
		var since, seen int64
		if err := rows.Scan(&cs.CheckID, &cs.Probe, &cs.Flow, &cs.Port, &cs.Expect, &cs.Outcome,
			&cs.Pass, &cs.Detail, &since, &seen); err != nil {
			return api.Status{}, err
		}
		cs.Since, cs.Seen = time.Unix(since, 0).UTC(), time.Unix(seen, 0).UTC()
		st.Total++
		if !cs.Pass {
			st.Failing++
		}
		if now.Sub(cs.Seen) > staleAfter {
			st.Stale++
		}
		st.Checks = append(st.Checks, cs)
	}
	return st, rows.Err()
}

// Prune deletes results older than keep.
func (s *Store) Prune(ctx context.Context, now time.Time, keep time.Duration) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM results WHERE at < ?`, now.Add(-keep).Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func getState(ctx context.Context, q querier, id string) (*api.CheckState, error) {
	var cs api.CheckState
	var since, seen int64
	err := q.QueryRowContext(ctx, `
		SELECT check_id, probe, flow, port, expect, outcome, pass, detail, since, last_seen
		FROM state WHERE check_id = ?`, id).Scan(&cs.CheckID, &cs.Probe, &cs.Flow, &cs.Port,
		&cs.Expect, &cs.Outcome, &cs.Pass, &cs.Detail, &since, &seen)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cs.Since, cs.Seen = time.Unix(since, 0).UTC(), time.Unix(seen, 0).UTC()
	return &cs, nil
}
