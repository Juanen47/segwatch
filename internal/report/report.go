// Package report renders the controller's history as a self-contained HTML
// page: a matrix of source networks against destinations, every check with
// its expected and observed result, and the recent state changes.
//
// The page has no scripts and no external resources, so it can be archived
// or attached to an audit as is.
package report

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"sort"
	"time"

	"github.com/Juanen47/segwatch/internal/policy"
	"github.com/Juanen47/segwatch/internal/store"
)

// Status of a check in the report.
const (
	Pass    = "pass"
	Fail    = "fail"
	Stale   = "stale"   // its probe has not reported for a while
	Pending = "pending" // in the policy, but no result yet
)

// Row is one check.
type Row struct {
	ID       string
	Flow     string
	From     string
	To       string
	Address  string
	Port     string
	Expect   string
	Observed string
	Status   string
	Detail   string
	Since    time.Time
	Seen     time.Time
	Runs     int
	Passes   int
}

// Uptime is the share of runs in the period that matched the policy.
func (r Row) Uptime() string {
	if r.Runs == 0 {
		return "–"
	}
	return fmt.Sprintf("%.1f %%", 100*float64(r.Passes)/float64(r.Runs))
}

// Cell is one source/destination pair of the matrix.
type Cell struct {
	Rows   []Row
	Status string // worst status in the cell, empty when nothing is tested
}

// Change is a pass/fail flip.
type Change struct {
	At       time.Time
	Flow     string
	From     string
	To       string
	Port     string
	Pass     bool
	Observed string
	Detail   string
}

// Report is everything the page shows.
type Report struct {
	Generated  time.Time
	Since      time.Time
	Version    string
	PolicyHash string

	Total, Passing, Failing, Stale, Pending int

	Sources []string
	Dests   []string
	Matrix  [][]Cell // [source][dest]
	Rows    []Row
	Changes []Change
	Retired []Row // checks with history that are no longer in the policy
}

// Options control what goes into the report.
type Options struct {
	Now        time.Time
	Period     time.Duration // history window for uptime and changes
	StaleAfter time.Duration
	Version    string
	PolicyRaw  []byte // hashed into the footer, so the report names the policy it checked
	MaxChanges int
}

// Build collects the report from the policy and the store.
func Build(ctx context.Context, pol *policy.Policy, st *store.Store, opt Options) (*Report, error) {
	if opt.MaxChanges <= 0 {
		opt.MaxChanges = 50
	}
	since := opt.Now.Add(-opt.Period)
	status, err := st.Status(ctx, opt.Now, opt.StaleAfter)
	if err != nil {
		return nil, err
	}
	hist, err := st.History(ctx, since)
	if err != nil {
		return nil, err
	}
	trans, err := st.Transitions(ctx, since, opt.MaxChanges)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(opt.PolicyRaw)
	r := &Report{Generated: opt.Now, Since: since, Version: opt.Version, PolicyHash: hex.EncodeToString(sum[:])}

	state := map[string]int{}
	for i, c := range status.Checks {
		state[c.CheckID] = i
	}
	inPolicy := map[string]Row{}
	for _, n := range pol.NetworkNames() {
		checks, _ := pol.ChecksFrom(n)
		for _, c := range checks {
			row := Row{
				ID: c.ID(), Flow: c.Flow, From: c.From, To: c.To, Address: c.Address.String(),
				Port: c.Port.String(), Expect: string(c.Expect), Status: Pending,
			}
			if i, ok := state[row.ID]; ok {
				s := status.Checks[i]
				row.Observed, row.Detail, row.Since, row.Seen = s.Outcome, s.Detail, s.Since, s.Seen
				switch {
				case opt.Now.Sub(s.Seen) > opt.StaleAfter:
					row.Status = Stale
				case s.Pass:
					row.Status = Pass
				default:
					row.Status = Fail
				}
			}
			h := hist[row.ID]
			row.Runs, row.Passes = h.Runs, h.Passes
			r.Rows = append(r.Rows, row)
			inPolicy[row.ID] = row
		}
	}
	for _, s := range status.Checks {
		if _, ok := inPolicy[s.CheckID]; !ok {
			r.Retired = append(r.Retired, Row{ID: s.CheckID, Flow: s.Flow, Port: s.Port, Expect: s.Expect,
				Observed: s.Outcome, Seen: s.Seen})
		}
	}
	sort.SliceStable(r.Rows, func(i, j int) bool {
		a, b := r.Rows[i], r.Rows[j]
		if rank(a.Status) != rank(b.Status) {
			return rank(a.Status) > rank(b.Status) // failures first
		}
		if a.Flow != b.Flow {
			return a.Flow < b.Flow
		}
		return a.Port < b.Port
	})

	for _, row := range r.Rows {
		r.Total++
		switch row.Status {
		case Pass:
			r.Passing++
		case Fail:
			r.Failing++
		case Stale:
			r.Stale++
		default:
			r.Pending++
		}
	}

	r.buildMatrix(pol)

	for _, t := range trans {
		row, ok := inPolicy[t.CheckID]
		if !ok {
			continue
		}
		r.Changes = append(r.Changes, Change{At: t.At, Flow: row.Flow, From: row.From, To: row.To,
			Port: row.Port, Pass: t.Pass, Observed: t.Outcome, Detail: t.Detail})
	}
	return r, nil
}

func rank(status string) int {
	switch status {
	case Fail:
		return 3
	case Stale:
		return 2
	case Pending:
		return 1
	}
	return 0
}

func (r *Report) buildMatrix(pol *policy.Policy) {
	src, dst := map[string]bool{}, map[string]bool{}
	for _, row := range r.Rows {
		src[row.From], dst[row.To] = true, true
	}
	// Columns: networks first (in name order), then targets.
	for _, n := range pol.NetworkNames() {
		if src[n] {
			r.Sources = append(r.Sources, n)
		}
		if dst[n] {
			r.Dests = append(r.Dests, n)
		}
	}
	var targets []string
	for t := range pol.Targets {
		if dst[t] {
			targets = append(targets, t)
		}
	}
	sort.Strings(targets)
	r.Dests = append(r.Dests, targets...)

	si, di := index(r.Sources), index(r.Dests)
	r.Matrix = make([][]Cell, len(r.Sources))
	for i := range r.Matrix {
		r.Matrix[i] = make([]Cell, len(r.Dests))
	}
	for _, row := range r.Rows {
		c := &r.Matrix[si[row.From]][di[row.To]]
		c.Rows = append(c.Rows, row)
		if c.Status == "" || rank(row.Status) > rank(c.Status) {
			c.Status = row.Status
		}
	}
	for i := range r.Matrix {
		for j := range r.Matrix[i] {
			rows := r.Matrix[i][j].Rows
			sort.SliceStable(rows, func(a, b int) bool { return rows[a].Port < rows[b].Port })
		}
	}
}

func index(names []string) map[string]int {
	m := make(map[string]int, len(names))
	for i, n := range names {
		m[n] = i
	}
	return m
}

//go:embed report.html.tmpl
var pageSrc string

var page = template.Must(template.New("report").Funcs(template.FuncMap{
	"ts": func(t time.Time) string {
		if t.IsZero() {
			return "–"
		}
		return t.UTC().Format("2006-01-02 15:04 UTC")
	},
	"tss":  func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") },
	"date": func(t time.Time) string { return t.UTC().Format("2006-01-02") },
	"mark": func(status string) string {
		switch status {
		case Pass:
			return "✓"
		case Fail:
			return "✗"
		case Stale:
			return "?"
		}
		return "…"
	},
}).Parse(pageSrc))

// Render writes the report as HTML.
func (r *Report) Render(w io.Writer) error { return page.Execute(w, r) }
