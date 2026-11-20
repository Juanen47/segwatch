// Package api holds the JSON messages exchanged between probes and the controller.
package api

import (
	"time"

	"github.com/Juanen47/segwatch/internal/policy"
)

const (
	// JobsPath returns the work for the calling probe.
	JobsPath = "/api/v1/jobs"
	// ResultsPath receives the results of a run.
	ResultsPath = "/api/v1/results"
)

// Job is what a probe must do until it asks again.
type Job struct {
	Probe       string         `json:"probe"`
	Network     string         `json:"network"`
	IntervalSec int            `json:"interval_sec"`
	ListenPorts []policy.Port  `json:"listen_ports"`
	Checks      []policy.Check `json:"checks"`
}

// Result is one check outcome reported by a probe.
type Result struct {
	CheckID    string `json:"check_id"`
	Outcome    string `json:"outcome"`
	Pass       bool   `json:"pass"`
	Detail     string `json:"detail,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

// Report is the body a probe posts after a run.
type Report struct {
	StartedAt time.Time `json:"started_at"`
	Results   []Result  `json:"results"`
}

// CheckState is the latest known state of one check.
type CheckState struct {
	CheckID string    `json:"check_id"`
	Probe   string    `json:"probe"`
	Flow    string    `json:"flow"`
	From    string    `json:"from,omitempty"`
	To      string    `json:"to,omitempty"`
	Port    string    `json:"port"`
	Expect  string    `json:"expect"`
	Outcome string    `json:"outcome"`
	Pass    bool      `json:"pass"`
	Detail  string    `json:"detail,omitempty"`
	Since   time.Time `json:"since"`
	Seen    time.Time `json:"last_seen"`
}

// Status summarises every check the controller knows about.
type Status struct {
	Generated time.Time    `json:"generated"`
	Total     int          `json:"total"`
	Failing   int          `json:"failing"`
	Stale     int          `json:"stale"`
	Checks    []CheckState `json:"checks"`
}
