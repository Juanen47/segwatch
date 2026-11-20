// Package controller serves jobs to probes and records their results.
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Juanen47/segwatch/internal/api"
	"github.com/Juanen47/segwatch/internal/policy"
	"github.com/Juanen47/segwatch/internal/store"
)

const maxReportBytes = 1 << 20

// TokenLookup resolves a bearer token to a probe name.
type TokenLookup interface {
	Lookup(token string) (string, bool)
}

// Server is the controller HTTP API.
type Server struct {
	Policy   *policy.Policy
	Tokens   TokenLookup
	Store    *store.Store
	Log      *slog.Logger
	OnChange func([]store.Change) // optional, called after a report with state changes
	Now      func() time.Time     // optional, for tests

	// SilentAfter is how long a probe may go without contacting the
	// controller before it counts as down. A deny check towards a probe
	// that is down cannot pass: no answer from a dead host looks exactly
	// like a block, so the result is recorded as "unverified" instead.
	// Zero disables the rule.
	SilentAfter time.Duration

	mu        sync.Mutex
	started   time.Time
	lastHeard map[string]time.Time
}

// Unverified is the outcome recorded for a deny check that looked blocked
// while its destination probe was not in contact with the controller.
const Unverified = "unverified"

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// heard records that probe contacted the controller at t.
func (s *Server) heard(probe string, t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastHeard == nil {
		s.lastHeard = map[string]time.Time{}
	}
	s.lastHeard[probe] = t
}

// silent reports whether probe has gone longer than SilentAfter without
// contacting the controller, and when it was last heard from. A probe never
// heard from gets SilentAfter of grace from the controller's start.
func (s *Server) silent(probe string, t time.Time) (bool, time.Time) {
	if s.SilentAfter <= 0 {
		return false, time.Time{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started.IsZero() {
		s.started = t
	}
	last, ok := s.lastHeard[probe]
	if !ok {
		return t.Sub(s.started) > s.SilentAfter, time.Time{}
	}
	return t.Sub(last) > s.SilentAfter, last
}

// Start marks the controller start, from which probes never heard from get
// their grace period. Calling it is optional (the first report sets it).
func (s *Server) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = s.now()
}

// Handler returns the HTTP handler for the API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+api.JobsPath, s.auth(s.jobs))
	mux.HandleFunc("POST "+api.ResultsPath, s.auth(s.results))
	return mux
}

type probeKey struct{}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		probe, known := "", false
		if ok {
			probe, known = s.Tokens.Lookup(tok)
		}
		if !known {
			s.Log.Warn("rejected request: bad or missing token", "remote", r.RemoteAddr, "path", r.URL.Path)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if _, inPolicy := s.Policy.NetworkOfProbe(probe); !inPolicy {
			s.Log.Warn("rejected request: probe not in policy", "probe", probe, "remote", r.RemoteAddr)
			http.Error(w, "probe not in policy", http.StatusForbidden)
			return
		}
		s.heard(probe, s.now())
		next(w, r.WithContext(context.WithValue(r.Context(), probeKey{}, probe)))
	}
}

func (s *Server) jobFor(probe string) (api.Job, error) {
	network, _ := s.Policy.NetworkOfProbe(probe)
	checks, err := s.Policy.ChecksFrom(network)
	if err != nil {
		return api.Job{}, err
	}
	ports, err := s.Policy.ListenPorts(network)
	if err != nil {
		return api.Job{}, err
	}
	return api.Job{
		Probe: probe, Network: network,
		IntervalSec: int(s.Policy.Defaults.Interval.Std() / time.Second),
		ListenPorts: ports, Checks: checks,
	}, nil
}

func (s *Server) jobs(w http.ResponseWriter, r *http.Request) {
	probe := r.Context().Value(probeKey{}).(string)
	job, err := s.jobFor(probe)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(job)
}

func (s *Server) results(w http.ResponseWriter, r *http.Request) {
	probe := r.Context().Value(probeKey{}).(string)
	var rep api.Report
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxReportBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rep); err != nil {
		http.Error(w, "bad report: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Only accept results for checks this probe was actually given.
	job, err := s.jobFor(probe)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	known := make(map[string]policy.Check, len(job.Checks))
	for _, c := range job.Checks {
		known[c.ID()] = c
	}
	accepted := rep.Results[:0]
	for _, res := range rep.Results {
		if _, ok := known[res.CheckID]; ok {
			accepted = append(accepted, res)
		} else {
			s.Log.Warn("ignored result for a check not assigned to this probe", "probe", probe, "check", res.CheckID)
		}
	}

	at := s.now()
	for i, res := range accepted {
		accepted[i] = s.verifyDeny(known[res.CheckID], res, at)
	}
	changes, err := s.Store.Record(r.Context(), probe, at, known, accepted)
	if err != nil {
		s.Log.Error("store results", "err", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	failing := 0
	for _, res := range accepted {
		if !res.Pass {
			failing++
		}
	}
	s.Log.Info("report", "probe", probe, "checks", len(accepted), "failing", failing, "changes", len(changes))
	for _, c := range changes {
		lvl := slog.LevelWarn
		if c.Current.Pass {
			lvl = slog.LevelInfo
		}
		s.Log.Log(r.Context(), lvl, "state change", "check", c.Current.CheckID,
			"pass", c.Current.Pass, "outcome", c.Current.Outcome, "detail", c.Current.Detail)
	}
	if len(changes) > 0 && s.OnChange != nil {
		s.OnChange(changes)
	}
	w.WriteHeader(http.StatusNoContent)
}

// verifyDeny downgrades a passing deny check towards a segwatch probe that
// is not in contact with the controller. Without a live responder there,
// "no answer" (or a reset from a host whose responder died) proves nothing.
func (s *Server) verifyDeny(c policy.Check, res api.Result, at time.Time) api.Result {
	if !c.Responder || c.Expect != policy.Deny || !res.Pass {
		return res
	}
	dest := s.Policy.Networks[c.To].Probe.Name
	silent, last := s.silent(dest, at)
	if !silent {
		return res
	}
	res.Pass = false
	res.Detail = fmt.Sprintf("observed %s, but destination probe %s is silent", res.Outcome, dest)
	if !last.IsZero() {
		res.Detail += " since " + last.Format(time.RFC3339)
	}
	res.Detail += "; a block cannot be told apart from a host that is down"
	res.Outcome = Unverified
	return res
}
