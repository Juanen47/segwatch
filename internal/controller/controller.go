// Package controller serves jobs to probes and records their results.
package controller

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
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

	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	changes, err := s.Store.Record(r.Context(), probe, now().UTC(), known, accepted)
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
