// Package agent runs a probe: it asks the controller for work, answers checks
// from other probes, runs its own checks and reports the results.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Juanen47/segwatch/internal/api"
	"github.com/Juanen47/segwatch/internal/check"
	"github.com/Juanen47/segwatch/internal/pki"
	"github.com/Juanen47/segwatch/internal/policy"
	"github.com/Juanen47/segwatch/internal/responder"
	"github.com/Juanen47/segwatch/internal/runner"
)

// Config configures a probe.
type Config struct {
	Controller  string // https://host:port
	Fingerprint string // sha256:<hex> of the controller certificate
	Token       string
	Bind        string     // address for the responder, "" for all
	Source      netip.Addr // optional fixed source address for checks
	Log         *slog.Logger
	Client      *http.Client // optional, for tests
	RetryAfter  time.Duration
}

// Run loops until ctx is cancelled.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Client == nil {
		c, err := pki.PinnedClient(cfg.Fingerprint, 30*time.Second)
		if err != nil {
			return err
		}
		cfg.Client = c
	}
	if cfg.RetryAfter == 0 {
		cfg.RetryAfter = 30 * time.Second
	}
	base := strings.TrimRight(cfg.Controller, "/")

	var stopResponder context.CancelFunc
	var responderDone chan struct{}
	var listening []policy.Port
	stop := func() {
		if stopResponder != nil {
			stopResponder()
			<-responderDone // wait until the old listeners are closed
		}
	}
	defer stop()

	for {
		wait := cfg.RetryAfter
		job, err := fetchJob(ctx, cfg.Client, base, cfg.Token)
		if err != nil {
			cfg.Log.Error("get job", "err", err)
		} else {
			if !slices.Equal(job.ListenPorts, listening) {
				stop()
				rctx, cancel := context.WithCancel(ctx)
				done := make(chan struct{})
				stopResponder, responderDone, listening = cancel, done, job.ListenPorts
				go func(ports []policy.Port) {
					defer close(done)
					if err := responder.Serve(rctx, cfg.Bind, ports, cfg.Log); err != nil {
						cfg.Log.Error("responder", "err", err)
					}
				}(job.ListenPorts)
			}
			if len(job.Checks) > 0 {
				started := time.Now().UTC()
				results := runner.Run(ctx, job.Checks, runner.Options{Source: cfg.Source})
				if err := sendReport(ctx, cfg.Client, base, cfg.Token, started, results); err != nil {
					cfg.Log.Error("send report", "err", err)
				} else {
					cfg.Log.Info("run complete", "network", job.Network, "checks", len(results), "failing", runner.Failed(results))
				}
			}
			if job.IntervalSec > 0 {
				wait = jitter(time.Duration(job.IntervalSec) * time.Second)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// jitter spreads probes by ±10% so they do not all fire at the same second.
func jitter(d time.Duration) time.Duration {
	delta := float64(d) * 0.1
	return d + time.Duration((rand.Float64()*2-1)*delta)
}

func fetchJob(ctx context.Context, c *http.Client, base, token string) (api.Job, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+api.JobsPath, nil)
	if err != nil {
		return api.Job{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		return api.Job{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return api.Job{}, fmt.Errorf("controller answered %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var job api.Job
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&job); err != nil {
		return api.Job{}, err
	}
	return job, nil
}

func sendReport(ctx context.Context, c *http.Client, base, token string, started time.Time, rs []check.Result) error {
	rep := api.Report{StartedAt: started}
	for _, r := range rs {
		rep.Results = append(rep.Results, api.Result{
			CheckID: r.Check.ID(), Outcome: string(r.Outcome), Pass: r.Pass,
			Detail: r.Detail, DurationMS: r.Duration.Milliseconds(),
		})
	}
	body, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+api.ResultsPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("controller answered %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}
