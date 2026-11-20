package controller_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Juanen47/segwatch/internal/agent"
	"github.com/Juanen47/segwatch/internal/api"
	"github.com/Juanen47/segwatch/internal/controller"
	"github.com/Juanen47/segwatch/internal/pki"
	"github.com/Juanen47/segwatch/internal/policy"
	"github.com/Juanen47/segwatch/internal/store"
	"github.com/Juanen47/segwatch/internal/tokens"
)

func freeTCP(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

type env struct {
	srv    *httptest.Server
	fp     string
	toks   *tokens.Store
	st     *store.Store
	allowP int
	denyP  int
}

func setup(t *testing.T) env {
	t.Helper()
	allowP, denyP := freeTCP(t), freeTCP(t)
	pol, err := policy.Parse([]byte(fmt.Sprintf(`
version: 1
defaults: { interval: 1s, timeout: 500ms }
networks:
  a: { cidr: 127.0.0.0/24, probe: { name: pa, address: 127.0.0.5 } }
  b: { cidr: 127.0.1.0/24, probe: { name: pb, address: 127.0.1.5 } }
  c: { cidr: 127.0.2.0/24, probe: { name: pc, address: 127.0.2.5 } }
flows:
  - { name: a-reaches-b, from: a, to: b, ports: [%d/tcp], expect: allow }
  - { name: a-blocked-from-b, from: a, to: b, ports: [%d/tcp], expect: deny }
`, allowP, denyP)))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	toks, err := tokens.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cert, err := pki.LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := &controller.Server{Policy: pol, Tokens: toks, Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	srv := httptest.NewUnstartedServer(c.Handler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return env{srv: srv, fp: pki.Fingerprint(cert), toks: toks, st: st, allowP: allowP, denyP: denyP}
}

func (e env) client(t *testing.T) *http.Client {
	c, err := pki.PinnedClient(e.fp, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e env) do(t *testing.T, method, path, token string, body any) *http.Response {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.client(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestAuth(t *testing.T) {
	e := setup(t)
	if r := e.do(t, "GET", api.JobsPath, "", nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: %s", r.Status)
	}
	if r := e.do(t, "GET", api.JobsPath, "sgw_nope", nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad token: %s", r.Status)
	}
	ghost, _ := e.toks.Add("not-in-policy")
	if r := e.do(t, "GET", api.JobsPath, ghost, nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("probe outside policy: %s", r.Status)
	}

	tok, _ := e.toks.Add("pa")
	r := e.do(t, "GET", api.JobsPath, tok, nil)
	var job api.Job
	if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
		t.Fatal(err)
	}
	if job.Network != "a" || len(job.Checks) != 2 || job.IntervalSec != 1 {
		t.Errorf("job = %+v", job)
	}

	// A probe cannot report results for checks it was not given.
	pcTok, _ := e.toks.Add("pc")
	rep := api.Report{Results: []api.Result{{CheckID: job.Checks[0].ID(), Outcome: "open", Pass: true}}}
	if r := e.do(t, "POST", api.ResultsPath, pcTok, rep); r.StatusCode != http.StatusNoContent {
		t.Fatalf("report: %s", r.Status)
	}
	if st, _ := e.st.Status(context.Background(), time.Now(), time.Hour); st.Total != 0 {
		t.Errorf("foreign result was stored: %+v", st)
	}
}

func TestProbesEndToEnd(t *testing.T) {
	e := setup(t)
	tokA, _ := e.toks.Add("pa")
	tokB, _ := e.toks.Add("pb")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	start := func(tok, bind string) chan error {
		done := make(chan error, 1)
		go func() {
			done <- agent.Run(ctx, agent.Config{
				Controller: e.srv.URL, Fingerprint: e.fp, Token: tok, Bind: bind,
				Log: log, RetryAfter: 200 * time.Millisecond,
			})
		}()
		return done
	}
	doneB := start(tokB, "127.0.1.5")
	doneA := start(tokA, "127.0.0.5")

	// On loopback nothing filters traffic: the allow flow must pass and the
	// deny flow must be caught as failing once probe b's responder is up.
	deadline := time.Now().Add(15 * time.Second)
	for {
		st, err := e.st.Status(ctx, time.Now(), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		pass := map[string]bool{}
		for _, c := range st.Checks {
			pass[c.Flow] = c.Pass
		}
		if st.Total == 2 && pass["a-reaches-b"] && !pass["a-blocked-from-b"] {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status never converged: %+v", st)
		}
		time.Sleep(200 * time.Millisecond)
	}
	cancel()
	for _, d := range []chan error{doneA, doneB} {
		if err := <-d; err != nil {
			t.Errorf("agent returned %v", err)
		}
	}
}
