package alert

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Juanen47/segwatch/internal/api"
	"github.com/Juanen47/segwatch/internal/policy"
	"github.com/Juanen47/segwatch/internal/store"
)

type hit struct {
	Path   string
	Header http.Header
	Body   string
}

type recorder struct {
	mu     sync.Mutex
	hits   []hit
	status int
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.hits = append(r.hits, hit{req.URL.Path, req.Header.Clone(), string(b)})
	st := r.status
	r.mu.Unlock()
	if st == 0 {
		st = http.StatusOK
	}
	w.WriteHeader(st)
}

func (r *recorder) all() []hit {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]hit(nil), r.hits...)
}

func newDispatcher(t *testing.T, alerts ...policy.Alert) *Dispatcher {
	t.Helper()
	d := New(alerts, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.sleep = func(time.Duration) {}
	return d
}

func change(pass bool, prev *api.CheckState) store.Change {
	cur := api.CheckState{
		CheckID: "guests-isolated:guests->servers:22/tcp", Flow: "guests-isolated", Port: "22/tcp",
		Expect: "deny", Outcome: "open", Pass: pass, Seen: time.Unix(1700000000, 0).UTC(),
	}
	if pass {
		cur.Outcome = "blocked"
	}
	return store.Change{Check: policy.Check{From: "guests", To: "servers"}, Previous: prev, Current: cur}
}

func TestNtfy(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	tokFile := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(tokFile, []byte("tk_secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := newDispatcher(t, policy.Alert{Type: "ntfy", URL: srv.URL + "/topic", TokenFile: tokFile})

	d.Notify(FromChanges([]store.Change{change(false, &api.CheckState{Outcome: "blocked", Pass: true})}))
	d.Wait()
	hits := rec.all()
	if len(hits) != 1 {
		t.Fatalf("got %d requests, want 1", len(hits))
	}
	h := hits[0]
	if h.Path != "/topic" || h.Header.Get("Priority") != "high" || h.Header.Get("Authorization") != "Bearer tk_secret" {
		t.Errorf("unexpected request: %+v", h)
	}
	if !strings.Contains(h.Header.Get("Title"), "1 check(s) failing") ||
		!strings.Contains(h.Body, "FAIL guests-isolated 22/tcp: expected deny, observed open") {
		t.Errorf("unexpected message: title %q body %q", h.Header.Get("Title"), h.Body)
	}
}

func TestWebhook(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	d := newDispatcher(t, policy.Alert{Type: "webhook", URL: srv.URL + "/hook"})

	d.Notify(FromChanges([]store.Change{change(true, &api.CheckState{Outcome: "open"})}))
	d.Wait()
	hits := rec.all()
	if len(hits) != 1 {
		t.Fatalf("got %d requests, want 1", len(hits))
	}
	var p Payload
	if err := json.Unmarshal([]byte(hits[0].Body), &p); err != nil {
		t.Fatal(err)
	}
	if p.Source != "segwatch" || len(p.Events) != 1 {
		t.Fatalf("payload %+v", p)
	}
	e := p.Events[0]
	if e.Kind != "recovered" || e.Previous != "open" || e.Outcome != "blocked" || e.From != "guests" || e.To != "servers" {
		t.Errorf("event %+v", e)
	}
	if hits[0].Header.Get("Authorization") != "" {
		t.Error("no token_file, but an Authorization header was sent")
	}
}

func TestHealthchecks(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	d := newDispatcher(t, policy.Alert{Type: "healthchecks", URL: srv.URL + "/ping/uuid/"})
	now := time.Now().UTC()

	d.Heartbeat(api.Status{Generated: now, Total: 1, Checks: []api.CheckState{{CheckID: "a", Pass: true, Seen: now}}})
	d.Wait()
	d.Heartbeat(api.Status{Generated: now, Total: 1, Failing: 1, Checks: []api.CheckState{
		{CheckID: "a", Flow: "f", Port: "22/tcp", Expect: "deny", Outcome: "open", Seen: now}}})
	d.Wait()

	hits := rec.all()
	if len(hits) != 2 || hits[0].Path != "/ping/uuid" || hits[1].Path != "/ping/uuid/fail" {
		t.Fatalf("got %+v", hits)
	}
	if !strings.Contains(hits[1].Body, "FAIL f 22/tcp: expected deny, observed open") {
		t.Errorf("fail body %q", hits[1].Body)
	}
}

func TestStaleAndBack(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	d := newDispatcher(t, policy.Alert{Type: "webhook", URL: srv.URL})
	now := time.Now().UTC()
	st := func(seen time.Time) api.Status {
		return api.Status{Generated: now, Checks: []api.CheckState{{CheckID: "a", Pass: true, Seen: seen}}}
	}

	d.Heartbeat(st(now.Add(-2 * time.Hour))) // stale: one alert
	d.Heartbeat(st(now.Add(-3 * time.Hour))) // still stale: nothing new
	d.Heartbeat(st(now))                     // back
	d.Wait()

	var kinds []string
	for _, h := range rec.all() {
		var p Payload
		_ = json.Unmarshal([]byte(h.Body), &p)
		for _, e := range p.Events {
			kinds = append(kinds, e.Kind)
		}
	}
	if strings.Join(kinds, ",") != "stale,reporting" {
		t.Errorf("events %v, want stale then reporting", kinds)
	}
}

func TestRetryThenGiveUpWithoutLeakingURL(t *testing.T) {
	rec := &recorder{status: http.StatusInternalServerError}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	var logs strings.Builder
	d := New([]policy.Alert{{Type: "ntfy", URL: srv.URL + "/secret-topic"}}, time.Hour,
		slog.New(slog.NewTextHandler(&logs, nil)))
	d.sleep = func(time.Duration) {}

	if failed := d.Test(api.Status{Generated: time.Now()}); failed != 1 {
		t.Fatalf("failed = %d, want 1", failed)
	}
	if n := len(rec.all()); n != 3 {
		t.Errorf("%d attempts, want 3", n)
	}
	if strings.Contains(logs.String(), "secret-topic") {
		t.Errorf("log leaks the URL: %s", logs.String())
	}

	// A connection error must not leak it either.
	srv.Close()
	logs.Reset()
	d.Test(api.Status{Generated: time.Now()})
	if strings.Contains(logs.String(), "secret-topic") {
		t.Errorf("log leaks the URL: %s", logs.String())
	}
}

func TestSummaryMixed(t *testing.T) {
	title, _, failing := Summary([]Event{{Kind: "failing"}, {Kind: "recovered"}})
	if title != "segwatch: 1 failing, 1 recovered" || !failing {
		t.Errorf("title %q failing %v", title, failing)
	}
}

func TestQuietAtStartup(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	d := newDispatcher(t, policy.Alert{Type: "webhook", URL: srv.URL})
	start := time.Now()
	d.Quiet(start.Add(time.Hour))

	// A failure and its recovery inside the quiet period: nothing is sent.
	d.Notify(FromChanges([]store.Change{change(false, nil)}))
	d.Notify(FromChanges([]store.Change{change(true, &api.CheckState{Outcome: "open"})}))
	d.Wait()
	if n := len(rec.all()); n != 0 {
		t.Fatalf("%d alerts sent during the quiet period", n)
	}

	// First heartbeat after it: what still fails is reported, once.
	st := api.Status{Generated: start.Add(time.Hour), Checks: []api.CheckState{
		{CheckID: "a", Flow: "f", Port: "22/tcp", Outcome: "open", Pass: false, Seen: start.Add(time.Hour)},
		{CheckID: "b", Pass: true, Seen: start.Add(time.Hour)},
	}}
	d.Heartbeat(st)
	d.Heartbeat(st)
	d.Wait()
	hits := rec.all()
	if len(hits) != 1 || !strings.Contains(hits[0].Body, `"check_id":"a"`) || strings.Contains(hits[0].Body, `"check_id":"b"`) {
		t.Fatalf("want one alert for the still-failing check, got %+v", hits)
	}
}
