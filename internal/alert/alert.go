// Package alert sends notifications when checks change state.
//
// ntfy and webhook channels get one message per batch of state changes.
// healthchecks gets a heartbeat with the overall result: a success ping when
// every check passes and none is stale, a /fail ping otherwise. If the
// controller stops, the pings stop and Healthchecks raises the alarm itself.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Juanen47/segwatch/internal/api"
	"github.com/Juanen47/segwatch/internal/policy"
	"github.com/Juanen47/segwatch/internal/store"
)

// Event is one check whose state changed, as sent to a webhook.
type Event struct {
	CheckID  string    `json:"check_id"`
	Flow     string    `json:"flow"`
	From     string    `json:"from"`
	To       string    `json:"to"`
	Port     string    `json:"port"`
	Expect   string    `json:"expect"`
	Outcome  string    `json:"outcome"`
	Pass     bool      `json:"pass"`
	Detail   string    `json:"detail,omitempty"`
	Previous string    `json:"previous_outcome,omitempty"`
	Kind     string    `json:"kind"` // failing, recovered, stale, reporting
	At       time.Time `json:"at"`
}

// Payload is the JSON body posted to a webhook.
type Payload struct {
	Source string  `json:"source"` // always "segwatch"
	Events []Event `json:"events"`
}

// Dispatcher fans state changes out to the alert channels in the policy.
// Each channel has its own queue, worked in order in the background with a
// timeout and a few retries, so a slow channel never holds up a probe's
// report and a recovery never arrives before the failure it follows.
type Dispatcher struct {
	Alerts []policy.Alert
	Client *http.Client
	Log    *slog.Logger
	// StaleAfter is how long a check may go without a result before its
	// probe is reported as silent. It must match the one used for Status.
	StaleAfter time.Duration

	mu         sync.Mutex
	stale      map[string]bool
	quietUntil time.Time // see Quiet
	quietDone  bool
	wg         sync.WaitGroup
	sleep      func(time.Duration) // for tests
	failed     atomic.Int64
	once       sync.Once
	queues     []chan func()
}

// New returns a dispatcher for the policy's alert channels.
func New(alerts []policy.Alert, staleAfter time.Duration, log *slog.Logger) *Dispatcher {
	return &Dispatcher{
		Alerts:     alerts,
		Client:     &http.Client{Timeout: 10 * time.Second},
		Log:        log,
		StaleAfter: staleAfter,
	}
}

const queueSize = 100

// enqueue runs job on channel i's worker, in order.
func (d *Dispatcher) enqueue(i int, job func()) {
	d.once.Do(func() {
		d.queues = make([]chan func(), len(d.Alerts))
		for n := range d.queues {
			q := make(chan func(), queueSize)
			d.queues[n] = q
			go func() {
				for f := range q {
					f()
				}
			}()
		}
	})
	d.wg.Add(1)
	select {
	case d.queues[i] <- func() { defer d.wg.Done(); job() }:
	default:
		d.wg.Done()
		d.failed.Add(1)
		d.Log.Error("alert dropped: queue full", "alert", i+1, "type", d.Alerts[i].Type)
	}
}

// FromChanges turns store changes into events.
func FromChanges(cs []store.Change) []Event {
	out := make([]Event, 0, len(cs))
	for _, c := range cs {
		e := Event{
			CheckID: c.Current.CheckID, Flow: c.Current.Flow, From: c.Check.From, To: c.Check.To,
			Port: c.Current.Port, Expect: c.Current.Expect, Outcome: c.Current.Outcome,
			Pass: c.Current.Pass, Detail: c.Current.Detail, At: c.Current.Seen, Kind: "failing",
		}
		if c.Current.Pass {
			e.Kind = "recovered"
		}
		if c.Previous != nil {
			e.Previous = c.Previous.Outcome
		}
		out = append(out, e)
	}
	return out
}

// Notify sends events to every ntfy and webhook channel.
// Quiet holds back state-change alerts until t. Use it at controller start:
// probes come up one by one, and a check against a probe whose responder is
// not listening yet fails for a moment. The first heartbeat at or after t
// sends whatever is still failing, so a real problem is not lost.
func (d *Dispatcher) Quiet(t time.Time) {
	d.mu.Lock()
	d.quietUntil, d.quietDone = t, false
	d.mu.Unlock()
}

func (d *Dispatcher) Notify(events []Event) {
	if len(events) == 0 {
		return
	}
	d.mu.Lock()
	quiet := time.Now().Before(d.quietUntil)
	d.mu.Unlock()
	if quiet {
		d.Log.Debug("alerts held during startup", "events", len(events))
		return
	}
	d.notify(events)
}

func (d *Dispatcher) notify(events []Event) {
	if len(events) == 0 {
		return
	}
	for i, a := range d.Alerts {
		if a.Type != "ntfy" && a.Type != "webhook" {
			continue
		}
		d.enqueue(i, func() {
			d.retry(i, a, func(ctx context.Context) error { return d.send(ctx, a, events) })
		})
	}
}

// Heartbeat reports the overall status: it pings healthchecks channels and
// notifies ntfy and webhook channels about checks that went stale (their
// probe stopped reporting) or came back.
func (d *Dispatcher) Heartbeat(st api.Status) {
	d.mu.Lock()
	if d.stale == nil {
		d.stale = map[string]bool{}
	}
	var events []Event
	if !d.quietUntil.IsZero() && !d.quietDone && !st.Generated.Before(d.quietUntil) {
		// End of the startup quiet period: report what is still failing.
		d.quietDone = true
		for _, c := range st.Checks {
			if !c.Pass {
				events = append(events, stateEvent(c, "failing", c.Seen))
			}
		}
	}
	now := map[string]bool{}
	for _, c := range st.Checks {
		if st.Generated.Sub(c.Seen) > d.StaleAfter {
			now[c.CheckID] = true
			if !d.stale[c.CheckID] {
				events = append(events, stateEvent(c, "stale", st.Generated))
			}
		} else if d.stale[c.CheckID] {
			events = append(events, stateEvent(c, "reporting", st.Generated))
		}
	}
	d.stale = now
	d.mu.Unlock()
	d.notify(events)

	for i, a := range d.Alerts {
		if a.Type != "healthchecks" {
			continue
		}
		d.enqueue(i, func() {
			d.retry(i, a, func(ctx context.Context) error { return d.ping(ctx, a, st) })
		})
	}
}

func stateEvent(c api.CheckState, kind string, at time.Time) Event {
	return Event{
		CheckID: c.CheckID, Flow: c.Flow, From: c.From, To: c.To, Port: c.Port, Expect: c.Expect,
		Outcome: c.Outcome, Pass: c.Pass, Detail: c.Detail, Kind: kind, At: at,
	}
}

// Wait blocks until every pending send has finished.
func (d *Dispatcher) Wait() { d.wg.Wait() }

// Failed counts sends that were given up after their retries.
func (d *Dispatcher) Failed() int { return int(d.failed.Load()) }

// Test sends a sample failing event to every ntfy and webhook channel and a
// heartbeat with the given status to every healthchecks channel, then waits.
func (d *Dispatcher) Test(st api.Status) int {
	d.Notify([]Event{{
		CheckID: "segwatch-test", Flow: "segwatch-test", Port: "0/tcp", Expect: "deny",
		Outcome: "open", Detail: "test alert, no action needed", Kind: "failing", At: time.Now().UTC(),
	}})
	d.Heartbeat(st)
	d.Wait()
	return d.Failed()
}

func (d *Dispatcher) retry(i int, a policy.Alert, f func(context.Context) error) {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			sleep := time.Sleep
			if d.sleep != nil {
				sleep = d.sleep
			}
			sleep(time.Duration(attempt*attempt) * 2 * time.Second)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err = f(ctx)
		cancel()
		if err == nil {
			return
		}
	}
	d.failed.Add(1)
	// The URL is not logged: ntfy topics and Healthchecks UUIDs are secrets.
	d.Log.Error("alert not delivered", "alert", i+1, "type", a.Type, "err", err)
}

func (d *Dispatcher) send(ctx context.Context, a policy.Alert, events []Event) error {
	var body []byte
	hdr := http.Header{}
	switch a.Type {
	case "ntfy":
		title, text, failing := Summary(events)
		body = []byte(text)
		hdr.Set("Title", title)
		hdr.Set("Content-Type", "text/plain; charset=utf-8")
		if failing {
			hdr.Set("Priority", "high")
			hdr.Set("Tags", "rotating_light")
		} else {
			hdr.Set("Tags", "white_check_mark")
		}
	case "webhook":
		var err error
		if body, err = json.Marshal(Payload{Source: "segwatch", Events: events}); err != nil {
			return err
		}
		hdr.Set("Content-Type", "application/json")
	}
	if a.TokenFile != "" {
		tok, err := os.ReadFile(a.TokenFile)
		if err != nil {
			return fmt.Errorf("read token_file: %w", err)
		}
		hdr.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	}
	return d.post(ctx, a.URL, hdr, body)
}

func (d *Dispatcher) ping(ctx context.Context, a policy.Alert, st api.Status) error {
	url := strings.TrimRight(a.URL, "/")
	text := fmt.Sprintf("%d checks, %d failing, %d stale\n", st.Total, st.Failing, st.Stale)
	if st.Failing > 0 || st.Stale > 0 {
		url += "/fail"
		for _, c := range st.Checks {
			if !c.Pass {
				text += fmt.Sprintf("FAIL %s %s: expected %s, observed %s\n", c.Flow, c.Port, c.Expect, c.Outcome)
			}
		}
	}
	return d.post(ctx, url, http.Header{"Content-Type": {"text/plain; charset=utf-8"}}, []byte(text))
}

func (d *Dispatcher) post(ctx context.Context, url string, hdr http.Header, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", "segwatch")
	resp, err := d.Client.Do(req)
	if err != nil {
		// Strip the URL from the error: it may hold a secret.
		return fmt.Errorf("%s request failed", req.Method)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// Summary renders events as a short title and a text body for chat-style
// channels. failing is true when at least one event is bad news.
func Summary(events []Event) (title, text string, failing bool) {
	sorted := append([]Event(nil), events...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].CheckID < sorted[j].CheckID })
	var bad, good int
	var b strings.Builder
	for _, e := range sorted {
		switch e.Kind {
		case "failing":
			bad++
			fmt.Fprintf(&b, "FAIL %s %s: expected %s, observed %s", e.Flow, e.Port, e.Expect, e.Outcome)
		case "stale":
			bad++
			fmt.Fprintf(&b, "STALE %s %s: no result since %s", e.Flow, e.Port, e.At.Format(time.RFC3339))
		case "recovered":
			good++
			fmt.Fprintf(&b, "OK %s %s: back to %s", e.Flow, e.Port, e.Outcome)
		default:
			good++
			fmt.Fprintf(&b, "OK %s %s: reporting again", e.Flow, e.Port)
		}
		if e.Detail != "" && e.Kind == "failing" {
			fmt.Fprintf(&b, " (%s)", e.Detail)
		}
		b.WriteByte('\n')
	}
	switch {
	case bad > 0 && good > 0:
		title = fmt.Sprintf("segwatch: %d failing, %d recovered", bad, good)
	case bad > 0:
		title = fmt.Sprintf("segwatch: %d check(s) failing", bad)
	default:
		title = fmt.Sprintf("segwatch: %d check(s) recovered", good)
	}
	return title, b.String(), bad > 0
}
