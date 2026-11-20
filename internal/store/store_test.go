package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Juanen47/segwatch/internal/api"
	"github.com/Juanen47/segwatch/internal/policy"
)

func TestRecordDetectsChanges(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	c := policy.Check{Flow: "f", From: "a", To: "b", Port: policy.Port{Number: 22, Proto: policy.TCP}, Expect: policy.Deny}
	ok := policy.Check{Flow: "g", From: "a", To: "b", Port: policy.Port{Number: 443, Proto: policy.TCP}, Expect: policy.Allow}
	checks := map[string]policy.Check{c.ID(): c, ok.ID(): ok}
	t0 := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

	report := func(at time.Time, cPass bool) []Change {
		t.Helper()
		out := "blocked"
		if !cPass {
			out = "open"
		}
		ch, err := s.Record(ctx, "p", at, checks, []api.Result{
			{CheckID: c.ID(), Outcome: out, Pass: cPass},
			{CheckID: ok.ID(), Outcome: "open", Pass: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		return ch
	}

	if ch := report(t0, true); len(ch) != 0 {
		t.Errorf("first run, all passing: want no changes, got %d", len(ch))
	}
	if ch := report(t0.Add(time.Hour), true); len(ch) != 0 {
		t.Errorf("same state: want no changes, got %d", len(ch))
	}
	ch := report(t0.Add(2*time.Hour), false)
	if len(ch) != 1 || ch[0].Current.Pass || ch[0].Previous == nil || !ch[0].Previous.Pass {
		t.Fatalf("pass -> fail: got %+v", ch)
	}
	report(t0.Add(3*time.Hour), false)

	st, err := s.Status(ctx, t0.Add(3*time.Hour), 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if st.Total != 2 || st.Failing != 1 || st.Stale != 0 {
		t.Errorf("status = %+v", st)
	}
	for _, cs := range st.Checks {
		if cs.CheckID == c.ID() && !cs.Since.Equal(t0.Add(2*time.Hour)) {
			t.Errorf("failing since = %v, want the first failing run", cs.Since)
		}
	}
	if st, _ := s.Status(ctx, t0.Add(10*time.Hour), 2*time.Hour); st.Stale != 2 {
		t.Errorf("stale = %d, want 2", st.Stale)
	}

	if ch := report(t0.Add(4*time.Hour), true); len(ch) != 1 || !ch[0].Current.Pass {
		t.Errorf("fail -> pass: got %+v", ch)
	}
	n, err := s.Prune(ctx, t0.Add(4*time.Hour), 90*time.Minute)
	if err != nil || n != 6 {
		t.Errorf("prune removed %d rows (err %v), want 6", n, err)
	}
}

func TestNewFailingCheckIsAChange(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := policy.Check{Flow: "f", Port: policy.Port{Proto: policy.ICMP}, Expect: policy.Deny}
	ch, err := s.Record(context.Background(), "p", time.Now(), map[string]policy.Check{c.ID(): c},
		[]api.Result{{CheckID: c.ID(), Outcome: "open", Pass: false}})
	if err != nil || len(ch) != 1 || ch[0].Previous != nil {
		t.Fatalf("got %+v, %v", ch, err)
	}
}
