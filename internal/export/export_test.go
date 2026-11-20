package export

import (
	"strings"
	"testing"
	"time"

	"github.com/Juanen47/segwatch/internal/api"
)

func status() api.Status {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	return api.Status{Generated: now, Total: 3, Failing: 1, Stale: 1, Checks: []api.CheckState{
		{CheckID: "guests-isolated:guests->servers:22/tcp", Probe: "p-guests", Expect: "deny", Outcome: "open",
			Pass: false, Since: now.Add(-time.Minute), Seen: now},
		{CheckID: "guests-isolated:guests->servers:icmp", Probe: "p-guests", Expect: "deny", Outcome: "blocked",
			Pass: true, Since: now.Add(-time.Hour), Seen: now},
		{CheckID: "mgmt-ssh:mgmt->servers:22/tcp", Probe: "p-mgmt", Expect: "allow", Outcome: "open",
			Pass: true, Since: now.Add(-2 * time.Hour), Seen: now.Add(-2 * time.Hour)},
	}}
}

func TestLabels(t *testing.T) {
	f, a, b, p := Labels("guests-isolated:guests->servers:22/tcp")
	if f != "guests-isolated" || a != "guests" || b != "servers" || p != "22/tcp" {
		t.Errorf("got %q %q %q %q", f, a, b, p)
	}
}

func TestPrometheus(t *testing.T) {
	var b strings.Builder
	if err := Prometheus(&b, status(), time.Hour); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"segwatch_checks_failing 1\n",
		`segwatch_check_pass{flow="guests-isolated",from="guests",to="servers",port="22/tcp",expect="deny",observed="open",probe="p-guests"} 0`,
		`segwatch_check_stale{flow="mgmt-ssh",from="mgmt",to="servers",port="22/tcp",expect="allow",observed="open",probe="p-mgmt"} 1`,
		"# TYPE segwatch_check_last_seen_timestamp_seconds gauge",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	// Every sample line is "name{labels} value" or "name value".
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.HasPrefix(l, "#") && strings.Count(l, " ") != 1 && !strings.Contains(l, "} ") {
			t.Errorf("malformed line %q", l)
		}
	}
}

func TestPrometheusEscapes(t *testing.T) {
	st := api.Status{Generated: time.Now(), Checks: []api.CheckState{{CheckID: "a:x->y:1/tcp", Probe: "p\"\\\n\tq"}}}
	var b strings.Builder
	_ = Prometheus(&b, st, time.Hour)
	if !strings.Contains(b.String(), `probe="p\"\\\nq"`) {
		t.Errorf("bad escaping:\n%s", b.String())
	}
}

func TestCheckmk(t *testing.T) {
	var b strings.Builder
	if err := Checkmk(&b, status(), time.Hour); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 2 flows + summary, got:\n%s", b.String())
	}
	if !strings.HasPrefix(lines[0], `2 "segwatch guests-isolated" failing=1|stale=0|checks=2 1 of 2 checks: guests->servers 22/tcp observed open, expected deny`) {
		t.Errorf("flow line: %s", lines[0])
	}
	if !strings.HasPrefix(lines[1], `1 "segwatch mgmt-ssh" failing=0|stale=1|checks=1`) {
		t.Errorf("stale line: %s", lines[1])
	}
	if !strings.HasPrefix(lines[2], `2 "segwatch summary" failing=1|stale=1|checks=3`) {
		t.Errorf("summary: %s", lines[2])
	}

	b.Reset()
	_ = Checkmk(&b, api.Status{Generated: time.Now()}, time.Hour)
	if strings.TrimSpace(b.String()) != `1 "segwatch summary" failing=0|stale=0|checks=0 no results yet` {
		t.Errorf("empty: %q", b.String())
	}
}
