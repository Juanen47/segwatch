package report

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Juanen47/segwatch/internal/api"
	"github.com/Juanen47/segwatch/internal/policy"
	"github.com/Juanen47/segwatch/internal/store"
)

const pol = `
version: 1
defaults: { interval: 1m, timeout: 1s }
networks:
  mgmt:    { cidr: 10.0.1.0/24, probe: { name: p-mgmt,    address: 10.0.1.5 } }
  servers: { cidr: 10.0.2.0/24, probe: { name: p-servers, address: 10.0.2.5 } }
  guests:  { cidr: 10.0.3.0/24, probe: { name: p-guests,  address: 10.0.3.5 } }
targets:
  web: { address: 10.0.2.20, network: servers }
flows:
  - { name: mgmt-ssh, from: mgmt, to: servers, ports: [22/tcp], expect: allow }
  - { name: "guests-<b>isolated</b>", from: guests, to: servers, ports: [22/tcp, icmp], expect: deny }
  - { name: guests-web, from: guests, to: web, ports: [80/tcp], expect: deny }
`

func TestBuildAndRender(t *testing.T) {
	ctx := context.Background()
	p, err := policy.Parse([]byte(pol))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	byID := map[string]policy.Check{}
	for _, n := range p.NetworkNames() {
		cs, _ := p.ChecksFrom(n)
		for _, c := range cs {
			byID[c.ID()] = c
		}
	}
	id := func(flow, port string) string {
		for k, c := range byID {
			if c.Flow == flow && c.Port.String() == port {
				return k
			}
		}
		t.Fatalf("no check %s %s", flow, port)
		return ""
	}
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	rec := func(at time.Time, probe string, rs ...api.Result) {
		t.Helper()
		if _, err := st.Record(ctx, probe, at, byID, rs); err != nil {
			t.Fatal(err)
		}
	}
	guestSSH := id("guests-<b>isolated</b>", "22/tcp")
	guestICMP := id("guests-<b>isolated</b>", "icmp")
	rec(now.Add(-3*time.Minute), "p-guests",
		api.Result{CheckID: guestSSH, Outcome: "blocked", Pass: true},
		api.Result{CheckID: guestICMP, Outcome: "blocked", Pass: true})
	rec(now.Add(-time.Minute), "p-guests",
		api.Result{CheckID: guestSSH, Outcome: "open", Pass: false},
		api.Result{CheckID: guestICMP, Outcome: "blocked", Pass: true})
	// mgmt reported long ago: stale. guests-web never ran: pending.
	rec(now.Add(-time.Hour), "p-mgmt", api.Result{CheckID: id("mgmt-ssh", "22/tcp"), Outcome: "open", Pass: true})
	// a check that has since been removed from the policy
	old := policy.Check{Flow: "old", From: "mgmt", To: "servers", Port: policy.Port{Number: 23, Proto: policy.TCP}}
	if _, err := st.Record(ctx, "p-mgmt", now.Add(-time.Hour), map[string]policy.Check{old.ID(): old},
		[]api.Result{{CheckID: old.ID(), Outcome: "blocked", Pass: true}}); err != nil {
		t.Fatal(err)
	}

	r, err := Build(ctx, p, st, Options{Now: now, Period: 24 * time.Hour, StaleAfter: 3 * time.Minute,
		Version: "test", PolicyRaw: []byte(pol)})
	if err != nil {
		t.Fatal(err)
	}
	if r.Total != 4 || r.Failing != 1 || r.Passing != 1 || r.Stale != 1 || r.Pending != 1 {
		t.Errorf("totals: %+v", r)
	}
	if r.Rows[0].ID != guestSSH || r.Rows[0].Uptime() != "50.0 %" {
		t.Errorf("first row should be the failure with 50%% uptime: %+v", r.Rows[0])
	}
	if strings.Join(r.Sources, ",") != "guests,mgmt" || strings.Join(r.Dests, ",") != "servers,web" {
		t.Errorf("axes: %v x %v", r.Sources, r.Dests)
	}
	if c := r.Matrix[0][0]; c.Status != Fail || len(c.Rows) != 2 {
		t.Errorf("guests->servers cell: %+v", c)
	}
	if c := r.Matrix[1][1]; len(c.Rows) != 0 {
		t.Errorf("mgmt->web should be untested: %+v", c)
	}
	if len(r.Changes) != 1 || r.Changes[0].Pass || r.Changes[0].Port != "22/tcp" {
		t.Errorf("changes: %+v", r.Changes)
	}
	if len(r.Retired) != 1 || r.Retired[0].Flow != "old" {
		t.Errorf("retired: %+v", r.Retired)
	}

	var b bytes.Buffer
	if err := r.Render(&b); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"1 of 4 checks do not match the policy", "not tested", "50.0 %",
		"guests-&lt;b&gt;isolated&lt;/b&gt;", "default-src &#39;none&#39;"} {
		if !strings.Contains(html, want) && !strings.Contains(html, strings.ReplaceAll(want, "&#39;", "'")) {
			t.Errorf("report misses %q", want)
		}
	}
	if strings.Contains(html, "<b>isolated") {
		t.Error("flow name was not escaped")
	}
	if strings.Contains(html, "<script") || strings.Contains(html, "http://") || strings.Contains(html, "https://") {
		t.Error("report must be self-contained")
	}
}
