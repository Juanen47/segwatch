// Package export renders the controller's status for monitoring systems:
// Prometheus (text exposition format) and Checkmk (local check output).
package export

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Juanen47/segwatch/internal/api"
)

// Labels splits a check ID ("flow:from->to:port") into its parts.
func Labels(id string) (flow, from, to, port string) {
	rest, port, ok := cut(id, ":", true)
	if !ok {
		return id, "", "", ""
	}
	path, to, ok := cut(rest, "->", true)
	if !ok {
		return rest, "", "", port
	}
	flow, from, _ = cut(path, ":", true)
	return flow, from, to, port
}

func cut(s, sep string, last bool) (before, after string, ok bool) {
	i := strings.Index(s, sep)
	if last {
		i = strings.LastIndex(s, sep)
	}
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}

func stale(c api.CheckState, st api.Status, after time.Duration) bool {
	return st.Generated.Sub(c.Seen) > after
}

// Prometheus writes st in the Prometheus text format. Use it from the
// controller's --metrics listener or through the node_exporter textfile
// collector.
func Prometheus(w io.Writer, st api.Status, staleAfter time.Duration) error {
	var b strings.Builder
	gauge := func(name, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	}
	gauge("segwatch_checks", "Checks the controller knows about.")
	fmt.Fprintf(&b, "segwatch_checks %d\n", st.Total)
	gauge("segwatch_checks_failing", "Checks whose latest result does not match the policy.")
	fmt.Fprintf(&b, "segwatch_checks_failing %d\n", st.Failing)
	gauge("segwatch_checks_stale", "Checks with no recent result (their probe stopped reporting).")
	fmt.Fprintf(&b, "segwatch_checks_stale %d\n", st.Stale)

	type series struct {
		name, help string
		val        func(api.CheckState) float64
	}
	per := []series{
		{"segwatch_check_pass", "1 when the latest result matches the policy, 0 when it does not.",
			func(c api.CheckState) float64 { return b2f(c.Pass) }},
		{"segwatch_check_stale", "1 when the check has no recent result.",
			func(c api.CheckState) float64 { return b2f(stale(c, st, staleAfter)) }},
		{"segwatch_check_last_seen_timestamp_seconds", "When the latest result arrived.",
			func(c api.CheckState) float64 { return float64(c.Seen.Unix()) }},
		{"segwatch_check_since_timestamp_seconds", "Since when the check has been passing or failing.",
			func(c api.CheckState) float64 { return float64(c.Since.Unix()) }},
	}
	checks := append([]api.CheckState(nil), st.Checks...)
	sort.Slice(checks, func(i, j int) bool { return checks[i].CheckID < checks[j].CheckID })
	for _, s := range per {
		gauge(s.name, s.help)
		for _, c := range checks {
			flow, from, to, port := Labels(c.CheckID)
			fmt.Fprintf(&b, "%s{flow=%q,from=%q,to=%q,port=%q,expect=%q,observed=%q,probe=%q} %g\n",
				s.name, esc(flow), esc(from), esc(to), esc(port), esc(c.Expect), esc(c.Outcome), esc(c.Probe), s.val(c))
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// esc prepares a label value. %q then adds the quotes and escapes backslash,
// quote and newline the way the exposition format expects; this drops any
// other control characters, which %q would write as \t or \x.. sequences.
func esc(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func b2f(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

// Checkmk states.
const (
	ok   = 0
	warn = 1
	crit = 2
)

// Checkmk writes one Checkmk local check service per flow plus a summary
// service. Install it as a local check on the controller host.
func Checkmk(w io.Writer, st api.Status, staleAfter time.Duration) error {
	type flowState struct {
		checks, failing, stale int
		problems               []string
	}
	flows := map[string]*flowState{}
	for _, c := range st.Checks {
		flow, from, to, port := Labels(c.CheckID)
		f := flows[flow]
		if f == nil {
			f = &flowState{}
			flows[flow] = f
		}
		f.checks++
		switch {
		case !c.Pass:
			f.failing++
			f.problems = append(f.problems, fmt.Sprintf("%s->%s %s observed %s, expected %s", from, to, port, c.Outcome, c.Expect))
		case stale(c, st, staleAfter):
			f.stale++
			f.problems = append(f.problems, fmt.Sprintf("%s->%s %s: no result since %s", from, to, port, c.Seen.UTC().Format(time.RFC3339)))
		}
	}
	names := make([]string, 0, len(flows))
	for n := range flows {
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	line := func(state int, service, metrics, text string) {
		// Checkmk local check: <state> "<service>" <metrics> <text>
		service = strings.NewReplacer(`"`, "'", "\n", " ").Replace(service)
		text = strings.ReplaceAll(text, "\n", " ")
		fmt.Fprintf(&b, "%d \"%s\" %s %s\n", state, service, metrics, text)
	}
	for _, n := range names {
		f := flows[n]
		state, text := ok, fmt.Sprintf("all %d checks match the policy", f.checks)
		if f.failing > 0 || f.stale > 0 {
			state = warn
			if f.failing > 0 {
				state = crit
			}
			text = fmt.Sprintf("%d of %d checks: %s", f.failing+f.stale, f.checks, strings.Join(f.problems, "; "))
		}
		line(state, "segwatch "+n, fmt.Sprintf("failing=%d|stale=%d|checks=%d", f.failing, f.stale, f.checks), text)
	}
	state, text := ok, fmt.Sprintf("%d checks in %d flows match the policy", st.Total, len(names))
	switch {
	case st.Total == 0:
		state, text = warn, "no results yet"
	case st.Failing > 0:
		state, text = crit, fmt.Sprintf("%d of %d checks do not match the policy", st.Failing, st.Total)
	case st.Stale > 0:
		state, text = warn, fmt.Sprintf("%d of %d checks have no recent result", st.Stale, st.Total)
	}
	line(state, "segwatch summary", fmt.Sprintf("failing=%d|stale=%d|checks=%d", st.Failing, st.Stale, st.Total), text)
	_, err := io.WriteString(w, b.String())
	return err
}
