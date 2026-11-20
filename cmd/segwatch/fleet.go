package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Juanen47/segwatch/internal/agent"
	"github.com/Juanen47/segwatch/internal/alert"
	"github.com/Juanen47/segwatch/internal/api"
	"github.com/Juanen47/segwatch/internal/controller"
	"github.com/Juanen47/segwatch/internal/export"
	"github.com/Juanen47/segwatch/internal/pki"
	"github.com/Juanen47/segwatch/internal/report"
	"github.com/Juanen47/segwatch/internal/store"
	"github.com/Juanen47/segwatch/internal/tokens"
)

const dbFile = "segwatch.db"

// parseSources parses "--source 10.0.30.5" or "--source 10.0.30.5,fd00:30::5":
// at most one address per family.
func parseSources(s string) ([]netip.Addr, error) {
	if s == "" {
		return nil, nil
	}
	var out []netip.Addr
	seen := map[bool]bool{}
	for _, part := range strings.Split(s, ",") {
		a, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("invalid source address %q", part)
		}
		a = a.Unmap()
		if seen[a.Is4()] {
			return nil, fmt.Errorf("--source takes at most one IPv4 and one IPv6 address")
		}
		seen[a.Is4()] = true
		out = append(out, a)
	}
	return out, nil
}

func newLogger(w io.Writer, debug bool) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

func cmdController(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("controller", flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", "", "data directory for certificate, tokens and history (required)")
	listen := fs.String("listen", ":8443", "address to listen on")
	keep := fs.Duration("keep", 90*24*time.Hour, "how long to keep raw results")
	debug := fs.Bool("debug", false, "verbose logging")
	stale := fs.Duration("stale", 0, "alert when a check has no result for this long (default: 3 policy intervals)")
	metrics := fs.String("metrics", "", "serve Prometheus metrics over plain HTTP on this address, e.g. 127.0.0.1:9469 (default: off)")
	pol, ok := loadPolicy(fs, args, stderr)
	if !ok {
		return 2
	}
	if *data == "" {
		fmt.Fprintln(stderr, "--data is required")
		return 2
	}
	log := newLogger(stderr, *debug)
	interval := pol.Defaults.Interval.Std()
	if *stale <= 0 {
		*stale = 3 * interval
	}

	cert, err := pki.LoadOrCreate(*data)
	if err != nil {
		log.Error("certificate", "err", err)
		return 2
	}
	toks, err := tokens.Open(*data)
	if err != nil {
		log.Error("tokens", "err", err)
		return 2
	}
	st, err := store.Open(filepath.Join(*data, dbFile))
	if err != nil {
		log.Error("database", "err", err)
		return 2
	}
	defer st.Close()

	alerts := alert.New(pol.Alerts, *stale, log)
	srv := &controller.Server{Policy: pol, Tokens: toks, Store: st, Log: log,
		OnChange: func(cs []store.Change) { alerts.Notify(alert.FromChanges(cs)) }, SilentAfter: *stale}
	srv.Start()
	hs := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(shut)
	}()
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			if n, err := st.Prune(ctx, time.Now(), *keep); err == nil && n > 0 {
				log.Info("pruned old results", "rows", n)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	if *metrics != "" {
		ms := &http.Server{Addr: *metrics, Handler: metricsHandler(st, *stale, log), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			<-ctx.Done()
			_ = ms.Close()
		}()
		go func() {
			if err := ms.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics listener", "err", err)
			}
		}()
		log.Info("metrics listening", "addr", *metrics, "path", "/metrics")
	}
	if len(pol.Alerts) > 0 {
		// Hold alerts for the first heartbeat period while probes come up.
		alerts.Quiet(time.Now().Add(heartbeatEvery(interval)))
		go heartbeat(ctx, st, alerts, interval, *stale, log)
	}

	fmt.Fprintf(stdout, "controller fingerprint: %s\n", pki.Fingerprint(cert))
	log.Info("controller listening", "addr", *listen, "probes_with_token", len(toks.Probes()))
	if err := hs.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("listen", "err", err)
		return 2
	}
	alerts.Wait()
	return 0
}

// heartbeat sends the overall status to the alert channels once per policy
// interval (at least every 5 minutes, so a silent probe is noticed soon).
// The first one waits a full period, so probes have time to report.
func heartbeatEvery(interval time.Duration) time.Duration { return min(interval, 5*time.Minute) }

func heartbeat(ctx context.Context, st *store.Store, d *alert.Dispatcher, interval, stale time.Duration, log *slog.Logger) {
	t := time.NewTicker(heartbeatEvery(interval))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		status, err := st.Status(ctx, time.Now().UTC(), stale)
		if err != nil {
			log.Error("status for heartbeat", "err", err)
			continue
		}
		d.Heartbeat(status)
	}
}

func cmdToken(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: segwatch token add|list|revoke ...")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("token "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", "", "controller data directory (required)")
	policyPath := fs.String("p", "", "policy file (required for add)")
	fs.StringVar(policyPath, "policy", "", "policy file (required for add)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *data == "" {
		fmt.Fprintln(stderr, "--data is required")
		return 2
	}
	toks, err := tokens.Open(*data)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	switch sub {
	case "list":
		for _, p := range toks.Probes() {
			fmt.Fprintln(stdout, p)
		}
		return 0
	case "add", "revoke":
		if fs.NArg() != 1 {
			fmt.Fprintf(stderr, "usage: segwatch token %s --data <dir> <probe-name>\n", sub)
			return 2
		}
		probe := fs.Arg(0)
		if sub == "revoke" {
			if err := toks.Revoke(probe); err != nil {
				fmt.Fprintln(stderr, err)
				return 2
			}
			fmt.Fprintf(stdout, "token for %s revoked (restart the controller to apply)\n", probe)
			return 0
		}
		if *policyPath == "" {
			fmt.Fprintln(stderr, "-p policy.yaml is required so the probe name can be checked")
			return 2
		}
		pf := flag.NewFlagSet("", flag.ContinueOnError)
		pol, ok := loadPolicy(pf, []string{"-p", *policyPath}, stderr)
		if !ok {
			return 2
		}
		if _, ok := pol.NetworkOfProbe(probe); !ok {
			fmt.Fprintf(stderr, "probe %q is not declared in the policy\n", probe)
			return 2
		}
		tok, err := toks.Add(probe)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		fmt.Fprintf(stdout, "%s\n", tok)
		fmt.Fprintln(stderr, "Store this token in a file readable only by the probe user (chmod 600). It is not shown again.")
		fmt.Fprintln(stderr, "Restart the controller to load it.")
		return 0
	}
	fmt.Fprintf(stderr, "unknown token command %q\n", sub)
	return 2
}

func cmdFingerprint(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fingerprint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", "", "controller data directory (required)")
	if err := fs.Parse(args); err != nil || *data == "" {
		fmt.Fprintln(stderr, "usage: segwatch fingerprint --data <dir>")
		return 2
	}
	cert, err := pki.LoadOrCreate(*data)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	fmt.Fprintln(stdout, pki.Fingerprint(cert))
	return 0
}

func cmdStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", "", "controller data directory (required)")
	asJSON := fs.Bool("json", false, "print as JSON")
	stale := fs.Duration("stale", 3*time.Hour, "mark checks not seen for this long as stale")
	if err := fs.Parse(args); err != nil || *data == "" {
		fmt.Fprintln(stderr, "usage: segwatch status --data <dir> [--json]")
		return 2
	}
	path := filepath.Join(*data, dbFile)
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintf(stderr, "no history yet at %s\n", path)
		return 2
	}
	st, err := store.Open(path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	defer st.Close()
	now := time.Now().UTC()
	status, err := st.Status(context.Background(), now, *stale)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(status)
	} else {
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "STATUS\tFLOW\tPORT\tEXPECT\tOBSERVED\tSINCE\tLAST SEEN")
		for _, c := range status.Checks {
			mark := "PASS"
			if !c.Pass {
				mark = "FAIL"
			}
			if now.Sub(c.Seen) > *stale {
				mark += " (stale)"
			}
			port := c.Port
			if strings.HasSuffix(c.CheckID, "@ipv6") {
				port += " (IPv6)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", mark, c.Flow, port, c.Expect, c.Outcome,
				c.Since.Format(time.RFC3339), c.Seen.Format(time.RFC3339))
		}
		tw.Flush()
		fmt.Fprintf(stdout, "\n%d checks, %d failing, %d stale\n", status.Total, status.Failing, status.Stale)
	}
	if status.Failing > 0 || status.Stale > 0 {
		return 1
	}
	return 0
}

func cmdProbe(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ctrl := fs.String("controller", "", "controller URL, e.g. https://10.0.99.10:8443 (required)")
	fp := fs.String("fingerprint", "", "controller certificate fingerprint, sha256:... (required)")
	tokenFile := fs.String("token-file", "", "file holding this probe's token (required)")
	bind := fs.String("bind", "", "address the responder listens on (default: all)")
	source := fs.String("source", "", "fixed source address for checks; one IPv4 and/or one IPv6, comma-separated")
	debug := fs.Bool("debug", false, "verbose logging")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *ctrl == "" || *fp == "" || *tokenFile == "" {
		fmt.Fprintln(stderr, "--controller, --fingerprint and --token-file are required")
		return 2
	}
	if !strings.HasPrefix(*ctrl, "https://") {
		fmt.Fprintln(stderr, "--controller must start with https://")
		return 2
	}
	raw, err := os.ReadFile(*tokenFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	src, err := parseSources(*source)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	log := newLogger(stderr, *debug)
	log.Info("probe starting", "controller", *ctrl)
	err = agent.Run(ctx, agent.Config{
		Controller: *ctrl, Fingerprint: *fp, Token: strings.TrimSpace(string(raw)),
		Bind: *bind, Sources: src, Log: log,
	})
	if err != nil {
		log.Error("probe", "err", err)
		return 2
	}
	return 0
}

func cmdAlert(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "test" {
		fmt.Fprintln(stderr, "usage: segwatch alert test -p policy.yaml")
		return 2
	}
	fs := flag.NewFlagSet("alert test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pol, ok := loadPolicy(fs, args[1:], stderr)
	if !ok {
		return 2
	}
	if len(pol.Alerts) == 0 {
		fmt.Fprintln(stderr, "the policy has no alerts")
		return 2
	}
	d := alert.New(pol.Alerts, time.Hour, newLogger(stderr, false))
	// Healthchecks gets a success ping, so the test does not leave it red.
	failed := d.Test(api.Status{Generated: time.Now().UTC()})
	if failed > 0 {
		fmt.Fprintf(stderr, "%d of %d alert channels failed\n", failed, len(pol.Alerts))
		return 1
	}
	fmt.Fprintf(stdout, "sent a test alert to %d channels\n", len(pol.Alerts))
	return 0
}

func cmdReport(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", "", "controller data directory (required)")
	out := fs.String("o", "", "write the HTML here (default: standard output)")
	days := fs.Int("days", 30, "history window for uptime and changes, in days")
	stale := fs.Duration("stale", 0, "mark checks not seen for this long as stale (default: 3 policy intervals)")
	pol, ok := loadPolicy(fs, args, stderr)
	if !ok {
		return 2
	}
	if *data == "" || *days <= 0 {
		fmt.Fprintln(stderr, "usage: segwatch report -p policy.yaml --data <dir> [-o report.html] [--days 30]")
		return 2
	}
	if *stale <= 0 {
		*stale = 3 * pol.Defaults.Interval.Std()
	}
	raw, err := os.ReadFile(fs.Lookup("p").Value.String())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	path := filepath.Join(*data, dbFile)
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintf(stderr, "no history yet at %s\n", path)
		return 2
	}
	st, err := store.Open(path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	defer st.Close()

	rep, err := report.Build(ctx, pol, st, report.Options{
		Now: time.Now().UTC(), Period: time.Duration(*days) * 24 * time.Hour, StaleAfter: *stale,
		Version: version, PolicyRaw: raw,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	w := stdout
	var f *os.File
	if *out != "" {
		if f, err = os.Create(*out); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		w = f
	}
	if err := rep.Render(w); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if f != nil {
		if err := f.Close(); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		fmt.Fprintf(stderr, "report written to %s: %d checks, %d failing, %d stale\n", *out, rep.Total, rep.Failing, rep.Stale)
	}
	if rep.Failing > 0 || rep.Stale > 0 {
		return 1
	}
	return 0
}

func metricsHandler(st *store.Store, stale time.Duration, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		status, err := st.Status(r.Context(), time.Now().UTC(), stale)
		if err != nil {
			log.Error("status for metrics", "err", err)
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = export.Prometheus(w, status, stale)
	})
	return mux
}

// cmdExport prints the status for a monitoring system: "metrics" for the
// Prometheus node_exporter textfile collector, "checkmk" for a local check.
func cmdExport(kind string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(kind, flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", "", "controller data directory (required)")
	stale := fs.Duration("stale", 3*time.Hour, "mark checks not seen for this long as stale")
	if err := fs.Parse(args); err != nil || *data == "" {
		fmt.Fprintf(stderr, "usage: segwatch %s --data <dir> [--stale 3h]\n", kind)
		return 2
	}
	path := filepath.Join(*data, dbFile)
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintf(stderr, "no history yet at %s\n", path)
		return 2
	}
	st, err := store.Open(path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	defer st.Close()
	status, err := st.Status(context.Background(), time.Now().UTC(), *stale)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if kind == "checkmk" {
		err = export.Checkmk(stdout, status, *stale)
	} else {
		err = export.Prometheus(stdout, status, *stale)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	// Monitoring reads the state from the output, so the exit code stays 0.
	return 0
}
