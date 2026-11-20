// Command segwatch checks that network segmentation matches a declared policy.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/Juanen47/segwatch/internal/check"
	"github.com/Juanen47/segwatch/internal/policy"
	"github.com/Juanen47/segwatch/internal/responder"
	"github.com/Juanen47/segwatch/internal/runner"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `segwatch: continuous network segmentation testing

Single host:
  segwatch validate -p policy.yaml
  segwatch run      -p policy.yaml --from <network> [--source addr] [--json]
  segwatch respond  -p policy.yaml --network <network> [--bind addr]

Controller and probes:
  segwatch controller  -p policy.yaml --data <dir> [--listen :8443]
  segwatch token add   -p policy.yaml --data <dir> <probe-name>
  segwatch token list  --data <dir>
  segwatch token revoke --data <dir> <probe-name>
  segwatch fingerprint --data <dir>
  segwatch status      --data <dir> [--json]
  segwatch probe --controller https://host:8443 --fingerprint sha256:... --token-file <file>
                 [--bind addr] [--source addr]

  segwatch version

Exit codes for run: 0 all flows match the policy, 1 at least one does not,
2 the run could not start.

Only use segwatch on networks you own or are authorised in writing to test.
`

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

func realMain(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch args[0] {
	case "validate":
		return cmdValidate(args[1:], stdout, stderr)
	case "run":
		return cmdRun(ctx, args[1:], stdout, stderr)
	case "respond":
		return cmdRespond(ctx, args[1:], stderr)
	case "controller":
		return cmdController(ctx, args[1:], stdout, stderr)
	case "token":
		return cmdToken(args[1:], stdout, stderr)
	case "fingerprint":
		return cmdFingerprint(args[1:], stdout, stderr)
	case "status":
		return cmdStatus(args[1:], stdout, stderr)
	case "probe":
		return cmdProbe(ctx, args[1:], stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "segwatch", version)
		return 0
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return 2
}

func loadPolicy(fs *flag.FlagSet, args []string, stderr io.Writer) (*policy.Policy, bool) {
	path := fs.String("p", "policy.yaml", "policy file")
	fs.StringVar(path, "policy", "policy.yaml", "policy file")
	if err := fs.Parse(args); err != nil {
		return nil, false
	}
	pol, err := policy.Load(*path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return nil, false
	}
	return pol, true
}

func cmdValidate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pol, ok := loadPolicy(fs, args, stderr)
	if !ok {
		return 2
	}
	checks := 0
	for _, n := range pol.NetworkNames() {
		cs, _ := pol.ChecksFrom(n)
		checks += len(cs)
	}
	fmt.Fprintf(stdout, "policy OK: %d networks, %d targets, %d flows, %d checks\n",
		len(pol.Networks), len(pol.Targets), len(pol.Flows), checks)
	return 0
}

func cmdRun(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	from := fs.String("from", "", "network this host is in (required)")
	asJSON := fs.Bool("json", false, "print results as JSON")
	conc := fs.Int("concurrency", 8, "parallel checks")
	rate := fs.Int("rate", 20, "checks started per second")
	source := fs.String("source", "", "fixed source address for checks (default: chosen by the kernel)")
	pol, ok := loadPolicy(fs, args, stderr)
	if !ok {
		return 2
	}
	src, err := parseOptionalAddr(*source)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if *from == "" {
		fmt.Fprintf(stderr, "--from is required; networks: %s\n", strings.Join(pol.NetworkNames(), ", "))
		return 2
	}
	checks, err := pol.ChecksFrom(*from)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if len(checks) == 0 {
		fmt.Fprintf(stderr, "no flows start in network %q\n", *from)
		return 2
	}

	results := runner.Run(ctx, checks, runner.Options{Concurrency: *conc, PerSecond: *rate, Source: src})
	if *asJSON {
		writeJSON(stdout, results)
	} else {
		writeTable(stdout, results)
	}
	if runner.Failed(results) > 0 {
		return 1
	}
	return 0
}

func cmdRespond(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("respond", flag.ContinueOnError)
	fs.SetOutput(stderr)
	network := fs.String("network", "", "network this probe is in (required)")
	bind := fs.String("bind", "", "address to listen on (default: all)")
	debug := fs.Bool("debug", false, "log every check received")
	pol, ok := loadPolicy(fs, args, stderr)
	if !ok {
		return 2
	}
	ports, err := pol.ListenPorts(*network)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	if len(ports) == 0 {
		log.Info("no TCP or UDP flows point at this network; only ICMP will be answered (by the kernel)")
	}
	if err := responder.Serve(ctx, *bind, ports, log); err != nil {
		log.Error("responder", "err", err)
		if errors.Is(err, syscall.EACCES) {
			log.Error("ports below 1024 need CAP_NET_BIND_SERVICE")
		}
		return 2
	}
	return 0
}

type jsonResult struct {
	ID       string `json:"id"`
	Flow     string `json:"flow"`
	From     string `json:"from"`
	To       string `json:"to"`
	Address  string `json:"address"`
	Port     string `json:"port"`
	Expect   string `json:"expect"`
	Outcome  string `json:"outcome"`
	Pass     bool   `json:"pass"`
	Detail   string `json:"detail,omitempty"`
	Duration int64  `json:"duration_ms"`
}

func writeJSON(w io.Writer, rs []check.Result) {
	out := make([]jsonResult, 0, len(rs))
	for _, r := range rs {
		out = append(out, jsonResult{
			ID: r.Check.ID(), Flow: r.Check.Flow, From: r.Check.From, To: r.Check.To,
			Address: r.Check.Address.String(), Port: r.Check.Port.String(),
			Expect: string(r.Check.Expect), Outcome: string(r.Outcome), Pass: r.Pass,
			Detail: r.Detail, Duration: r.Duration.Milliseconds(),
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func writeTable(w io.Writer, rs []check.Result) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tFLOW\tTO\tPORT\tEXPECT\tOBSERVED\tDETAIL")
	for _, r := range rs {
		status := "PASS"
		if !r.Pass {
			status = "FAIL"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s (%s)\t%s\t%s\t%s\t%s\n", status, r.Check.Flow, r.Check.To,
			r.Check.Address, r.Check.Port, r.Check.Expect, r.Outcome, r.Detail)
	}
	tw.Flush()
	failed := runner.Failed(rs)
	fmt.Fprintf(w, "\n%d checks, %d pass, %d fail\n", len(rs), len(rs)-failed, failed)
}
