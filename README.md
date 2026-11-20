# segwatch

**Continuous network segmentation testing.** Write down which network may
talk to which, on which ports. Small probes inside each network test those
flows and tell you when reality drifts from the policy.

> Status: early draft (v0.1 in progress). Single-host mode, probes, the
> controller, its history, alerts, the HTML report and Prometheus/Checkmk
> export work today.
> [Leer en español](README.es.md).

## Why

VLANs and firewall rules get configured once, then a rule change quietly
lets the guest Wi-Fi reach the servers and nobody notices until the next
yearly audit. PCI DSS asks for segmentation tests at least every 12 months
and after any change (every 6 months for service providers); most teams do
it by hand with nmap and a spreadsheet.

Existing tools are either manual (GUI ping matrices), one-off audit scripts,
Kubernetes-only (NetAssert) or full attack-simulation suites. segwatch is a
small, declarative, always-on check that fits next to your monitoring.

## How it works

```
 guests network        servers network        management network
 ┌──────────────┐ deny ┌──────────────────┐ allow ┌──────────────┐
 │    probe     │─────▶│ probe + responder│◀──────│    probe     │
 └──────┬───────┘      └────────┬─────────┘  443  └──────┬───────┘
        └──────────── HTTPS (probe calls out) ───────────┘
                                ▼
                 controller ─▶ report · alerts · Checkmk / Prometheus
```

* A **probe** is one static binary placed in each network (an LXC, a VM, a
  Raspberry Pi). It runs checks and answers checks from other probes.
* When a flow points at a **network**, the check targets that network's
  probe, which listens on every port in the policy. A `deny` flow therefore
  passes only if traffic really does not get through, not just because no
  service happened to be listening.
* When a flow points at a **target** (a real host), segwatch connects to it
  directly.

### Outcomes

| Outcome   | Meaning                                                       | `allow` | `deny` |
|-----------|---------------------------------------------------------------|---------|--------|
| `open`    | Connected, or UDP/ICMP echo received                          | pass    | fail   |
| `refused` | Real host answered with a reset: the packet arrived           | fail    | fail   |
| `blocked` | Timeout, unreachable, or reset in front of a listening probe  | fail    | pass   |
| `unknown` | UDP to a real host stayed silent: cannot tell                 | fail    | fail   |
| `unverified` | Looked blocked, but the destination probe is down (controller only) | –  | fail   |

A silent destination looks exactly like a firewall that drops traffic, so
the controller only trusts a `deny` towards a probe while that probe is in
contact with it. If the destination probe has not polled for longer than
`--stale` (3 intervals by default), a passing `deny` towards it is recorded
as `unverified` and counts as failing. A probe whose responder cannot listen
exits instead of polling, so a broken responder is caught the same way.
Results towards a probe that first polled less than 5 seconds ago are
dropped, so probes starting in any order do not raise false alarms.

## Policy

```yaml
version: 1
defaults: { interval: 1h, timeout: 2s }

networks:
  guests:  { cidr: 10.0.30.0/24, probe: { name: probe-guests,  address: 10.0.30.5 } }
  servers: { cidr: 10.0.10.0/24, probe: { name: probe-servers, address: 10.0.10.5 } }

targets:
  nas: { address: 10.0.10.20, network: servers }

flows:
  - name: guests-isolated-from-servers
    from: guests
    to: servers
    ports: [22/tcp, 445/tcp, 53/udp, icmp]
    expect: deny
```

See [examples/policy.yaml](examples/policy.yaml). Unknown keys are rejected,
so a typo cannot silently disable a check.

## Usage

```sh
# check the policy file
segwatch validate -p policy.yaml

# on the probe in "servers": answer checks on the ports the policy uses
segwatch respond -p policy.yaml --network servers

# on the probe in "guests": run every flow that starts there
segwatch run -p policy.yaml --from guests          # table, exit 1 on any FAIL
segwatch run -p policy.yaml --from guests --json   # for scripts and CI
```

```
STATUS  FLOW                          TO                    PORT     EXPECT  OBSERVED  DETAIL
PASS    guests-isolated-from-servers  servers (10.0.10.5)   22/tcp   deny    blocked   timeout
FAIL    guests-isolated-from-servers  servers (10.0.10.5)   445/tcp  deny    open
```

### Controller and probes

Run the controller once, somewhere every probe can reach (one TCP port):

```sh
# on the controller host
segwatch token add -p policy.yaml --data /var/lib/segwatch probe-guests > guests.token
segwatch token add -p policy.yaml --data /var/lib/segwatch probe-servers > servers.token
segwatch controller -p policy.yaml --data /var/lib/segwatch --listen :8443
# prints: controller fingerprint: sha256:...
```

Copy each token to its probe (`chmod 600`) and start the probe. It only
needs the controller address, the fingerprint and its token: the controller
tells it what to test and which ports to answer on.

```sh
segwatch probe --controller https://10.0.99.10:8443 \
  --fingerprint sha256:... --token-file /etc/segwatch/token --source 10.0.30.5
```

```sh
segwatch status --data /var/lib/segwatch   # exit 1 if any check fails or is stale
```

* Probes always call the controller; the controller never connects to them.
* TLS 1.3 with the controller certificate pinned by fingerprint: no CA, no DNS.
* Tokens are stored hashed. A probe only gets the checks for its own network,
  and results it sends for anything else are discarded.
* History lives in SQLite; state changes (pass to fail and back) are logged.

### Report

```sh
segwatch report -p policy.yaml --data /var/lib/segwatch -o report.html   # --days 30 by default
```

One self-contained HTML page, with no scripts and no external resources, so
you can archive it or attach it to an audit:

* a matrix of source networks against destinations, one badge per check
  (✓ matches the policy, ✗ does not, ? stale, … not run yet);
* every check with its expected and observed result, since when, and the
  share of runs that matched the policy over the period;
* the recent changes (broke / recovered);
* the policy's SHA-256 hash, so the report names the exact policy it checked.

It exits 1 when any check fails or is stale, so a cron job can mail it only
when something is wrong. It reads the history and needs no running controller.

### Monitoring: Prometheus and Checkmk

**Prometheus.** Start the controller with `--metrics 127.0.0.1:9469` and
scrape `/metrics` (plain HTTP, so keep it on localhost or a management
network). Without a listener, `segwatch metrics --data <dir>` prints the same
text for the node_exporter textfile collector:

```sh
segwatch metrics --data /var/lib/segwatch > /var/lib/node_exporter/segwatch.prom.tmp \
  && mv /var/lib/node_exporter/segwatch.prom.tmp /var/lib/node_exporter/segwatch.prom
```

Totals: `segwatch_checks`, `segwatch_checks_failing` and
`segwatch_checks_stale`. Per check, labelled with flow, from, to, port,
expect, observed and probe: `segwatch_check_pass`, `segwatch_check_stale`,
`segwatch_check_last_seen_timestamp_seconds` and
`segwatch_check_since_timestamp_seconds`. A starting alert rule:
`segwatch_checks_failing > 0 or segwatch_checks_stale > 0`.

**Checkmk.** On the controller host, add a local check that prints one
service per flow plus `segwatch summary` (CRIT when a check fails, WARN
when one is stale, with metrics for graphs):

```sh
cat > /usr/lib/check_mk_agent/local/segwatch <<'SH'
#!/bin/sh
exec /usr/local/bin/segwatch checkmk --data /var/lib/segwatch
SH
chmod +x /usr/lib/check_mk_agent/local/segwatch
```

### Alerts

The controller sends alerts to the channels listed under `alerts:` in the
policy:

| Type           | What it gets                                                                 |
|----------------|------------------------------------------------------------------------------|
| `ntfy`         | A short message per batch of changes: failing (high priority), recovered, probe silent, reporting again |
| `webhook`      | The same events as JSON: `{"source":"segwatch","events":[{check_id, flow, from, to, port, expect, outcome, pass, previous_outcome, kind, at, last_seen}]}` |
| `healthchecks` | A heartbeat every interval (at most 5 min): success when every check passes and none is stale, `/fail` with the failing list otherwise. If the controller dies, the pings stop and Healthchecks alerts you |

```yaml
alerts:
  - type: ntfy
    url: https://ntfy.sh/a-long-secret-topic
    token_file: /etc/segwatch/ntfy.token   # optional bearer token, also for webhook
  - type: healthchecks
    url: https://hc-ping.com/your-uuid
```

A check counts as stale (its probe went silent) after 3 intervals with no
result; change it with `segwatch controller --stale`. Send a test alert to
every channel with `segwatch alert test -p policy.yaml`. Alert URLs are
never written to the log, because ntfy topics and Healthchecks UUIDs work
as passwords.

Permissions: no root needed. Ports below 1024 need `CAP_NET_BIND_SERVICE`
for the responder; ICMP uses unprivileged ping sockets
(`net.ipv4.ping_group_range`) or falls back to `CAP_NET_RAW`.

## Try it on Docker

[examples/lab](examples/lab) builds three isolated Docker networks (management,
servers, guests), a controller, three probes and one real web server. Needs
Go and Docker, no root.

```sh
cd examples/lab
./lab.sh up       # build, create tokens, start everything
./lab.sh status   # 12 checks, 0 failing
./lab.sh drift    # simulate a firewall mistake: guests reach the servers
./lab.sh status   # the 5 guest-to-server checks now FAIL
./lab.sh heal     # undo it; back to 0 failing
./lab.sh outage   # stop the servers probe: after ~40s its denies are "unverified"
./lab.sh restore  # start it again; back to 0 failing
./lab.sh alerts   # what ntfy, the webhook and Healthchecks received
./lab.sh report   # writes examples/lab/report.html
./lab.sh metrics  # Prometheus metrics from the controller
./lab.sh checkmk  # Checkmk local check output
./lab.sh down
```

`IPV6=1 ./lab.sh up` (and the same prefix on every command) runs the lab
dual-stack, with 24 checks: each one over IPv4 and IPv6. It needs IPv6 in
the Docker host, which Docker Desktop and WSL2 have.

## IPv6 and dual-stack networks

On a dual-stack network, IPv6 often gets less firewall attention than IPv4:
the VLAN is isolated over IPv4 while IPv6 routes straight through. segwatch
tests both. Give a network `cidr6` and its probe `address6` (and a target
`address6`), and every flow to it runs once per family:

```yaml
networks:
  guests:  { cidr: 10.0.30.0/24, cidr6: "fd00:30::/64",
             probe: { name: probe-guests, address: 10.0.30.5, address6: "fd00:30::5" } }
targets:
  nas: { address: 10.0.10.20, address6: "fd00:10::20", network: servers }
```

IPv6 checks have IDs ending in `@ipv6`. They show up as `22/tcp v6` in the
report, with `family="ipv6"` in Prometheus and with "(IPv6)" in Checkmk. A
network can also be IPv6-only (`cidr6` and `address6` alone). For a probe
with several interfaces, fix the source address per family:
`--source 10.0.30.5,fd00:30::5`.

## Install

Download a release for your platform from
[Releases](https://github.com/Juanen47/segwatch/releases): Linux amd64, arm64
and armv7 (Raspberry Pi), and FreeBSD amd64 (OPNsense, pfSense). Each one is
a single static binary. Check the download before you run it:

```sh
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify segwatch_*_linux_amd64.tar.gz --repo Juanen47/segwatch   # built by this repo's CI
```

## Build

```sh
CGO_ENABLED=0 go build -trimpath -o segwatch ./cmd/segwatch
go test ./...
```

## Roadmap

- [x] Policy file with validation
- [x] TCP, UDP and ICMP checks with outcome classification
- [x] Responder and single-host `run` mode
- [x] Controller: probes authenticate with a token over pinned TLS and pull their checks
- [x] Scheduling on the probe, SQLite history and state-change detection
- [x] Alerts: webhook, ntfy, Healthchecks
- [x] HTML report with the expected-vs-observed matrix
- [x] Checkmk local check and Prometheus metrics
- [x] IPv6 and dual-stack flows
- [x] Release binaries with checksums and build provenance

## Responsible use

Only test networks you own or are authorised in writing to test. segwatch
only contacts what the policy lists, with a rate limit. See
[SECURITY.md](SECURITY.md) ([en español](SECURITY.es.md)).

## License

[Apache 2.0](LICENSE)
