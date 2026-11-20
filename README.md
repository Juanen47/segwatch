# segwatch

**Continuous network segmentation testing.** Write down which network may
talk to which, on which ports. Small probes inside each network test those
flows and tell you when reality drifts from the policy.

> Status: early draft (v0.1 in progress). The single-host `run` mode and the
> responder work today; the controller, history and alerts are on the way.
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

Permissions: no root needed. Ports below 1024 need `CAP_NET_BIND_SERVICE`
for the responder; ICMP uses unprivileged ping sockets
(`net.ipv4.ping_group_range`) or falls back to `CAP_NET_RAW`.

## Build

```sh
CGO_ENABLED=0 go build -trimpath -o segwatch ./cmd/segwatch
go test ./...
```

## Roadmap

- [x] Policy file with validation
- [x] TCP, UDP and ICMP checks with outcome classification
- [x] Responder and single-host `run` mode
- [ ] Controller: probes register with a token over pinned TLS and pull their checks
- [ ] Scheduler, SQLite history and state-change detection
- [ ] Alerts: webhook, ntfy, Healthchecks
- [ ] HTML report with the expected-vs-observed matrix
- [ ] Checkmk local check and Prometheus metrics
- [ ] IPv6 flows, release binaries

## Responsible use

Only test networks you own or are authorised in writing to test. segwatch
only contacts what the policy lists, with a rate limit. See
[SECURITY.md](SECURITY.md).

## License

[Apache 2.0](LICENSE)
