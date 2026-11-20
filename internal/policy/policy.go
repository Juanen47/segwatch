// Package policy loads and validates a segwatch policy file.
//
// A policy declares networks (each with a probe), named targets, and the
// flows that are expected to be allowed or denied between them.
package policy

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Expectation is what the policy says should happen to a flow.
type Expectation string

const (
	Allow Expectation = "allow"
	Deny  Expectation = "deny"
)

// Proto is a transport protocol a check can use.
type Proto string

const (
	TCP  Proto = "tcp"
	UDP  Proto = "udp"
	ICMP Proto = "icmp"
)

// Policy is the parsed content of policy.yaml.
type Policy struct {
	Version  int                `yaml:"version"`
	Defaults Defaults           `yaml:"defaults"`
	Networks map[string]Network `yaml:"networks"`
	Targets  map[string]Target  `yaml:"targets"`
	Flows    []Flow             `yaml:"flows"`
	Alerts   []Alert            `yaml:"alerts"`
}

// Defaults holds values applied to every flow unless overridden.
type Defaults struct {
	Interval Duration `yaml:"interval"`
	Timeout  Duration `yaml:"timeout"`
}

// Network is a segment that hosts one probe.
type Network struct {
	CIDR  string `yaml:"cidr"`
	Probe Probe  `yaml:"probe"`

	prefix netip.Prefix
}

// Probe identifies the segwatch probe placed inside a network.
type Probe struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`

	addr netip.Addr
}

// Target is a real host (not a probe) that flows can point at.
type Target struct {
	Address string `yaml:"address"`
	Network string `yaml:"network"`

	addr netip.Addr
}

// Flow is one expected behaviour between a source network and a destination.
type Flow struct {
	Name    string      `yaml:"name"`
	From    string      `yaml:"from"`
	To      string      `yaml:"to"`
	Ports   []string    `yaml:"ports"`
	Expect  Expectation `yaml:"expect"`
	Timeout Duration    `yaml:"timeout"`
}

// Alert is a notification channel used when a flow changes state.
type Alert struct {
	Type string `yaml:"type"`
	URL  string `yaml:"url"`
	// TokenFile optionally holds a bearer token sent to ntfy or a webhook.
	// It is a path so that secrets stay out of the policy file.
	TokenFile string `yaml:"token_file"`
}

// Port is a parsed entry of Flow.Ports such as "22/tcp" or "icmp".
type Port struct {
	Number int   `json:"number,omitempty"`
	Proto  Proto `json:"proto"`
}

func (p Port) String() string {
	if p.Proto == ICMP {
		return "icmp"
	}
	return fmt.Sprintf("%d/%s", p.Number, p.Proto)
}

// Duration is a time.Duration that unmarshals from strings like "2s" or "1h".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q", n.Line, n.Value)
	}
	*d = Duration(v)
	return nil
}

// Std returns the value as a time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

const (
	defaultInterval = time.Hour
	defaultTimeout  = 2 * time.Second
)

// Load reads, parses and validates a policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses and validates policy YAML. Unknown keys are rejected so that
// typos do not silently disable a check.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if p.Defaults.Interval == 0 {
		p.Defaults.Interval = Duration(defaultInterval)
	}
	if p.Defaults.Timeout == 0 {
		p.Defaults.Timeout = Duration(defaultTimeout)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// ValidationError collects every problem found in a policy.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid policy:\n  - " + strings.Join(e.Problems, "\n  - ")
}

func (p *Policy) validate() error {
	var probs []string
	add := func(format string, a ...any) { probs = append(probs, fmt.Sprintf(format, a...)) }

	if p.Version != 1 {
		add("version must be 1 (got %d)", p.Version)
	}
	if len(p.Networks) == 0 {
		add("at least one network is required")
	}

	probeNames := map[string]string{}
	for _, name := range sortedKeys(p.Networks) {
		n := p.Networks[name]
		pfx, err := netip.ParsePrefix(n.CIDR)
		if err != nil {
			add("network %q: invalid cidr %q", name, n.CIDR)
		} else {
			n.prefix = pfx.Masked()
		}
		if n.Probe.Name == "" {
			add("network %q: probe.name is required", name)
		} else if other, dup := probeNames[n.Probe.Name]; dup {
			add("network %q: probe %q is already used by network %q", name, n.Probe.Name, other)
		} else {
			probeNames[n.Probe.Name] = name
		}
		if n.Probe.Address != "" {
			a, err := netip.ParseAddr(n.Probe.Address)
			switch {
			case err != nil:
				add("network %q: invalid probe.address %q", name, n.Probe.Address)
			case n.prefix.IsValid() && !n.prefix.Contains(a):
				add("network %q: probe.address %s is outside %s", name, a, n.prefix)
			default:
				n.Probe.addr = a
			}
		}
		p.Networks[name] = n
	}

	for _, name := range sortedKeys(p.Targets) {
		t := p.Targets[name]
		if _, clash := p.Networks[name]; clash {
			add("target %q: name is also used by a network", name)
		}
		a, err := netip.ParseAddr(t.Address)
		if err != nil {
			add("target %q: invalid address %q", name, t.Address)
		} else {
			t.addr = a
		}
		n, ok := p.Networks[t.Network]
		switch {
		case !ok:
			add("target %q: unknown network %q", name, t.Network)
		case t.addr.IsValid() && n.prefix.IsValid() && !n.prefix.Contains(t.addr):
			add("target %q: address %s is outside network %q (%s)", name, t.addr, t.Network, n.prefix)
		}
		p.Targets[name] = t
	}

	seen := map[string]bool{}
	for i, f := range p.Flows {
		label := fmt.Sprintf("flow #%d", i+1)
		if f.Name != "" {
			label = fmt.Sprintf("flow %q", f.Name)
		}
		if f.Name == "" {
			add("%s: name is required", label)
		} else if seen[f.Name] {
			add("%s: duplicate name", label)
		}
		seen[f.Name] = true

		if _, ok := p.Networks[f.From]; !ok {
			add("%s: from %q is not a network", label, f.From)
		}
		toNet, isNet := p.Networks[f.To]
		_, isTarget := p.Targets[f.To]
		switch {
		case !isNet && !isTarget:
			add("%s: to %q is neither a network nor a target", label, f.To)
		case isNet && !toNet.Probe.addr.IsValid():
			add("%s: network %q needs probe.address to be used as a destination", label, f.To)
		}
		if f.From != "" && f.From == f.To {
			add("%s: from and to are the same network", label)
		}
		if f.Expect != Allow && f.Expect != Deny {
			add("%s: expect must be allow or deny (got %q)", label, f.Expect)
		}
		if len(f.Ports) == 0 {
			add("%s: at least one port is required", label)
		}
		for _, s := range f.Ports {
			if _, err := ParsePort(s); err != nil {
				add("%s: %v", label, err)
			}
		}
	}

	for i, a := range p.Alerts {
		switch a.Type {
		case "ntfy", "webhook", "healthchecks":
		default:
			add("alert #%d: unknown type %q (use ntfy, webhook or healthchecks)", i+1, a.Type)
		}
		if !strings.HasPrefix(a.URL, "https://") && !strings.HasPrefix(a.URL, "http://") {
			add("alert #%d: url must start with https:// or http://", i+1)
		}
		if a.TokenFile != "" && a.Type == "healthchecks" {
			add("alert #%d: token_file is not used by healthchecks", i+1)
		}
	}

	if len(probs) > 0 {
		return &ValidationError{Problems: probs}
	}
	return nil
}

// ParsePort parses "22/tcp", "53/udp" or "icmp".
func ParsePort(s string) (Port, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "icmp" {
		return Port{Proto: ICMP}, nil
	}
	num, proto, ok := strings.Cut(s, "/")
	if !ok {
		return Port{}, fmt.Errorf("port %q: use <number>/tcp, <number>/udp or icmp", s)
	}
	n, err := strconv.Atoi(num)
	if err != nil || n < 1 || n > 65535 {
		return Port{}, fmt.Errorf("port %q: number must be 1-65535", s)
	}
	switch Proto(proto) {
	case TCP, UDP:
		return Port{Number: n, Proto: Proto(proto)}, nil
	}
	return Port{}, fmt.Errorf("port %q: protocol must be tcp or udp", s)
}

// Check is one concrete test derived from a flow: one destination, one port.
type Check struct {
	Flow      string        `json:"flow"`
	From      string        `json:"from"`
	To        string        `json:"to"`
	Address   netip.Addr    `json:"address"`
	Port      Port          `json:"port"`
	Expect    Expectation   `json:"expect"`
	Timeout   time.Duration `json:"timeout_ns"`
	Responder bool          `json:"responder"` // destination is a segwatch probe that answers on every port
}

// ID is a stable identifier for a check, used for history and alerts.
func (c Check) ID() string {
	return fmt.Sprintf("%s:%s->%s:%s", c.Flow, c.From, c.To, c.Port)
}

// ChecksFrom expands every flow whose source is network into checks.
func (p *Policy) ChecksFrom(network string) ([]Check, error) {
	if _, ok := p.Networks[network]; !ok {
		return nil, fmt.Errorf("unknown network %q", network)
	}
	var out []Check
	for _, f := range p.Flows {
		if f.From != network {
			continue
		}
		addr, responder := p.destination(f.To)
		timeout := p.Defaults.Timeout.Std()
		if f.Timeout > 0 {
			timeout = f.Timeout.Std()
		}
		for _, s := range f.Ports {
			port, _ := ParsePort(s) // already validated
			out = append(out, Check{
				Flow: f.Name, From: f.From, To: f.To, Address: addr, Port: port,
				Expect: f.Expect, Timeout: timeout, Responder: responder,
			})
		}
	}
	return out, nil
}

// ListenPorts returns the TCP and UDP ports a probe in network must answer on,
// so that flows pointing at that network can be tested.
func (p *Policy) ListenPorts(network string) ([]Port, error) {
	if _, ok := p.Networks[network]; !ok {
		return nil, fmt.Errorf("unknown network %q", network)
	}
	set := map[Port]bool{}
	for _, f := range p.Flows {
		if f.To != network {
			continue
		}
		for _, s := range f.Ports {
			port, _ := ParsePort(s)
			if port.Proto != ICMP {
				set[port] = true
			}
		}
	}
	ports := make([]Port, 0, len(set))
	for port := range set {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Proto != ports[j].Proto {
			return ports[i].Proto < ports[j].Proto
		}
		return ports[i].Number < ports[j].Number
	})
	return ports, nil
}

func (p *Policy) destination(to string) (netip.Addr, bool) {
	if n, ok := p.Networks[to]; ok {
		return n.Probe.addr, true
	}
	return p.Targets[to].addr, false
}

// NetworkOfProbe returns the network a probe name belongs to.
func (p *Policy) NetworkOfProbe(probe string) (string, bool) {
	for name, n := range p.Networks {
		if n.Probe.Name == probe {
			return name, true
		}
	}
	return "", false
}

// NetworkNames returns network names in a stable order.
func (p *Policy) NetworkNames() []string { return sortedKeys(p.Networks) }

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
