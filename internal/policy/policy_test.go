package policy

import (
	"strings"
	"testing"
	"time"
)

const valid = `
version: 1
defaults: { timeout: 1s }
networks:
  guests:  { cidr: 10.0.30.0/24, probe: { name: p-guests, address: 10.0.30.5 } }
  servers: { cidr: 10.0.10.0/24, probe: { name: p-servers, address: 10.0.10.5 } }
targets:
  nas: { address: 10.0.10.20, network: servers }
flows:
  - { name: isolated, from: guests, to: servers, ports: [22/tcp, 53/udp, icmp], expect: deny }
  - { name: nas, from: guests, to: nas, ports: [443/tcp], expect: allow, timeout: 3s }
`

func TestParseValid(t *testing.T) {
	p, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Defaults.Interval.Std(); got != time.Hour {
		t.Errorf("default interval = %v, want 1h", got)
	}
	checks, err := p.ChecksFrom("guests")
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 4 {
		t.Fatalf("got %d checks, want 4", len(checks))
	}
	c := checks[0]
	if !c.Responder || c.Address.String() != "10.0.10.5" || c.Timeout != time.Second {
		t.Errorf("network destination check = %+v", c)
	}
	last := checks[3]
	if last.Responder || last.Address.String() != "10.0.10.20" || last.Timeout != 3*time.Second {
		t.Errorf("target destination check = %+v", last)
	}
	if none, _ := p.ChecksFrom("servers"); len(none) != 0 {
		t.Errorf("servers has no outgoing flows, got %d checks", len(none))
	}
}

func TestListenPorts(t *testing.T) {
	p, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	ports, err := p.ListenPorts("servers")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, port := range ports {
		got = append(got, port.String())
	}
	if strings.Join(got, ",") != "22/tcp,53/udp" {
		t.Errorf("listen ports = %v", got)
	}
}

func TestParseInvalid(t *testing.T) {
	bad := `
version: 2
networks:
  a: { cidr: 10.0.0.0/33, probe: { name: p } }
  b: { cidr: 10.1.0.0/24, probe: { name: p, address: 10.9.9.9 } }
targets:
  t: { address: 10.5.5.5, network: b }
flows:
  - { name: x, from: a, to: nowhere, ports: [99999/tcp, 22/sctp], expect: maybe }
  - { name: x, from: a, to: b, ports: [], expect: deny }
alerts:
  - { type: email, url: ftp://x }
`
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{
		"version must be 1",
		`network "a": invalid cidr`,
		`probe "p" is already used`,
		"outside 10.1.0.0/24",
		`target "t": address 10.5.5.5 is outside`,
		`to "nowhere" is neither`,
		"number must be 1-65535",
		"protocol must be tcp or udp",
		"expect must be allow or deny",
		"duplicate name",
		"at least one port",
		`unknown type "email"`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	_, err := Parse([]byte(strings.Replace(valid, "expect: deny", "expct: deny", 1)))
	if err == nil || !strings.Contains(err.Error(), "expct") {
		t.Fatalf("typo in key should be rejected, got %v", err)
	}
}

func TestParsePort(t *testing.T) {
	for in, want := range map[string]string{"22/tcp": "22/tcp", " 53/UDP ": "53/udp", "ICMP": "icmp"} {
		p, err := ParsePort(in)
		if err != nil || p.String() != want {
			t.Errorf("ParsePort(%q) = %v, %v; want %s", in, p, err, want)
		}
	}
	for _, in := range []string{"22", "0/tcp", "22/icmp", "tcp/22"} {
		if _, err := ParsePort(in); err == nil {
			t.Errorf("ParsePort(%q) should fail", in)
		}
	}
}

func TestExampleValidates(t *testing.T) {
	if _, err := Load("../../examples/policy.yaml"); err != nil {
		t.Fatal(err)
	}
}
