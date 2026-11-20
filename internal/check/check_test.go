package check_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Juanen47/segwatch/internal/check"
	"github.com/Juanen47/segwatch/internal/policy"
	"github.com/Juanen47/segwatch/internal/responder"
)

func TestEvaluate(t *testing.T) {
	cases := []struct {
		expect    policy.Expectation
		responder bool
		out       check.Outcome
		pass      bool
	}{
		{policy.Allow, true, check.Open, true},
		{policy.Allow, false, check.Refused, false},
		{policy.Allow, false, check.Unknown, false},
		{policy.Deny, true, check.Blocked, true},
		{policy.Deny, true, check.Refused, true}, // a reset in front of a listening responder comes from the path
		{policy.Deny, false, check.Refused, false},
		{policy.Deny, false, check.Open, false},
		{policy.Deny, false, check.Unknown, false},
		{policy.Deny, false, check.Error, false},
	}
	for _, c := range cases {
		got, _ := check.Evaluate(policy.Check{Expect: c.expect, Responder: c.responder}, c.out)
		if got != c.pass {
			t.Errorf("check.Evaluate(%s, responder=%v, %s) = %v, want %v", c.expect, c.responder, c.out, got, c.pass)
		}
	}
}

func freePort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		return pc.LocalAddr().(*net.UDPAddr).Port
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestAgainstResponder(t *testing.T) {
	tcpPort, udpPort, closedPort := freePort(t, "tcp"), freePort(t, "udp"), freePort(t, "tcp")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ports := []policy.Port{{Number: tcpPort, Proto: policy.TCP}, {Number: udpPort, Proto: policy.UDP}}
	go func() { _ = responder.Serve(ctx, "127.0.0.1", ports, log) }()
	time.Sleep(100 * time.Millisecond)

	lo := netip.MustParseAddr("127.0.0.1")
	mk := func(port int, proto policy.Proto, expect policy.Expectation, resp bool) policy.Check {
		return policy.Check{Flow: "t", Address: lo, Port: policy.Port{Number: port, Proto: proto},
			Expect: expect, Timeout: 500 * time.Millisecond, Responder: resp}
	}

	if r := check.Run(ctx, mk(tcpPort, policy.TCP, policy.Allow, true)); !r.Pass || r.Outcome != check.Open || r.Detail != "" {
		t.Errorf("tcp to responder: %+v", r)
	}
	if r := check.Run(ctx, mk(udpPort, policy.UDP, policy.Allow, true)); !r.Pass || r.Outcome != check.Open {
		t.Errorf("udp to responder: %+v", r)
	}
	if r := check.Run(ctx, mk(tcpPort, policy.TCP, policy.Deny, true)); r.Pass {
		t.Errorf("deny must fail when the responder is reachable: %+v", r)
	}
	// Nothing listens on closedPort: against a real host this proves the packet arrived.
	if r := check.Run(ctx, mk(closedPort, policy.TCP, policy.Deny, false)); r.Pass || r.Outcome != check.Refused {
		t.Errorf("deny to a real host that resets: %+v", r)
	}
}
