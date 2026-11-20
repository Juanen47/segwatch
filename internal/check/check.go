// Package check runs a single connectivity test and classifies what happened.
package check

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/Juanen47/segwatch/internal/policy"
)

// Outcome is what was observed on the wire.
type Outcome string

const (
	// Open: a connection was established, or a UDP/ICMP echo came back.
	Open Outcome = "open"
	// Refused: the destination host answered with a reset or ICMP port
	// unreachable. The packet reached it, but nothing listens there.
	Refused Outcome = "refused"
	// Blocked: no answer before the timeout, or an ICMP "administratively
	// prohibited" / unreachable from something in the path.
	Blocked Outcome = "blocked"
	// Unknown: the result cannot be told apart (for example UDP to a real
	// host that stays silent).
	Unknown Outcome = "unknown"
	// Error: the check could not run (bad local setup, missing permission).
	Error Outcome = "error"
)

// Result is the outcome of one check plus how it compares to the policy.
type Result struct {
	Check    policy.Check
	Outcome  Outcome
	Pass     bool
	Detail   string
	Duration time.Duration
}

// Magic prefixes every message exchanged with a segwatch responder.
const Magic = "SEGW1 "

// Run executes c and evaluates the outcome against c.Expect.
func Run(ctx context.Context, c policy.Check) Result {
	return RunFrom(ctx, c, netip.Addr{})
}

// RunFrom is Run with a fixed source address (zero value: let the kernel pick).
// Fixing it makes a probe with several interfaces test from the right network.
func RunFrom(ctx context.Context, c policy.Check, src netip.Addr) Result {
	start := time.Now()
	var out Outcome
	var detail string
	switch c.Port.Proto {
	case policy.TCP:
		out, detail = tcp(ctx, c, src)
	case policy.UDP:
		out, detail = udp(ctx, c, src)
	case policy.ICMP:
		out, detail = ping(ctx, c, src)
	default:
		out, detail = Error, "unsupported protocol"
	}
	pass, note := Evaluate(c, out)
	if note != "" {
		if detail != "" {
			detail += "; "
		}
		detail += note
	}
	return Result{Check: c, Outcome: out, Pass: pass, Detail: detail, Duration: time.Since(start)}
}

// Evaluate decides whether an outcome satisfies the expectation.
//
// When the destination is a segwatch responder, it listens on every port in
// the policy, so a reset can only come from something in the path rejecting
// the packet: it counts as blocked. Against a real host a reset proves the
// packet arrived, which breaks a deny rule.
func Evaluate(c policy.Check, out Outcome) (bool, string) {
	if c.Responder && out == Refused {
		out = Blocked
	}
	switch c.Expect {
	case policy.Allow:
		switch out {
		case Open:
			return true, ""
		case Unknown:
			return false, "no answer; cannot confirm the flow is allowed"
		}
		return false, ""
	case policy.Deny:
		switch out {
		case Blocked:
			return true, ""
		case Refused:
			return false, "packet reached the destination host"
		case Unknown:
			return false, "no answer; UDP to a real host cannot prove it is blocked"
		}
		return false, ""
	}
	return false, "invalid expectation"
}

func tcp(ctx context.Context, c policy.Check, src netip.Addr) (Outcome, string) {
	d := net.Dialer{Timeout: c.Timeout}
	if src.IsValid() {
		d.LocalAddr = &net.TCPAddr{IP: src.AsSlice()}
	}
	addr := netip.AddrPortFrom(c.Address, uint16(c.Port.Number)).String()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return classify(err)
	}
	defer conn.Close()
	if !c.Responder {
		return Open, ""
	}
	// Confirm we reached the segwatch responder and not some other service.
	nonce := newNonce()
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	if _, err := conn.Write([]byte(Magic + nonce + "\n")); err != nil {
		return Open, "connected, but echo failed: " + err.Error()
	}
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if !bytes.Equal(bytes.TrimSpace(buf[:n]), []byte(Magic+nonce)) {
		return Open, "connected, but the answer was not from a segwatch responder"
	}
	return Open, ""
}

func udp(ctx context.Context, c policy.Check, src netip.Addr) (Outcome, string) {
	d := net.Dialer{Timeout: c.Timeout}
	if src.IsValid() {
		d.LocalAddr = &net.UDPAddr{IP: src.AsSlice()}
	}
	addr := netip.AddrPortFrom(c.Address, uint16(c.Port.Number)).String()
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return Error, err.Error()
	}
	defer conn.Close()
	nonce := newNonce()
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	if _, err := conn.Write([]byte(Magic + nonce)); err != nil {
		return classify(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		out, detail := classify(err)
		if out == Blocked && !c.Responder {
			// Silence from a real host proves nothing for UDP.
			return Unknown, "no UDP answer"
		}
		return out, detail
	}
	if c.Responder && string(buf[:n]) != Magic+nonce {
		return Open, "answer was not from a segwatch responder"
	}
	return Open, ""
}

func ping(ctx context.Context, c policy.Check, src netip.Addr) (Outcome, string) {
	listenAddr := ""
	if src.IsValid() {
		listenAddr = src.String()
	}
	network, proto := "udp4", 1
	var typ icmp.Type = ipv4.ICMPTypeEcho
	var reply icmp.Type = ipv4.ICMPTypeEchoReply
	if c.Address.Is6() {
		network, proto = "udp6", 58
		typ, reply = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	// Unprivileged ICMP sockets: needs net.ipv4.ping_group_range to include
	// the user's group (the default on most current distributions).
	// Falls back to a raw socket when running with CAP_NET_RAW.
	raw := false
	conn, err := icmp.ListenPacket(network, listenAddr)
	if err != nil {
		rawNet := "ip4:icmp"
		if c.Address.Is6() {
			rawNet = "ip6:ipv6-icmp"
		}
		var rawErr error
		if conn, rawErr = icmp.ListenPacket(rawNet, listenAddr); rawErr != nil {
			return Error, "cannot open ICMP socket (allow the user in net.ipv4.ping_group_range or grant CAP_NET_RAW): " + err.Error()
		}
		raw = true
	}
	defer conn.Close()

	id := os.Getpid() & 0xffff
	payload := []byte(Magic + newNonce())
	msg := icmp.Message{Type: typ, Body: &icmp.Echo{ID: id, Seq: 1, Data: payload}}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return Error, err.Error()
	}
	var dst net.Addr = &net.UDPAddr{IP: c.Address.AsSlice()}
	if raw {
		dst = &net.IPAddr{IP: c.Address.AsSlice()}
	}
	if _, err := conn.WriteTo(wb, dst); err != nil {
		return classify(err)
	}
	deadline := time.Now().Add(c.Timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetReadDeadline(deadline)
	rb := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(rb)
		if err != nil {
			return classify(err)
		}
		m, err := icmp.ParseMessage(proto, rb[:n])
		if err != nil {
			continue
		}
		// Unprivileged sockets only deliver our own replies (the kernel
		// rewrites the ID); raw sockets see every reply, so match the payload.
		if echo, ok := m.Body.(*icmp.Echo); ok && m.Type == reply && bytes.Equal(echo.Data, payload) {
			return Open, ""
		}
	}
}

// classify maps a socket error to an outcome.
func classify(err error) (Outcome, string) {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return Refused, "connection refused"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return Blocked, "unreachable"
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return Blocked, "rejected by local or path filter"
	case errors.As(err, &ne) && ne.Timeout():
		return Blocked, "timeout"
	case errors.Is(err, context.DeadlineExceeded):
		return Blocked, "timeout"
	}
	return Error, err.Error()
}

func newNonce() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return hex.EncodeToString(b)
}
