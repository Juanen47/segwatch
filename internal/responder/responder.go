// Package responder answers segwatch checks on the ports a policy uses.
//
// It never runs commands: TCP connections get their first line echoed back
// if it carries the segwatch magic, UDP datagrams likewise, and everything
// else is dropped. Connections are short-lived and size-limited.
package responder

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Juanen47/segwatch/internal/check"
	"github.com/Juanen47/segwatch/internal/policy"
)

const (
	maxLine     = 64
	connTimeout = 5 * time.Second
)

// Serve listens on every port until ctx is cancelled. It returns an error if
// any listener cannot be opened.
func Serve(ctx context.Context, bind string, ports []policy.Port, log *slog.Logger) error {
	var closers []func()
	var wg sync.WaitGroup
	defer func() {
		for _, c := range closers {
			c()
		}
		wg.Wait()
	}()

	for _, p := range ports {
		addr := net.JoinHostPort(bind, strconv.Itoa(p.Number))
		switch p.Proto {
		case policy.TCP:
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("listen %s: %w", p, err)
			}
			closers = append(closers, func() { ln.Close() })
			wg.Add(1)
			go func() { defer wg.Done(); serveTCP(ln, log) }()
		case policy.UDP:
			pc, err := net.ListenPacket("udp", addr)
			if err != nil {
				return fmt.Errorf("listen %s: %w", p, err)
			}
			closers = append(closers, func() { pc.Close() })
			wg.Add(1)
			go func() { defer wg.Done(); serveUDP(pc, log) }()
		}
		log.Info("listening", "port", p.String())
	}
	<-ctx.Done()
	return nil
}

func serveTCP(ln net.Listener, log *slog.Logger) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Warn("accept", "err", err)
			}
			return
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(connTimeout))
			line, err := bufio.NewReaderSize(conn, maxLine).ReadSlice('\n')
			if err != nil {
				return
			}
			msg := strings.TrimSpace(string(line))
			if strings.HasPrefix(msg, check.Magic) && len(msg) <= maxLine {
				_, _ = conn.Write([]byte(msg + "\n"))
				log.Debug("tcp check", "from", conn.RemoteAddr().String())
			}
		}()
	}
}

func serveUDP(pc net.PacketConn, log *slog.Logger) {
	buf := make([]byte, maxLine)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Warn("udp read", "err", err)
			}
			return
		}
		if n <= maxLine && strings.HasPrefix(string(buf[:n]), check.Magic) {
			_, _ = pc.WriteTo(buf[:n], from)
			log.Debug("udp check", "from", from.String())
		}
	}
}
