// Package runner executes a batch of checks with a concurrency and rate limit.
package runner

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/Juanen47/segwatch/internal/check"
	"github.com/Juanen47/segwatch/internal/policy"
)

// Options limit how hard a run hits the network.
type Options struct {
	Concurrency int // parallel checks, default 8
	PerSecond   int // checks started per second, default 20
}

// Run executes every check and returns the results sorted by flow and port.
func Run(ctx context.Context, checks []policy.Check, opt Options) []check.Result {
	if opt.Concurrency <= 0 {
		opt.Concurrency = 8
	}
	if opt.PerSecond <= 0 {
		opt.PerSecond = 20
	}
	tick := time.NewTicker(time.Second / time.Duration(opt.PerSecond))
	defer tick.Stop()

	results := make([]check.Result, len(checks))
	sem := make(chan struct{}, opt.Concurrency)
	var wg sync.WaitGroup
	for i, c := range checks {
		select {
		case <-ctx.Done():
			results[i] = check.Result{Check: c, Outcome: check.Error, Detail: ctx.Err().Error()}
			continue
		case <-tick.C:
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int, c policy.Check) {
			defer func() { <-sem; wg.Done() }()
			results[i] = check.Run(ctx, c)
		}(i, c)
	}
	wg.Wait()

	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i].Check, results[j].Check
		if a.Flow != b.Flow {
			return a.Flow < b.Flow
		}
		return a.Port.String() < b.Port.String()
	})
	return results
}

// Failed counts results that do not match the policy.
func Failed(rs []check.Result) int {
	n := 0
	for _, r := range rs {
		if !r.Pass {
			n++
		}
	}
	return n
}
