package runner

import (
	"net/netip"
	"testing"
)

func TestSourceFor(t *testing.T) {
	v4, v6 := netip.MustParseAddr("10.0.30.5"), netip.MustParseAddr("fd00:30::5")
	srcs := []netip.Addr{v4, v6}
	if got := SourceFor(srcs, netip.MustParseAddr("10.0.10.5")); got != v4 {
		t.Errorf("v4 dst: %v", got)
	}
	if got := SourceFor(srcs, netip.MustParseAddr("fd00:10::5")); got != v6 {
		t.Errorf("v6 dst: %v", got)
	}
	if got := SourceFor([]netip.Addr{v4}, netip.MustParseAddr("fd00:10::5")); got.IsValid() {
		t.Errorf("no v6 source: want zero, got %v", got)
	}
}
