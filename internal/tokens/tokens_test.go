package tokens

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddLookupRevoke(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.Add("probe-a")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, "sgw_") {
		t.Errorf("token %q lacks prefix", tok)
	}
	if p, ok := s.Lookup(tok); !ok || p != "probe-a" {
		t.Errorf("Lookup = %q, %v", p, ok)
	}
	if _, ok := s.Lookup(tok + "x"); ok {
		t.Error("wrong token accepted")
	}

	raw, _ := os.ReadFile(filepath.Join(dir, fileName))
	if strings.Contains(string(raw), tok) {
		t.Error("token stored in clear text")
	}
	if fi, _ := os.Stat(filepath.Join(dir, fileName)); fi.Mode().Perm() != 0o600 {
		t.Errorf("token file mode = %v", fi.Mode().Perm())
	}

	again, _ := Open(dir)
	if p, ok := again.Lookup(tok); !ok || p != "probe-a" {
		t.Error("token not persisted")
	}
	if err := again.Revoke("probe-a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := again.Lookup(tok); ok {
		t.Error("revoked token still accepted")
	}
}
