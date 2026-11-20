// Package tokens stores one secret per probe. Only SHA-256 hashes are kept
// on disk; the token itself is shown once when it is created.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

const fileName = "tokens.json"

// Store maps probe names to token hashes.
type Store struct {
	mu     sync.RWMutex
	path   string
	hashes map[string]string // probe -> hex(sha256(token))
}

// Open loads the token store in dir (an empty store if the file is missing).
func Open(dir string) (*Store, error) {
	s := &Store{path: filepath.Join(dir, fileName), hashes: map[string]string{}}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &s.hashes); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path, err)
	}
	return s, nil
}

// Add creates (or replaces) the token for probe and returns it.
func (s *Store) Add(probe string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := "sgw_" + base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hashes[probe] = hash(tok)
	return tok, s.save()
}

// Revoke deletes the token of probe.
func (s *Store) Revoke(probe string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.hashes[probe]; !ok {
		return fmt.Errorf("no token for probe %q", probe)
	}
	delete(s.hashes, probe)
	return s.save()
}

// Probes lists probes that have a token.
func (s *Store) Probes() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.hashes))
	for p := range s.hashes {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Lookup returns the probe that owns token. It compares every entry in
// constant time so timing does not reveal which probe matched.
func (s *Store) Lookup(token string) (string, bool) {
	h := []byte(hash(token))
	s.mu.RLock()
	defer s.mu.RUnlock()
	found := ""
	for probe, want := range s.hashes {
		if subtle.ConstantTimeCompare(h, []byte(want)) == 1 {
			found = probe
		}
	}
	return found, found != ""
}

func (s *Store) save() error {
	data, err := json.MarshalIndent(s.hashes, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func hash(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}
