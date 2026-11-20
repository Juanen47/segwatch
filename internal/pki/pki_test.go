package pki

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPinnedClient(t *testing.T) {
	dir := t.TempDir()
	cert, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadOrCreate(dir)
	if err != nil || Fingerprint(again) != Fingerprint(cert) {
		t.Fatal("certificate not reused on second start")
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()

	good, err := PinnedClient(Fingerprint(cert), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := good.Get(srv.URL)
	if err != nil {
		t.Fatalf("pinned request failed: %v", err)
	}
	resp.Body.Close()

	bad, _ := PinnedClient("sha256:"+strings.Repeat("0", 64), 5*time.Second)
	if _, err := bad.Get(srv.URL); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("wrong pin should fail, got %v", err)
	}

	if _, err := PinnedClient("md5:abc", time.Second); err == nil {
		t.Error("malformed fingerprint accepted")
	}
}
