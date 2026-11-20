// Package pki creates the controller's self-signed certificate and lets probes
// pin it by fingerprint, so no public CA or DNS name is needed.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	certFile = "controller.crt"
	keyFile  = "controller.key"
)

// LoadOrCreate returns the controller certificate stored in dir, creating a
// new ECDSA P-256 key and a 10-year self-signed certificate on first use.
func LoadOrCreate(dir string) (tls.Certificate, error) {
	cp, kp := filepath.Join(dir, certFile), filepath.Join(dir, keyFile)
	if _, err := os.Stat(cp); err == nil {
		return tls.LoadX509KeyPair(cp, kp)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "segwatch controller"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(cp, kp)
}

// Fingerprint returns "sha256:<hex>" of the leaf certificate.
func Fingerprint(cert tls.Certificate) string {
	sum := sha256.Sum256(cert.Certificate[0])
	return "sha256:" + hex.EncodeToString(sum[:])
}

// PinnedClient returns an HTTP client that only talks to a server whose leaf
// certificate matches fingerprint ("sha256:<hex>").
func PinnedClient(fingerprint string, timeout time.Duration) (*http.Client, error) {
	want, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(fingerprint)), "sha256:")
	if !ok || len(want) != 64 {
		return nil, errors.New("fingerprint must look like sha256:<64 hex characters>")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			// Chain validation is replaced by the pin below.
			InsecureSkipVerify: true, //nolint:gosec // pinned in VerifyPeerCertificate
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return errors.New("no server certificate")
				}
				sum := sha256.Sum256(raw[0])
				if got := hex.EncodeToString(sum[:]); got != want {
					return fmt.Errorf("controller certificate fingerprint mismatch: got sha256:%s", got)
				}
				return nil
			},
		},
		Proxy: nil, // never send probe traffic through a proxy
	}
	return &http.Client{Transport: tr, Timeout: timeout}, nil
}
