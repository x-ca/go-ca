/*
Copyright © 2022 xiexianbin.cn
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCreateLoadSignE2E exercises the full Root → TLS → leaf flow on EC keys,
// reloads the TLS CA from disk, and verifies the leaf cert's key usage.
func TestCreateLoadSignE2E(t *testing.T) {
	rootCA, err := NewRootCA("ec", 0, "P256")
	if err != nil {
		t.Fatalf("NewRootCA: %v", err)
	}

	tlsCA, err := NewTLSCA("ec", 0, "P256", rootCA.Cert, rootCA.Key)
	if err != nil {
		t.Fatalf("NewTLSCA: %v", err)
	}
	if !tlsCA.Cert.IsCA {
		t.Fatal("tls cert should be CA")
	}
	if tlsCA.Cert.SubjectKeyId == nil {
		t.Error("tls cert should have SubjectKeyId (S4)")
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tls-ca.key")
	certPath := filepath.Join(dir, "tls-ca.crt")
	chainPath := filepath.Join(dir, "tls-ca-chain.pem")
	if err := tlsCA.Write(keyPath, certPath, chainPath); err != nil {
		t.Fatalf("tlsCA.Write: %v", err)
	}

	// load back
	loaded, err := LoadTLSCA(keyPath, certPath)
	if err != nil {
		t.Fatalf("LoadTLSCA: %v", err)
	}
	if err := ValidateKeyCertMatch(loaded.Key, loaded.Cert); err != nil {
		t.Fatalf("ValidateKeyCertMatch after reload: %v", err)
	}

	// sign an EC leaf
	leafKey, leafCert, err := tlsCA.Sign("example.com",
		[]string{"example.com", "*.example.com"}, nil, 365, "ec", 0, "P256")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if leafCert.IsCA {
		t.Error("leaf cert should not be CA")
	}
	if leafCert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		t.Error("EC leaf should not have KeyEncipherment (S1)")
	}
	if leafCert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("EC leaf should have DigitalSignature")
	}

	// write leaf and verify bundle = leaf + root + tls (3 certs)
	if err := tlsCA.WriteSignedCert(dir, "example.com", leafKey, leafCert, chainPath); err != nil {
		t.Fatalf("WriteSignedCert: %v", err)
	}
	bundle, err := os.ReadFile(filepath.Join(dir, "certs", "example.com", "example.com.bundle.crt"))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if n := strings.Count(string(bundle), "BEGIN CERTIFICATE"); n != 3 {
		t.Errorf("bundle has %d certs, want 3 (leaf+root+tls)", n)
	}
}

func TestRSALeafKeyUsage(t *testing.T) {
	rootCA, err := NewRootCA("rsa", 2048, "")
	if err != nil {
		t.Fatalf("NewRootCA: %v", err)
	}
	tlsCA, err := NewTLSCA("rsa", 2048, "", rootCA.Cert, rootCA.Key)
	if err != nil {
		t.Fatalf("NewTLSCA: %v", err)
	}
	_, cert, err := tlsCA.Sign("rsa.example.com", []string{"rsa.example.com"}, nil, 365, "rsa", 2048, "")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("RSA leaf should have KeyEncipherment")
	}
}

func TestLoadTLSCADetectsMismatch(t *testing.T) {
	rootCA, _ := NewRootCA("ec", 0, "P256")
	a, _ := NewTLSCA("ec", 0, "P256", rootCA.Cert, rootCA.Key)
	b, _ := NewTLSCA("ec", 0, "P256", rootCA.Cert, rootCA.Key)

	dir := t.TempDir()
	if err := a.WriteKey(filepath.Join(dir, "k.key")); err != nil {
		t.Fatalf("WriteKey: %v", err)
	}
	if err := b.WriteCert(filepath.Join(dir, "k.crt")); err != nil {
		t.Fatalf("WriteCert: %v", err)
	}
	if _, err := LoadTLSCA(filepath.Join(dir, "k.key"), filepath.Join(dir, "k.crt")); err == nil {
		t.Fatal("expected key/cert mismatch error, got nil")
	}
}

// TestLoadKeyAcceptsECDSAPEMType verifies B1: a PEM block whose header is the
// "ECDSA PRIVATE KEY" variant (carrying the same SEC1 bytes) loads correctly.
func TestLoadKeyAcceptsECDSAPEMType(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: der})

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ecdsa.key")
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var b BaseCA
	if err := b.LoadKey(keyPath); err != nil {
		t.Fatalf("LoadKey should accept 'ECDSA PRIVATE KEY' PEM type (B1): %v", err)
	}
	if _, ok := b.Key.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", b.Key)
	}
}

func TestWriteSignedCertRespectsOutputDir(t *testing.T) {
	rootCA, _ := NewRootCA("ec", 0, "P256")
	tlsCA, _ := NewTLSCA("ec", 0, "P256", rootCA.Cert, rootCA.Key)

	dir := t.TempDir()
	chainPath := filepath.Join(dir, "tls-ca-chain.pem")
	if err := tlsCA.Write(filepath.Join(dir, "tls-ca.key"), filepath.Join(dir, "tls-ca.crt"), chainPath); err != nil {
		t.Fatalf("Write: %v", err)
	}

	customOut := filepath.Join(dir, "custom-ca")
	key, cert, err := tlsCA.Sign("foo.example.com", []string{"foo.example.com"}, nil, 100, "ec", 0, "P256")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := tlsCA.WriteSignedCert(customOut, "foo.example.com", key, cert, chainPath); err != nil {
		t.Fatalf("WriteSignedCert: %v", err)
	}
	want := filepath.Join(customOut, "certs", "foo.example.com", "foo.example.com.crt")
	if _, err := os.Stat(want); err != nil {
		t.Errorf("expected cert at %s, got %v (B3: output dir must be honored)", want, err)
	}
}

// TestSignCapsDaysAtMaxTLSDays verifies Sign silently caps validity at
// MaxTLSDays (825) — a security-relevant behavior that must not regress.
func TestSignCapsDaysAtMaxTLSDays(t *testing.T) {
	rootCA, _ := NewRootCA("ec", 0, "P256")
	tlsCA, _ := NewTLSCA("ec", 0, "P256", rootCA.Cert, rootCA.Key)

	_, cert, err := tlsCA.Sign("cap.example.com", []string{"cap.example.com"}, nil, 10000, "ec", 0, "P256")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// allow a 2h tolerance for test runtime
	upper := time.Now().Add(MaxTLSDays*24*time.Hour + 2*time.Hour)
	lower := time.Now().Add(MaxTLSDays*24*time.Hour - 2*time.Hour)
	if cert.NotAfter.After(upper) {
		t.Errorf("NotAfter %v exceeds MaxTLSDays cap (~%d days)", cert.NotAfter, MaxTLSDays)
	}
	if cert.NotAfter.Before(lower) {
		t.Errorf("NotAfter %v below MaxTLSDays cap (~%d days); days not capped as expected", cert.NotAfter, MaxTLSDays)
	}
}

// TestSignRSARoundsKeyBits verifies that non-multiples of 1024 are rewritten
// to 4096 for RSA leaf certs.
func TestSignRSARoundsKeyBits(t *testing.T) {
	rootCA, _ := NewRootCA("rsa", 2048, "")
	tlsCA, _ := NewTLSCA("rsa", 2048, "", rootCA.Cert, rootCA.Key)

	key, cert, err := tlsCA.Sign("round.example.com", []string{"round.example.com"}, nil, 30, "rsa", 1500, "")
	if err != nil {
		t.Fatalf("Sign with keyBits=1500: %v", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", key)
	}
	if rsaKey.N.BitLen() != 4096 {
		t.Errorf("rounded RSA key bits = %d, want 4096", rsaKey.N.BitLen())
	}
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		t.Errorf("cert public key type = %T, want *rsa.PublicKey", cert.PublicKey)
	}
}

// TestSignNegativePaths exercises Sign's own unsupported-curve and
// unsupported-key-type branches (independent of NewRootCA/NewTLSCA).
func TestSignNegativePaths(t *testing.T) {
	rootCA, _ := NewRootCA("ec", 0, "P256")
	tlsCA, _ := NewTLSCA("ec", 0, "P256", rootCA.Cert, rootCA.Key)

	t.Run("unsupported curve", func(t *testing.T) {
		if _, _, err := tlsCA.Sign("x", []string{"x.example.com"}, nil, 30, "ec", 0, "P999"); err == nil {
			t.Fatal("expected error for unsupported curve, got nil")
		}
	})
	t.Run("unsupported key type", func(t *testing.T) {
		if _, _, err := tlsCA.Sign("x", []string{"x.example.com"}, nil, 30, "dsa", 0, ""); err == nil {
			t.Fatal("expected error for unsupported key type, got nil")
		}
	})
}

// TestWriteSignedCertMissingChain verifies that a missing TLS chain file
// produces an error rather than a silently incomplete bundle.
func TestWriteSignedCertMissingChain(t *testing.T) {
	rootCA, _ := NewRootCA("ec", 0, "P256")
	tlsCA, _ := NewTLSCA("ec", 0, "P256", rootCA.Cert, rootCA.Key)
	key, cert, err := tlsCA.Sign("m.example.com", []string{"m.example.com"}, nil, 30, "ec", 0, "P256")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "does-not-exist", "chain.pem")
	if err := tlsCA.WriteSignedCert(t.TempDir(), "m.example.com", key, cert, missing); err == nil {
		t.Fatal("expected error for missing chain file, got nil")
	}
}

// TestWriteSignedCertRejectsTraversal verifies that a crafted commonName
// containing path separators or traversal sequences is rejected before any
// file is written.
func TestWriteSignedCertRejectsTraversal(t *testing.T) {
	rootCA, _ := NewRootCA("ec", 0, "P256")
	tlsCA, _ := NewTLSCA("ec", 0, "P256", rootCA.Cert, rootCA.Key)
	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain.pem")
	if err := tlsCA.Write(filepath.Join(dir, "k.key"), filepath.Join(dir, "k.crt"), chainPath); err != nil {
		t.Fatalf("Write: %v", err)
	}
	key, cert, err := tlsCA.Sign("ok.example.com", []string{"ok.example.com"}, nil, 30, "ec", 0, "P256")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	for _, bad := range []string{"../evil", "/etc/passwd", "a/b", "..", ""} {
		if err := tlsCA.WriteSignedCert(dir, bad, key, cert, chainPath); err == nil {
			t.Errorf("expected error for commonName %q, got nil", bad)
		}
	}
}

// TestWriteSignedCertWildcardDir verifies that a wildcard commonName
// (*.example.com) lands under certs/example.com/ (only the leading wildcard
// label is stripped).
func TestWriteSignedCertWildcardDir(t *testing.T) {
	rootCA, _ := NewRootCA("ec", 0, "P256")
	tlsCA, _ := NewTLSCA("ec", 0, "P256", rootCA.Cert, rootCA.Key)
	out := t.TempDir()
	chain := filepath.Join(out, "chain.pem")
	if err := tlsCA.Write(filepath.Join(out, "k.key"), filepath.Join(out, "k.crt"), chain); err != nil {
		t.Fatalf("Write: %v", err)
	}
	key, cert, err := tlsCA.Sign("*.example.com", []string{"*.example.com"}, nil, 30, "ec", 0, "P256")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := tlsCA.WriteSignedCert(out, "*.example.com", key, cert, chain); err != nil {
		t.Fatalf("WriteSignedCert: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "certs", "example.com", "*.example.com.crt")); err != nil {
		t.Errorf("expected wildcard cert at certs/example.com/: %v", err)
	}
}

// TestNewTLSCANilRoot confirms NewTLSCA rejects a nil root cert/key rather
// than producing a malformed self-signed TLS CA.
func TestNewTLSCANilRoot(t *testing.T) {
	if _, err := NewTLSCA("ec", 0, "P256", nil, nil); err == nil {
		t.Fatal("expected error when root cert/key are nil, got nil")
	}
}
