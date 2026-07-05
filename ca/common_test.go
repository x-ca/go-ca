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
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDomains(t *testing.T) {
	got, err := ParseDomains([]string{"www.xiexianbin.cn", "*.xiexianbin.cn", "localhost"})
	if err != nil {
		t.Fatalf("ParseDomains returned unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 domains, got %d (%v)", len(got), got)
	}
}

func TestParseDomainsInvalid(t *testing.T) {
	cases := []string{"-bad.com", "bad-.com", "a..b", "*", ".", "*foo.com", "ok..com"}
	for _, c := range cases {
		if _, err := ParseDomains([]string{c}); err == nil {
			t.Errorf("expected error for invalid domain %q, got nil", c)
		}
	}
}

func TestParseDomainsSkipsEmpty(t *testing.T) {
	got, err := ParseDomains([]string{"", "example.com", ""})
	if err != nil {
		t.Fatalf("ParseDomains returned unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 domain after skipping empties, got %d (%v)", len(got), got)
	}
}

func TestParseIPs(t *testing.T) {
	got, err := ParseIPs([]string{"1.1.1.1", "8.8.8.8", "::1"})
	if err != nil {
		t.Fatalf("ParseIPs returned unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 IPs, got %d", len(got))
	}
}

func TestParseIPsInvalid(t *testing.T) {
	if _, err := ParseIPs([]string{"not-an-ip"}); err == nil {
		t.Errorf("expected error for invalid IP, got nil")
	}
}

func TestParseIPsSkipsEmpty(t *testing.T) {
	got, err := ParseIPs([]string{"", "1.1.1.1"})
	if err != nil {
		t.Fatalf("ParseIPs returned unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 IP after skipping empties, got %d", len(got))
	}
}

func TestCheckFileExists(t *testing.T) {
	dir := t.TempDir()
	existing := dir + "/here"
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if ok, err := CheckFileExists(existing); err != nil || !ok {
		t.Errorf("existing file: ok=%v err=%v", ok, err)
	}
	if ok, err := CheckFileExists(dir + "/missing"); err != nil || ok {
		t.Errorf("missing file: ok=%v err=%v", ok, err)
	}
}

func TestLoadKeyRejectsEncryptedPEM(t *testing.T) {
	blk := &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Bytes:   []byte("dummy"),
		Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"},
	}
	p := filepath.Join(t.TempDir(), "enc.key")
	if err := os.WriteFile(p, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var b BaseCA
	err := b.LoadKey(p)
	if err == nil || !strings.Contains(err.Error(), "encrypted PEM blocks are not supported") {
		t.Errorf("expected encrypted-PEM rejection, got %v", err)
	}
}

func TestLoadKeyUnsupportedPEMType(t *testing.T) {
	blk := &pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")}
	p := filepath.Join(t.TempDir(), "weird.key")
	if err := os.WriteFile(p, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var b BaseCA
	if err := b.LoadKey(p); err == nil || !strings.Contains(err.Error(), "unsupported PEM type") {
		t.Errorf("expected unsupported-PEM-type error, got %v", err)
	}
}

func TestValidateKeyCertMatchUnsupportedKey(t *testing.T) {
	if err := ValidateKeyCertMatch(123, &x509.Certificate{}); err == nil ||
		!strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("expected unsupported key type error, got %v", err)
	}
}

func TestValidateSafeName(t *testing.T) {
	for _, bad := range []string{"", "../evil", "/etc/passwd", "a/b", "a\\b", "..", "a..b", "x\x00y"} {
		if err := validateSafeName(bad); err == nil {
			t.Errorf("expected error for %q, got nil", bad)
		}
	}
	for _, ok := range []string{"example.com", "*.example.com", "My Service", "localhost"} {
		if err := validateSafeName(ok); err != nil {
			t.Errorf("unexpected error for %q: %v", ok, err)
		}
	}
}
