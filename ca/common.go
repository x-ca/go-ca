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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"regexp"
	"strings"
)

// Common CA constants
const (
	DefaultKeyType = "ec"
	DefaultKeyBits = 2048
	DefaultCurve   = "P256"

	RootCertCountry            = "CN"
	RootCertOrganization       = "X CA"
	RootCertOrganizationalUnit = "www.xiexianbin.cn"
	RootCertCN                 = "X Root CA - R1"
	RootCertYears              = 60

	XCARootPath = "XCA_ROOT_PATH"
)

// domainRegexp matches a hostname or domain with an optional leading "*."
// wildcard. Each label must be non-empty, alphanumeric, and may contain
// interior hyphens but must not start or end with one.
var domainRegexp = regexp.MustCompile(`^(\*\.)?([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])(\.([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9]))*$`)

// ValidateKeyCertMatch validates that a private key matches a certificate
func ValidateKeyCertMatch(privateKey any, cert *x509.Certificate) error {
	var pubKey crypto.PublicKey
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		pubKey = k.Public()
	case *ecdsa.PrivateKey:
		pubKey = k.Public()
	default:
		return fmt.Errorf("unsupported key type")
	}

	keyPKBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return err
	}

	certPKBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}

	if !bytes.Equal(keyPKBytes, certPKBytes) {
		return fmt.Errorf("public key in certificate doesn't match private key")
	}

	return nil
}

// CheckFileExists checks if a file exists
func CheckFileExists(filePath string) (bool, error) {
	_, err := os.Stat(filePath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// validateSafeName rejects names that are unsafe to embed in filesystem paths.
// It blocks empty input, path separators (/ and \), traversal sequences (..),
// and NUL bytes — the components a crafted commonName could use to escape its
// target directory.
func validateSafeName(name string) error {
	if name == "" {
		return fmt.Errorf("empty name")
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("name %q must not contain path separators", name)
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("name %q must not contain traversal sequences", name)
	}
	if strings.ContainsRune(name, 0) {
		return fmt.Errorf("name %q must not contain NUL bytes", name)
	}
	return nil
}

// randSerial returns a fixed positive serial when x > 0, otherwise a
// cryptographically random serial in [0, math.MaxInt64). RFC 5280 requires
// serial numbers to be positive and unique.
func randSerial(x int64) (*big.Int, error) {
	if x > 0 {
		return big.NewInt(x), nil
	}

	b, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return b, nil
}

func calculateKeyID(pubKey crypto.PublicKey) ([]byte, error) {
	pkixByte, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	var pkiInfo struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(pkixByte, &pkiInfo)
	if err != nil {
		return nil, err
	}
	skid := sha1.Sum(pkiInfo.SubjectPublicKey.Bytes)
	return skid[:], nil
}

// ParseDomains parses and validates a list of domain names. Empty entries are
// skipped. Any invalid entry returns an error naming the offender.
func ParseDomains(domainStr []string) ([]string, error) {
	var domainSlice []string
	for _, s := range domainStr {
		if s == "" {
			continue
		}
		if !domainRegexp.MatchString(s) {
			return nil, fmt.Errorf("invalid domain %q", s)
		}
		domainSlice = append(domainSlice, s)
	}

	return domainSlice, nil
}

// ParseIPs parses and validates a list of IP addresses. Empty entries are
// skipped. Any invalid entry returns an error naming the offender.
func ParseIPs(ipStr []string) ([]net.IP, error) {
	var ipSlice []net.IP
	for _, s := range ipStr {
		if s == "" {
			continue
		}
		p := net.ParseIP(s)
		if p == nil {
			return nil, fmt.Errorf("invalid IP %q", s)
		}
		ipSlice = append(ipSlice, p)
	}
	return ipSlice, nil
}

func GetEnvDefault(key, defVal string) string {
	val, ex := os.LookupEnv(key)
	if !ex {
		return defVal
	}
	return val
}
