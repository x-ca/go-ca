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
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"time"
)

const (
	tlsCertCountry            = "CN"
	tlsCertOrganization       = "X CA"
	tlsCertOrganizationalUnit = "www.xiexianbin.cn"
	tlsCertCN                 = "X TLS CA 1C1"
	tlsCertYears              = 20
	MaxTLSDays                = 825
)

// TLSCA embeds BaseCA for key/cert storage and IO, and adds the root CA that
// signs this second-level (intermediate) CA.
type TLSCA struct {
	BaseCA
	RootCert *x509.Certificate
	RootKey  any // *rsa.PrivateKey or *ecdsa.PrivateKey
}

// NewTLSCA create new tls CA
func NewTLSCA(keyType string, keyBits int, curve string, rootCert *x509.Certificate, rootKey any) (*TLSCA, error) {
	tlsCA := &TLSCA{
		BaseCA: BaseCA{
			KeyBits: keyBits,
			Curve:   curve,
		},
	}
	if rootCert != nil {
		tlsCA.RootCert = rootCert
	}
	if rootKey != nil {
		tlsCA.RootKey = rootKey
	}

	if err := tlsCA.GenerateKey(keyType); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	if err := tlsCA.CreateCert(); err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	return tlsCA, nil
}

// LoadTLSCA load TLS CA from key/cert files. Only unencrypted PEM keys are
// supported; decrypt encrypted keys with openssl first.
func LoadTLSCA(keyPath, certPath string) (*TLSCA, error) {
	tlsCA := &TLSCA{}

	if err := tlsCA.LoadKey(keyPath); err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}

	if err := tlsCA.LoadCert(certPath); err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	if err := ValidateKeyCertMatch(tlsCA.Key, tlsCA.Cert); err != nil {
		return nil, fmt.Errorf("key and certificate don't match: %w", err)
	}

	return tlsCA, nil
}

// CreateCert create tls cert signed by the root CA
func (c *TLSCA) CreateCert() error {
	pubKey, err := c.GetPublicKey()
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	keyID, err := calculateKeyID(pubKey)
	if err != nil {
		return fmt.Errorf("failed to calculate key ID: %w", err)
	}

	serial, err := randSerial(2) // default tls serial number is 2
	if err != nil {
		return fmt.Errorf("failed to generate serial: %w", err)
	}

	tlsCSR := &x509.Certificate{
		Version:      3,
		SerialNumber: serial,
		Subject: pkix.Name{
			Country:            []string{tlsCertCountry},
			Organization:       []string{tlsCertOrganization},
			OrganizationalUnit: []string{tlsCertOrganizationalUnit},
			CommonName:         tlsCertCN,
		},

		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(tlsCertYears, 0, 0),
		SubjectKeyId:          keyID,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tlsCSR, c.RootCert, pubKey, c.RootKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}
	c.Cert = certificate
	return nil
}

// Write writes the tls CA key, cert, and chain (root + tls) to files
func (c *TLSCA) Write(keyPath, certPath, chainPath string) error {
	if err := c.WriteKey(keyPath); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	if err := c.WriteCert(certPath); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// write chain
	if err := os.MkdirAll(path.Dir(chainPath), 0700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to create chain directory: %w", err)
	}

	chainFile, err := os.OpenFile(chainPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open chain file: %w", err)
	}
	defer chainFile.Close()

	// root cert then tls cert
	for _, cert := range []*x509.Certificate{c.RootCert, c.Cert} {
		if err := pem.Encode(chainFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			return fmt.Errorf("failed to encode chain: %w", err)
		}
	}

	return nil
}

func (c *TLSCA) Sign(commonName string, domains []string, ips []net.IP, days int, keyType string, keyBits int, curve string) (any, *x509.Certificate, error) {
	if days > MaxTLSDays {
		days = MaxTLSDays
	}

	keyTypeLower := strings.ToLower(keyType)
	// RSA key sizes are aligned to a multiple of 1024 bits; EC ignores keyBits.
	if keyTypeLower == "rsa" && keyBits%1024 != 0 {
		keyBits = 1024 * 4
	}

	// generate key
	var key any
	var err error
	var keyUsage x509.KeyUsage
	switch keyTypeLower {
	case "ec", "ecdsa":
		var ecCurve elliptic.Curve
		switch curve {
		case "P224":
			ecCurve = elliptic.P224()
		case "P256":
			ecCurve = elliptic.P256()
		case "P384":
			ecCurve = elliptic.P384()
		case "P521":
			ecCurve = elliptic.P521()
		default:
			return nil, nil, fmt.Errorf("unsupported curve %s", curve)
		}
		key, err = ecdsa.GenerateKey(ecCurve, rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate EC key: %w", err)
		}
		// EC keys do not perform key encipherment.
		keyUsage = x509.KeyUsageDigitalSignature
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, keyBits)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	default:
		return nil, nil, fmt.Errorf("unsupported key type %s", keyType)
	}

	serial, err := randSerial(0)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial: %w", err)
	}

	// create csr
	csr := &x509.Certificate{
		Version:      3,
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: commonName,
		},

		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, days),

		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	if len(domains) > 0 {
		csr.DNSNames = domains
	}
	if len(ips) > 0 {
		csr.IPAddresses = ips
	}

	var pubKey any
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pubKey = k.Public()
	case *ecdsa.PrivateKey:
		pubKey = k.Public()
	}

	// create cert
	der, err := x509.CreateCertificate(rand.Reader, csr, c.Cert, pubKey, c.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return key, cert, nil
}

// WriteSignedCert writes a signed leaf cert (key + crt + bundle) under outputDir/certs/<dir>.
// The bundle is the leaf followed by the TLS CA chain read from tlsChainPath.
// commonName flows into filesystem paths, so it is validated to reject path
// separators and traversal sequences.
func (c *TLSCA) WriteSignedCert(outputDir, commonName string, key any, cert *x509.Certificate, tlsChainPath string) error {
	if err := validateSafeName(commonName); err != nil {
		return fmt.Errorf("invalid common name: %w", err)
	}
	// strip a leading wildcard label so "*.example.com" lands under example.com/
	dir := strings.TrimPrefix(commonName, "*.")
	certDir := fmt.Sprintf("%s/certs/%s", strings.TrimRight(outputDir, "/"), dir)
	if err := os.MkdirAll(certDir, 0700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}

	// write key
	keyPath := fmt.Sprintf("%s/%s.key", certDir, commonName)
	keyFile, err := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key file: %w", err)
	}
	defer keyFile.Close()

	keyBlock, err := marshalPrivateKeyPEM(key)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}
	if err := pem.Encode(keyFile, keyBlock); err != nil {
		return fmt.Errorf("failed to encode key: %w", err)
	}

	// write cert
	certPath := fmt.Sprintf("%s/%s.crt", certDir, commonName)
	certFile, err := os.OpenFile(certPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open cert file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}); err != nil {
		return fmt.Errorf("failed to encode cert: %w", err)
	}

	// write cert chain: leaf + tls chain (root + tls)
	certChainPath := fmt.Sprintf("%s/%s.bundle.crt", certDir, commonName)
	certChainFile, err := os.OpenFile(certChainPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open chain file: %w", err)
	}
	defer certChainFile.Close()

	if err := pem.Encode(certChainFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}); err != nil {
		return fmt.Errorf("failed to encode leaf cert to chain: %w", err)
	}

	chainBytes, err := os.ReadFile(tlsChainPath)
	if err != nil {
		return fmt.Errorf("failed to read TLS chain %s: %w", tlsChainPath, err)
	}
	if _, err := certChainFile.Write(chainBytes); err != nil {
		return fmt.Errorf("failed to write TLS chain: %w", err)
	}

	fmt.Printf("write cert to %s/{%s.key,%s.crt,%s.bundle.crt}\n", certDir, commonName, commonName, commonName)

	return nil
}
