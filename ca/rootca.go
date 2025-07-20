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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"
)

var (
	supportPemType = []string{"ECDSA PRIVATE KEY", "RSA PRIVATE KEY"}
)

// RootCA represents a root certificate authority
type RootCA struct {
	BaseCA
}

// NewRootCA creates a new root CA
func NewRootCA(keyType string, keyBits int, curve string) (*RootCA, error) {
	rootCA := &RootCA{
		BaseCA: BaseCA{
			KeyBits: keyBits,
			Curve:   curve,
		},
	}

	if err := rootCA.GenerateKey(keyType); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	if err := rootCA.CreateCert(); err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	return rootCA, nil
}

// LoadRootCA loads an existing root CA from files
func LoadRootCA(keyPath, certPath, password string) (*RootCA, error) {
	rootCA := &RootCA{
		BaseCA: BaseCA{},
	}

	if err := rootCA.LoadKey(keyPath); err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}

	if err := rootCA.LoadCert(certPath); err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	// Validate key and certificate match
	if err := ValidateKeyCertMatch(rootCA.Key, rootCA.Cert); err != nil {
		return nil, fmt.Errorf("key and certificate don't match: %w", err)
	}

	return rootCA, nil
}

// CreateCert creates the root CA certificate
func (c *RootCA) CreateCert() error {
	pubKey, err := c.GetPublicKey()
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	rootKeyID, err := calculateKeyID(pubKey)
	if err != nil {
		return fmt.Errorf("failed to calculate key ID: %w", err)
	}

	rootCSR := &x509.Certificate{
		Version:      3,
		SerialNumber: randSerial(1), // default root serial number is 1
		Subject: pkix.Name{
			Country:            []string{RootCertCountry},
			Organization:       []string{RootCertOrganization},
			OrganizationalUnit: []string{RootCertOrganizationalUnit},
			CommonName:         RootCertCN,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(RootCertYears, 0, 0),
		SubjectKeyId:          rootKeyID,
		AuthorityKeyId:        rootKeyID,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, rootCSR, rootCSR, pubKey, c.Key)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	c.Cert = cert
	return nil
}

// Write writes the root CA key and certificate to files
func (c *RootCA) Write(rootKeyPath, rootCertPath, chainPath string) error {
	if err := c.WriteKey(rootKeyPath); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	if err := c.WriteCert(rootCertPath); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	return nil
}
