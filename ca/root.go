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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"time"
)

const (
	rootCertCountry            = "CN"
	rootCertOrganization       = "X CA"
	rootCertOrganizationalUnit = "www.xiexianbin.cn"
	rootCertCN                 = "X Root CA - R1"
	rootCertYears              = 60
)

var (
	// sort.StringsAreSorted(supportPemType) == true
	supportPemType = []string{"ECDSA PRIVATE KEY", "RSA PRIVATE KEY"}
)

type RootCA struct {
	Key     *rsa.PrivateKey
	Cert    *x509.Certificate
	KeyBits int // 1024 * 2^x
}

// NewRootCA create new root CA
func NewRootCA(keyBits int) (*RootCA, error) {
	rootCA := &RootCA{
		KeyBits: keyBits,
	}

	if err := rootCA.CreateKey(); err != nil {
		return nil, err
	}

	if err := rootCA.CreateCert(); err != nil {
		return nil, err
	}

	return rootCA, nil
}

// LoadRootCA create new tls CA
func LoadRootCA(keyPath, certPath, password string) (*RootCA, error) {
	keyBytes, kErr := ioutil.ReadFile(keyPath)
	certBytes, cErr := ioutil.ReadFile(certPath)
	if kErr != nil {
		return nil, kErr
	} else if cErr != nil {
		return nil, cErr
	}

	// parse key
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return nil, fmt.Errorf("decode key is nil")
	} else if supportPemType[sort.SearchStrings(supportPemType, keyBlock.Type)] != keyBlock.Type {
		return nil, fmt.Errorf("unsupport PEM type %s", keyBlock.Type)
	}

	/* Fix x-ca/ca root/tls key Problem
	 * https://github.com/x-ca/ca/blob/f82f6cc529662d5a751b79d87698a13c65f342ec/etc/root-ca.conf#L15
	 * https://security.stackexchange.com/questions/93417/what-encryption-is-applied-on-a-key-generated-by-openssl-req
	 * https://rfc-editor.org/rfc/rfc1423.html
	 * openssl asn1parse -in root-ca.key -i | cut -c-90
	 * - golang code
	 *
	 * if x509.IsEncryptedPEMBlock(keyBlock) == true {
	 *    der, err := x509.DecryptPEMBlock(keyBlock, []byte("pwd"))
	 *    key, _ = x509.ParsePKCS1PrivateKey(der)
	 * } else {
	 *    key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	 * }
	 *
	 * Raise error: `Error: fromPEMBytes: x509: no DEK-Info header in block`
	 *
	 * - fix run: `openssl rsa -in root-ca.key -des3`
	 */
	var key *rsa.PrivateKey
	var err error
	if x509.IsEncryptedPEMBlock(keyBlock) == true {
		der, err := x509.DecryptPEMBlock(keyBlock, []byte(password))
		if err != nil {
			return nil, err
		}
		key, _ = x509.ParsePKCS1PrivateKey(der)
	} else {
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("load private key %s, error %s", keyPath, err)
	}

	// parse cert
	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		return nil, fmt.Errorf("decode cert is nil")
	} else if certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unsupport PEM type %s", certBlock.Type)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate %s, error %s", certPath, err)
	}

	// compare key and cert match?
	keyPKBytes, keyPKErr := x509.MarshalPKIXPublicKey(key.Public())
	if keyPKErr != nil {
		return nil, keyPKErr
	}
	certPKBytes, certPKErr := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if certPKErr != nil {
		return nil, certPKErr
	}
	if bytes.Compare(keyPKBytes, certPKBytes) != 0 {
		return nil, fmt.Errorf("public key in CA certificate %s don't match private key in %s", certPath, keyPath)
	}

	rootCA := &RootCA{
		Key:  key,
		Cert: cert,
	}

	return rootCA, nil
}

// CreateKey create root key
func (c *RootCA) CreateKey() error {
	rootKey, err := rsa.GenerateKey(rand.Reader, c.KeyBits)
	if err != nil {
		return err
	}
	c.Key = rootKey
	return nil
}

// CreateCert create root cert
func (c *RootCA) CreateCert() error {
	rootKeyID, err := calculateKeyID(c.Key.Public())
	if err != nil {
		return err
	}

	rootCSR := &x509.Certificate{
		Version:      3,
		SerialNumber: randSerial(1), // default tls serial number is 1
		Subject: pkix.Name{
			Country:            []string{rootCertCountry},
			Organization:       []string{rootCertOrganization},
			OrganizationalUnit: []string{rootCertOrganizationalUnit},
			CommonName:         rootCertCN,
		},

		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(rootCertYears, 0, 0),

		SubjectKeyId:          rootKeyID,
		AuthorityKeyId:        rootKeyID,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, rootCSR, rootCSR, c.Key.Public(), c.Key)
	if err != nil {
		return err
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	c.Cert = certificate
	return nil
}

// Write root key/cert to file
func (c *RootCA) Write(rootCAKeyPath, rootCACertPath, chainPath string) error {
	var err error
	// mkdir
	err = os.MkdirAll(path.Dir(rootCAKeyPath), 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}

	err = os.MkdirAll(path.Dir(rootCACertPath), 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}

	// write key
	keyFile, err := os.OpenFile(rootCAKeyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	err = pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(c.Key),
	})
	if err != nil {
		return err
	}

	// write cert
	certFile, err := os.OpenFile(rootCACertPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Cert.Raw,
	})
	if err != nil {
		return err
	}

	return nil
}
