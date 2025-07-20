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
	"sort"
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

type TLSCA struct {
	Key     any // *rsa.PrivateKey or *ecdsa.PrivateKey
	Cert    *x509.Certificate
	KeyBits int    // 1024 * 2^x
	Curve   string // P224, P256, P384, P521

	RootCert *x509.Certificate
	RootKey  any // *rsa.PrivateKey or *ecdsa.PrivateKey
}

// NewTLSCA create new tls CA
func NewTLSCA(keyType string, keyBits int, curve string, rootCert *x509.Certificate, rootKey any) (*TLSCA, error) {
	tlsCA := &TLSCA{
		KeyBits: keyBits,
		Curve:   curve,
	}
	if rootCert != nil {
		tlsCA.RootCert = rootCert
	}
	if rootKey != nil {
		tlsCA.RootKey = rootKey
	}

	if err := tlsCA.CreateKey(keyType); err != nil {
		return nil, err
	}

	if err := tlsCA.CreateCert(); err != nil {
		return nil, err
	}

	return tlsCA, nil
}

// LoadTLSCA create new tls CA
func LoadTLSCA(keyPath, certPath, password string) (*TLSCA, error) {
	keyBytes, kErr := os.ReadFile(keyPath)
	certBytes, cErr := os.ReadFile(certPath)
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
	 *
	 * Note: The deprecated x509.IsEncryptedPEMBlock and x509.DecryptPEMBlock functions
	 * have been replaced with direct PEM header checking
	 */
	var key any
	var err error

	// Check if the PEM block is encrypted by checking for headers
	isEncrypted := len(keyBlock.Headers) > 0 && keyBlock.Headers["Proc-Type"] == "4,ENCRYPTED"
	if isEncrypted {
		// Since x509.DecryptPEMBlock is deprecated, we recommend users decrypt their keys first
		return nil, fmt.Errorf("encrypted PEM blocks are not supported - please decrypt your key first using: openssl rsa -in encrypted.key -out decrypted.key")
	}

	// Parse the unencrypted key
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	default:
		return nil, fmt.Errorf("unsupport PEM type %s", keyBlock.Type)
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
	var pubKey any
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pubKey = k.Public()
	case *ecdsa.PrivateKey:
		pubKey = k.Public()
	}
	keyPKBytes, keyPKErr := x509.MarshalPKIXPublicKey(pubKey)
	if keyPKErr != nil {
		return nil, keyPKErr
	}
	certPKBytes, certPKErr := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if certPKErr != nil {
		return nil, certPKErr
	}
	if !bytes.Equal(keyPKBytes, certPKBytes) {
		return nil, fmt.Errorf("public key in CA certificate %s don't match private key in %s", certPath, keyPath)
	}

	tlsCA := &TLSCA{
		Key:  key,
		Cert: cert,
	}

	return tlsCA, nil
}

// CreateKey create tls key
func (c *TLSCA) CreateKey(keyType string) error {
	switch strings.ToLower(keyType) {
	case "ec", "ecdsa":
		var curve elliptic.Curve
		switch c.Curve {
		case "P224":
			curve = elliptic.P224()
		case "P256":
			curve = elliptic.P256()
		case "P384":
			curve = elliptic.P384()
		case "P521":
			curve = elliptic.P521()
		default:
			return fmt.Errorf("unsupport curve %s", c.Curve)
		}
		tlsKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return err
		}
		c.Key = tlsKey
	case "rsa":
		tlsKey, err := rsa.GenerateKey(rand.Reader, c.KeyBits)
		if err != nil {
			return err
		}
		c.Key = tlsKey
	default:
		return fmt.Errorf("unsupport key type %s", keyType)
	}
	return nil
}

// CreateCert create tls cert
func (c *TLSCA) CreateCert() error {
	tlsCSR := &x509.Certificate{
		Version:      3,
		SerialNumber: randSerial(2), // default tls serial number is 2
		Subject: pkix.Name{
			Country:            []string{tlsCertCountry},
			Organization:       []string{tlsCertOrganization},
			OrganizationalUnit: []string{tlsCertOrganizationalUnit},
			CommonName:         tlsCertCN,
		},

		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(tlsCertYears, 0, 0),

		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	var pubKey any
	switch k := c.Key.(type) {
	case *rsa.PrivateKey:
		pubKey = k.Public()
	case *ecdsa.PrivateKey:
		pubKey = k.Public()
	}

	der, err := x509.CreateCertificate(rand.Reader, tlsCSR, c.RootCert, pubKey, c.RootKey)
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
func (c *TLSCA) Write(keyPath, certPath, chainPath string) error {
	var err error
	// mkdir
	err = os.MkdirAll(path.Dir(keyPath), 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}

	err = os.MkdirAll(path.Dir(certPath), 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}

	// write key
	keyFile, err := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	var keyType string
	var keyBytes []byte
	switch k := c.Key.(type) {
	case *rsa.PrivateKey:
		keyType = "RSA PRIVATE KEY"
		keyBytes = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		keyType = "EC PRIVATE KEY"
		keyBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return err
		}
	}

	err = pem.Encode(keyFile, &pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	})
	if err != nil {
		return err
	}

	// write cert
	certFile, err := os.OpenFile(certPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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

	// write chain
	chainFile, err := os.OpenFile(chainPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer chainFile.Close()

	// root cert
	err = pem.Encode(chainFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.RootCert.Raw,
	})
	if err != nil {
		return err
	}

	// tsl cert
	err = pem.Encode(chainFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Cert.Raw,
	})
	if err != nil {
		return err
	}

	return nil
}

func (c *TLSCA) Sign(commonName string, domains []string, ips []net.IP, days int, keyType string, keyBits int, curve string) (any, *x509.Certificate, error) {
	if keyBits%1024 != 0 {
		keyBits = 1024 * 4
	}
	if days/365 > tlsCertYears || days > MaxTLSDays {
		days = MaxTLSDays
	}

	// generate key
	var key any
	var err error
	switch strings.ToLower(keyType) {
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
			return nil, nil, fmt.Errorf("unsupport curve %s", curve)
		}
		key, err = ecdsa.GenerateKey(ecCurve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, keyBits)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("unsupport key type %s", keyType)
	}

	// create csr
	csr := &x509.Certificate{
		Version:      3,
		SerialNumber: randSerial(0),
		Subject: pkix.Name{
			CommonName: commonName,
		},

		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, days),

		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
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
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, nil
}

func (c *TLSCA) WriteCert(commonName string, key any, cert *x509.Certificate, tlsChainPath string) error {
	// mkdir
	var dir = strings.Replace(commonName, "*.", "", -1)
	err := os.MkdirAll(fmt.Sprintf("x-ca/certs/%s", dir), 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}

	// write key
	keyPath := fmt.Sprintf("x-ca/certs/%s/%s.key", dir, commonName)
	keyFile, err := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	var keyType string
	var keyBytes []byte
	switch k := key.(type) {
	case *rsa.PrivateKey:
		keyType = "RSA PRIVATE KEY"
		keyBytes = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		keyType = "EC PRIVATE KEY"
		keyBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return err
		}
	}

	err = pem.Encode(keyFile, &pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	})
	if err != nil {
		return err
	}

	// write cert
	certPath := fmt.Sprintf("x-ca/certs/%s/%s.crt", dir, commonName)
	certFile, err := os.OpenFile(certPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if err != nil {
		return err
	}

	// write cert chain
	certChainPath := fmt.Sprintf("x-ca/certs/%s/%s.bundle.crt", dir, commonName)
	certChainFile, err := os.OpenFile(certChainPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer certChainFile.Close()

	certBytes, err := os.ReadFile(certPath)
	if err == nil {
		_, err := certChainFile.Write(certBytes)
		if err != nil {
			return err
		}
	}
	chainBytes, err := os.ReadFile(tlsChainPath)
	if err == nil {
		_, err := certChainFile.Write(chainBytes)
		if err != nil {
			return err
		}
	}

	// print
	fmt.Println("write cert to", fmt.Sprintf("./x-ca/certs/%s/{%s.key,%s.crt,%s.bundle.crt}", commonName, commonName, commonName, commonName))

	return nil
}
