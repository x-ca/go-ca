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
	"fmt"
	"os"
	"path"
	"strings"
)

type CA interface {
	GenerateKey() error
	CreateCert() error
	Write(keyPath, certPath, chainPath string) error
	//Load(keyPath, certPath string) (any, error)
}

// BaseCA represents common functionality for all CA types
type BaseCA struct {
	Key     any // *rsa.PrivateKey or *ecdsa.PrivateKey
	Cert    *x509.Certificate
	KeyBits int
	Curve   string
}

// GenerateKey generates a new private key based on key type
func (b *BaseCA) GenerateKey(keyType string) error {
	switch strings.ToLower(keyType) {
	case "ec", "ecdsa":
		var curve elliptic.Curve
		switch b.Curve {
		case "P224":
			curve = elliptic.P224()
		case "P256":
			curve = elliptic.P256()
		case "P384":
			curve = elliptic.P384()
		case "P521":
			curve = elliptic.P521()
		default:
			return fmt.Errorf("unsupported curve %s", b.Curve)
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return err
		}
		b.Key = key
	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, b.KeyBits)
		if err != nil {
			return err
		}
		b.Key = key
	default:
		return fmt.Errorf("unsupported key type %s", keyType)
	}
	return nil
}

// GetPublicKey extracts the public key from the private key
func (b *BaseCA) GetPublicKey() (any, error) {
	switch k := b.Key.(type) {
	case *rsa.PrivateKey:
		return k.Public(), nil
	case *ecdsa.PrivateKey:
		return k.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
}

// WriteKey writes the private key to a PEM file
func (b *BaseCA) WriteKey(keyPath string) error {
	// Create directory if it doesn't exist
	err := os.MkdirAll(path.Dir(keyPath), 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}

	keyFile, err := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	var keyType string
	var keyBytes []byte
	switch k := b.Key.(type) {
	case *rsa.PrivateKey:
		keyType = "RSA PRIVATE KEY"
		keyBytes = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		keyType = "EC PRIVATE KEY"
		var err error
		keyBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported key type")
	}

	return pem.Encode(keyFile, &pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	})
}

// WriteCert writes the certificate to a PEM file
func (b *BaseCA) WriteCert(certPath string) error {
	// Create directory if it doesn't exist
	err := os.MkdirAll(path.Dir(certPath), 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}

	certFile, err := os.OpenFile(certPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer certFile.Close()

	return pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: b.Cert.Raw,
	})
}

// LoadKey loads a private key from a PEM file
func (b *BaseCA) LoadKey(keyPath string) error {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}

	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return fmt.Errorf("decode key is nil")
	}

	// Check if encrypted
	isEncrypted := len(keyBlock.Headers) > 0 && keyBlock.Headers["Proc-Type"] == "4,ENCRYPTED"
	if isEncrypted {
		return fmt.Errorf("encrypted PEM blocks are not supported - please decrypt your key first, using: openssl rsa -in encrypted.key -out decrypted.key")
	}

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		b.Key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		b.Key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	default:
		return fmt.Errorf("unsupported PEM type %s", keyBlock.Type)
	}
	return err
}

// LoadCert loads a certificate from a PEM file
func (b *BaseCA) LoadCert(certPath string) error {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}

	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		return fmt.Errorf("decode cert is nil")
	} else if certBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("unsupported PEM type %s", certBlock.Type)
	}

	b.Cert, err = x509.ParseCertificate(certBlock.Bytes)
	return err
}
