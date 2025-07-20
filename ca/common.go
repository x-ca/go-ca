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
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
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

// CreateCertificateChain writes a certificate chain to file
func CreateCertificateChain(chainPath string, certs ...*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("no certificates provided")
	}

	// Create directory if it doesn't exist
	err := os.MkdirAll(path.Dir(chainPath), 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}

	chainFile, err := os.OpenFile(chainPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer chainFile.Close()

	for _, cert := range certs {
		err = pem.Encode(chainFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

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
	_, err := os.ReadFile(filePath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// EnsureDirectory creates a directory if it doesn't exist
func EnsureDirectory(dirPath string) error {
	return os.MkdirAll(dirPath, 0700)
}

// CreateFile creates a file with exclusive creation mode
func CreateFile(filePath string) (*os.File, error) {
	return os.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}

func randSerial(x int64) *big.Int {
	if x > 0 {
		return big.NewInt(x)
	}

	b, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return big.NewInt(1)
	}
	return b
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

func ParseDomains(domainStr []string) ([]string, error) {
	var domainSlice []string
	re := regexp.MustCompile("^[A-Za-z0-9-.*]+$")
	for _, s := range domainStr {
		if re.MatchString(s) {
			domainSlice = append(domainSlice, s)
		}
	}

	return domainSlice, nil
}

func ParseIPs(ipStr []string) (ipSlice []net.IP, err error) {
	for _, s := range ipStr {
		if len(s) == 0 {
			continue
		}
		p := net.ParseIP(s)
		if p == nil {
			return nil, fmt.Errorf("invalid IP %s", s)
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

func ExecPath() (string, error) {
	ex, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(ex), nil
}
