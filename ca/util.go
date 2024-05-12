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
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math"
	"math/big"
	"net"
	"regexp"
)

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
		} else {
			return nil, fmt.Errorf("invalid domain %s", s)
		}
	}

	return domainSlice, nil
}

func ParseIPs(ipStr []string) ([]net.IP, error) {
	var ipSlice []net.IP
	for _, s := range ipStr {
		p := net.ParseIP(s)
		if p == nil {
			return nil, fmt.Errorf("invalid IP %s", s)
		}
		ipSlice = append(ipSlice, p)
	}
	return ipSlice, nil
}
