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

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"github.com/x-ca/go-ca/ca"
)

var (
	createCa       bool
	rootKeyPath    string
	rootCertPath   string
	tlsKeyPath     string
	tlsCertPath    string
	tlsChainPath   string
	tlsKeyPassword string
	domainStr      string
	commonName     string
	domains        []string
	ipStr          string
	ips            []net.IP
	help           bool
)

func init() {
	flag.BoolVar(&createCa, "create-ca", false, "Create Root CA.")
	flag.StringVar(&rootKeyPath, "root-key", "x-ca/ca/root-ca/private/root-ca.key", "Root private key file path, PEM format.")
	flag.StringVar(&rootCertPath, "root-cert", "x-ca/ca/root-ca.crt", "Root certificate file path, PEM format.")
	flag.StringVar(&tlsKeyPath, "tls-key", "x-ca/ca/tls-ca/private/tls-ca.key", "Second-Level private key file path, PEM format.")
	flag.StringVar(&tlsCertPath, "tls-cert", "x-ca/ca/tls-ca.crt", "Second-Level certificate file path, PEM format.")
	flag.StringVar(&tlsChainPath, "tls-chain", "x-ca/ca/tls-ca-chain.pem", "Root/Second-Level CA Chain file path, PEM format.")
	flag.StringVar(&tlsKeyPassword, "tls-key-password", "", "tls key password, only work for load github.com/x-ca/x-ca.")
	flag.StringVar(&domainStr, "domains", "", "Comma-Separated domain names.")
	flag.StringVar(&commonName, "cn", "", "sign cert common name.")
	flag.StringVar(&ipStr, "ips", "", "Comma-Separated IP addresses.")
	flag.BoolVar(&help, "help", false, "show help message")

	flag.Parse()

	flag.Usage = func() {
		fmt.Print(`Create Root CA and TLS CA:
xca -create-ca true \
  -root-cert x-ca/ca/root-ca.crt \
  -root-key x-ca/ca/root-ca/private/root-ca.key \
  -tls-cert x-ca/ca/tls-ca.crt \
  -tls-key x-ca/ca/tls-ca/private/tls-ca.key \
  -tls-chain x-ca/ca/tls-ca-chain.pem

Sign Domains or Ips:
xca -cn xxxx \
  --domains "xxx,xxx" --ips "xxx,xxx" \
  -tls-cert x-ca/ca/tls-ca.crt \
  -tls-key x-ca/ca/tls-ca/private/tls-ca.key \
  -tls-chain x-ca/ca/tls-ca-chain.pem
`)
		fmt.Println()
		fmt.Println("Usage:")
		flag.PrintDefaults()
		fmt.Println()
		fmt.Println(`Source Code:
  https://github.com/x-ca/go-ca`)
	}
}

func check() error {
	// check domains and ips
	if createCa == false {
		if domainStr == "" && ipStr == "" {
			return fmt.Errorf("domains and ips is empty")
		}
		if _, err := ioutil.ReadFile(tlsKeyPath); err != nil {
			return err
		}
		if _, err := ioutil.ReadFile(tlsCertPath); err != nil {
			return err
		}
	}

	var err error
	// check domain
	domains, err = ca.ParseDomains(strings.Split(domainStr, ","))
	if err != nil {
		return err
	}

	// check ips
	ips, err = ca.ParseIPs(strings.Split(ipStr, ","))
	if err != nil {
		return err
	}

	return nil
}

func doCreateCa() error {
	var err error

	// if file is exist skip
	for _, path := range []string{rootKeyPath, rootCertPath, tlsKeyPath, tlsCertPath} {
		_, err := ioutil.ReadFile(path)
		if err != nil && os.IsNotExist(err) {
			continue
		} else {
			return fmt.Errorf("%s is already exist", path)
		}
	}

	// create
	rootCA, err := ca.NewRootCA(1024 * 4)
	if err != nil {
		return err
	}
	err = rootCA.Write(rootKeyPath, rootCertPath, "")
	if err != nil {
		return err
	}

	tlsca, err := ca.NewTLSCA(1024*4, rootCA.Cert, rootCA.Key)
	if err != nil {
		return err
	}
	err = tlsca.Write(tlsKeyPath, tlsCertPath, tlsChainPath)
	if err != nil {
		return err
	}

	return nil
}

func doSign() error {
	var err error

	tlsCA, err := ca.LoadTLSCA(tlsKeyPath, tlsCertPath, tlsKeyPassword)
	if err != nil {
		return err
	}

	key, cert, err := tlsCA.Sign(commonName, domains, ips, 825, 1024*4)
	if err != nil {
		return err
	}
	err = tlsCA.WriteCert(commonName, key, cert, tlsChainPath)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	if help == true || len(os.Args) == 1 {
		flag.Usage()
		return
	}

	// create CA
	if createCa == true {
		if err := doCreateCa(); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	} else {
		if err := check(); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		if err := doSign(); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	}
}
