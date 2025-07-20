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
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"go.xiexianbin.cn/x-ca/ca"
)

var (
	signCommonName  string
	signDomains     string
	signIPs         string
	signTlsKey      string
	signTlsCert     string
	signTlsChain    string
	signKeyType     string
	signKeyBits     int
	signCurve       string
	signDays        int
	signKeyPassword string
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign [common-name]",
	Short: "Sign a certificate for domains and/or IPs",
	Long: `Sign a new certificate using the TLS CA for the specified common name and domains/IPs.

Examples:
  xca sign example.com --domains "example.com"
  xca sign api.example.com --domains "api.example.com,*.example.com"
  xca sign 192.168.1.1 --ips "192.168.1.1"
  xca sign multi.example.com --domains "example.com,www.example.com" --ips "10.0.0.1"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		signCommonName = args[0]
		if err := runSign(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func initSignCmd() {
	xcarootpath := ca.GetEnvDefault(ca.XCARootPath, "x-ca")
	signCmd.Flags().StringVar(&signDomains, "domains", "", "Comma-separated domain names")
	signCmd.Flags().StringVar(&signIPs, "ips", "", "Comma-separated IP addresses")
	signCmd.Flags().StringVar(&signTlsKey, "tls-key", xcarootpath+"/ca/tls-ca/private/tls-ca.key", "TLS CA private key file path")
	signCmd.Flags().StringVar(&signTlsCert, "tls-cert", xcarootpath+"/ca/tls-ca.crt", "TLS CA certificate file path")
	signCmd.Flags().StringVar(&signTlsChain, "tls-chain", xcarootpath+"/ca/tls-ca-chain.pem", "TLS CA chain file path")
	signCmd.Flags().StringVar(&signKeyType, "key-type", ca.DefaultKeyType, "Key type (rsa or ec)")
	signCmd.Flags().IntVar(&signKeyBits, "key-bits", ca.DefaultKeyBits, "RSA key bits")
	signCmd.Flags().StringVar(&signCurve, "curve", ca.DefaultCurve, "EC curve (P224, P256, P384, P521)")
	signCmd.Flags().IntVar(&signDays, "days", 825, "Certificate validity in days")
	signCmd.Flags().StringVar(&signKeyPassword, "tls-key-password", "", "TLS key password (if encrypted)")
}

func runSign() error {
	// Parse domains and IPs
	domainList, err := ca.ParseDomains(strings.Split(signDomains, ","))
	if err != nil {
		return fmt.Errorf("invalid domains: %w", err)
	}

	ipList, err := ca.ParseIPs(strings.Split(signIPs, ","))
	if err != nil {
		return fmt.Errorf("invalid IPs: %w", err)
	}

	if len(domainList) == 0 && len(ipList) == 0 {
		return fmt.Errorf("at least one domain or IP must be specified")
	}

	// Load TLS CA
	tlsCA, err := ca.LoadTLSCA(signTlsKey, signTlsCert, signKeyPassword)
	if err != nil {
		return fmt.Errorf("failed to load TLS CA: %w", err)
	}

	// Sign certificate
	key, cert, err := tlsCA.Sign(signCommonName, domainList, ipList, signDays, signKeyType, signKeyBits, signCurve)
	if err != nil {
		return fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Write certificate
	if err := tlsCA.WriteCert(signCommonName, key, cert, signTlsChain); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	fmt.Printf("Successfully signed certificate for %s\n", signCommonName)
	return nil
}
