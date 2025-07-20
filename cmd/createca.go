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

	"github.com/spf13/cobra"

	"go.xiexianbin.cn/x-ca/ca"
)

var (
	createCaRootCert string
	createCaRootKey  string
	createCaTlsCert  string
	createCaTlsKey   string
	createCaTlsChain string
	createCaKeyType  string
	createCaKeyBits  int
	createCaCurve    string
)

// createCaCmd represents the create-ca command
var createCaCmd = &cobra.Command{
	Use:   "create-ca",
	Short: "Create root and TLS CA certificates",
	Long: `Create a new root CA and TLS CA with the specified parameters.

Examples:
  xca create-ca --key-type ec --curve P256
  xca create-ca --root-cert custom-root.crt --root-key custom-root.key
  xca create-ca --key-type rsa --key-bits 4096`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runCreateCa(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func initCreateCACmd() {
	createCaCmd.Flags().StringVar(&createCaRootCert, "root-cert", "x-ca/ca/root-ca.crt", "Root certificate file path")
	createCaCmd.Flags().StringVar(&createCaRootKey, "root-key", "x-ca/ca/root-ca/private/root-ca.key", "Root private key file path")
	createCaCmd.Flags().StringVar(&createCaTlsCert, "tls-cert", "x-ca/ca/tls-ca.crt", "TLS certificate file path")
	createCaCmd.Flags().StringVar(&createCaTlsKey, "tls-key", "x-ca/ca/tls-ca/private/tls-ca.key", "TLS private key file path")
	createCaCmd.Flags().StringVar(&createCaTlsChain, "tls-chain", "x-ca/ca/tls-ca-chain.pem", "TLS CA chain file path")
	createCaCmd.Flags().StringVar(&createCaKeyType, "key-type", "rsa", "Key type (rsa or ec)")
	createCaCmd.Flags().IntVar(&createCaKeyBits, "key-bits", ca.DefaultKeyBits, "RSA key bits")
	createCaCmd.Flags().StringVar(&createCaCurve, "curve", ca.DefaultCurve, "EC curve (P224, P256, P384, P521)")
}

func runCreateCa() error {
	// Check if files already exist
	files := []string{createCaRootKey, createCaRootCert, createCaTlsKey, createCaTlsCert}
	for _, file := range files {
		if exists, _ := ca.CheckFileExists(file); exists {
			return fmt.Errorf("%s already exists", file)
		}
	}

	// Create root CA
	rootCA, err := ca.NewRootCA(createCaKeyType, createCaKeyBits, createCaCurve)
	if err != nil {
		return fmt.Errorf("failed to create root CA: %w", err)
	}

	// Write root CA
	if err := rootCA.Write(createCaRootKey, createCaRootCert, ""); err != nil {
		return fmt.Errorf("failed to write root CA: %w", err)
	}

	// Create TLS CA
	tlsCA, err := ca.NewTLSCA(createCaKeyType, createCaKeyBits, createCaCurve, rootCA.Cert, rootCA.Key)
	if err != nil {
		return fmt.Errorf("failed to create TLS CA: %w", err)
	}

	// Write TLS CA
	if err := tlsCA.Write(createCaTlsKey, createCaTlsCert, createCaTlsChain); err != nil {
		return fmt.Errorf("failed to write TLS CA: %w", err)
	}

	fmt.Println("Successfully created root and TLS CA certificates")
	return nil
}
