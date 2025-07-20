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
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "xca",
	Short: "X Certificate Authority management tool",
	Long: `XCA is a command-line tool for creating and managing Root/Second-Level Certificate Authorities (CAs)
and signing certificates for domains and IP addresses.

Available Commands:
  create-ca   Create root and TLS CA certificates
	info        Display information about Certificates
  sign        Sign a certificate for domains and/or IPs
  version     Show version information

Environment:
  XCA_ROOT_PATH  Which path to store Root/Second-Level/TLS cert, default is "$(pwd)/x-ca"

Examples:
  xca create-ca --key-type ec --curve P256
  xca sign example.com --domains "example.com,www.example.com"
  xca sign 192.168.1.1 --ips "192.168.1.1"

Source Code:
  https://github.com/x-ca/go-ca	`,
	Run: func(cmd *cobra.Command, args []string) {
		// If no subcommand, show help
		cmd.Help()
	},
}

func init() {
	// Add subcommands
	rootCmd.AddCommand(createCaCmd)
	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(versionCmd)
}

func initCommands() {
	initCreateCACmd()
	initSignCmd()
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
