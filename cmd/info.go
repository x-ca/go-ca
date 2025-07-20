/*
Copyright © 2025 xiexianbin.cn
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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	certfilePath string
)

// OIDs for various X.509 extensions.
var (
	oidExtensionSubjectKeyId          = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtensionKeyUsage              = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtensionAuthorityKeyId        = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtensionSubjectAltName        = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionBasicConstraints      = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidExtensionCertificatePolicies   = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidAuthorityInfoAccess            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
)

// Maps OIDs to their string representations for better readability.
var oidToStringMap = map[string]string{
	"2.5.29.14":         "X509v3 Subject Key Identifier",
	"2.5.29.15":         "X509v3 Key Usage",
	"2.5.29.19":         "X509v3 Basic Constraints",
	"2.5.29.31":         "X509v3 CRL Distribution Points",
	"2.5.29.32":         "X509v3 Certificate Policies",
	"2.5.29.35":         "X509v3 Authority Key Identifier",
	"2.5.29.37":         "X509v3 Extended Key Usage",
	"2.5.29.17":         "X509v3 Subject Alternative Name",
	"1.3.6.1.5.5.7.1.1": "Authority Information Access",
}

func printCertificateInfo(cert *x509.Certificate) {
	fmt.Println("Certificate:")
	fmt.Println("    Data:")
	// Version
	fmt.Printf("        Version: %d (0x%x)\n", cert.Version, cert.Version-1)

	// Serial Number
	fmt.Printf("        Serial Number:\n            %s\n", formatSerialNumber(cert.SerialNumber))

	// Signature Algorithm
	fmt.Printf("        Signature Algorithm: %s\n", cert.SignatureAlgorithm.String())

	// Issuer
	fmt.Printf("        Issuer: %s\n", formatName(cert.Issuer))

	// Validity
	fmt.Println("        Validity")
	fmt.Printf("            Not Before: %s\n", cert.NotBefore.UTC().Format("Jan 2 15:04:05 2006 GMT"))
	fmt.Printf("            Not After : %s\n", cert.NotAfter.UTC().Format("Jan 2 15:04:05 2006 GMT"))

	// Subject
	fmt.Printf("        Subject: %s\n", formatName(cert.Subject))

	// Public Key
	fmt.Println("        Subject Public Key Info:")
	printPublicKeyInfo(cert.PublicKey)

	// Extensions
	if len(cert.Extensions) > 0 {
		fmt.Println("        X509v3 extensions:")
		printExtensions(cert)
	}

	// Signature
	fmt.Printf("    Signature Algorithm: %s\n", cert.SignatureAlgorithm.String())
	printHexBlock("         ", cert.Signature, 18)
}

func formatName(name pkix.Name) string {
	var parts []string
	if len(name.Country) > 0 {
		parts = append(parts, "C="+strings.Join(name.Country, ","))
	}
	if len(name.Province) > 0 {
		parts = append(parts, "ST="+strings.Join(name.Province, ","))
	}
	if len(name.Locality) > 0 {
		parts = append(parts, "L="+strings.Join(name.Locality, ","))
	}
	if len(name.Organization) > 0 {
		parts = append(parts, "O="+strings.Join(name.Organization, ","))
	}
	if len(name.OrganizationalUnit) > 0 {
		parts = append(parts, "OU="+strings.Join(name.OrganizationalUnit, ","))
	}
	if name.CommonName != "" {
		parts = append(parts, "CN="+name.CommonName)
	}
	return strings.Join(parts, ", ")
}

func formatSerialNumber(serial *big.Int) string {
	hex := fmt.Sprintf("%x", serial)
	if len(hex)%2 != 0 {
		hex = "0" + hex
	}
	var parts []string
	for i := 0; i < len(hex); i += 2 {
		parts = append(parts, hex[i:i+2])
	}
	return strings.Join(parts, ":")
}

func printPublicKeyInfo(pub interface{}) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		fmt.Printf("            Public Key Algorithm: %s\n", x509.RSA.String())
		fmt.Printf("                RSA Public-Key: (%d bit)\n", pub.N.BitLen())
		fmt.Println("                Modulus:")
		printHexBlock("                    ", pub.N.Bytes(), 15)
		fmt.Printf("                Exponent: %d (0x%x)\n", pub.E, pub.E)

	case *ecdsa.PublicKey:
		fmt.Printf("            Public Key Algorithm: %s\n", x509.ECDSA.String())
		fmt.Printf("                Public-Key: (%d bit)\n", pub.Curve.Params().BitSize)
		printHexBlock("                    ", pub.X.Bytes(), 15) // Just showing the X coordinate for brevity, similar to some tools
		fmt.Printf("                Curve: %s\n", pub.Curve.Params().Name)
	default:
		fmt.Println("            Public Key Algorithm: Unknown")
	}
}

func printExtensions(cert *x509.Certificate) {
	for _, ext := range cert.Extensions {
		oidStr := ext.Id.String()
		extName, ok := oidToStringMap[oidStr]
		if !ok {
			extName = oidStr // Fallback to OID if not in map
		}

		criticalStr := ""
		if ext.Critical {
			criticalStr = "critical"
		}
		fmt.Printf("            %s: %s\n", extName, criticalStr)

		// Parse and print specific extension details
		printExtensionValue(ext, cert)
	}
}

func printExtensionValue(ext pkix.Extension, cert *x509.Certificate) {
	indent := "                "
	switch {
	case ext.Id.Equal(oidExtensionKeyUsage):
		printKeyUsage(cert.KeyUsage, indent)
	case ext.Id.Equal(oidExtensionExtendedKeyUsage):
		printExtendedKeyUsage(cert.ExtKeyUsage, indent)
	case ext.Id.Equal(oidExtensionBasicConstraints):
		fmt.Printf("%sCA:%t\n", indent, cert.IsCA)
	case ext.Id.Equal(oidExtensionSubjectKeyId):
		fmt.Printf("%s%s\n", indent, formatHex(cert.SubjectKeyId))
	case ext.Id.Equal(oidExtensionAuthorityKeyId):
		fmt.Printf("%skeyid:%s\n", indent, formatHex(cert.AuthorityKeyId))
	case ext.Id.Equal(oidExtensionSubjectAltName):
		printSAN(cert, indent)
	case ext.Id.Equal(oidAuthorityInfoAccess):
		printAIA(cert, indent)
	case ext.Id.Equal(oidExtensionCRLDistributionPoints):
		for _, point := range cert.CRLDistributionPoints {
			fmt.Printf("%sFull Name:\n%s  URI:%s\n", indent, indent, point)
		}
	case ext.Id.Equal(oidExtensionCertificatePolicies):
		for _, policy := range cert.PolicyIdentifiers {
			fmt.Printf("%sPolicy: %s\n", indent, policy.String())
		}
	}
}

func printKeyUsage(ku x509.KeyUsage, indent string) {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}
	fmt.Printf("%s%s\n", indent, strings.Join(usages, ", "))
}

func printExtendedKeyUsage(ekus []x509.ExtKeyUsage, indent string) {
	var usages []string
	for _, eku := range ekus {
		switch eku {
		case x509.ExtKeyUsageAny:
			usages = append(usages, "Any")
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "TLS Web Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "TLS Web Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "E-mail Protection")
		case x509.ExtKeyUsageIPSECEndSystem:
			usages = append(usages, "IPSEC End System")
		case x509.ExtKeyUsageIPSECTunnel:
			usages = append(usages, "IPSEC Tunnel")
		case x509.ExtKeyUsageIPSECUser:
			usages = append(usages, "IPSEC User")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSP Signing")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			usages = append(usages, "Microsoft Server Gated Crypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			usages = append(usages, "Netscape Server Gated Crypto")
		default:
			usages = append(usages, "Unknown")
		}
	}
	fmt.Printf("%s%s\n", indent, strings.Join(usages, ", "))
}

func printSAN(cert *x509.Certificate, indent string) {
	var san []string
	for _, name := range cert.DNSNames {
		san = append(san, "DNS:"+name)
	}
	for _, email := range cert.EmailAddresses {
		san = append(san, "email:"+email)
	}
	for _, ip := range cert.IPAddresses {
		san = append(san, "IP Address:"+ip.String())
	}
	for _, uri := range cert.URIs {
		san = append(san, "URI:"+uri.String())
	}
	fmt.Printf("%s%s\n", indent, strings.Join(san, ", "))
}

func printAIA(cert *x509.Certificate, indent string) {
	if len(cert.OCSPServer) > 0 {
		fmt.Printf("%sOCSP - URI:%s\n", indent, strings.Join(cert.OCSPServer, ", "))
	}
	if len(cert.IssuingCertificateURL) > 0 {
		fmt.Printf("%sCA Issuers - URI:%s\n", indent, strings.Join(cert.IssuingCertificateURL, ", "))
	}
}

func formatHex(data []byte) string {
	var parts []string
	for i, b := range data {
		if i > 0 {
			parts = append(parts, ":")
		}
		parts = append(parts, fmt.Sprintf("%02X", b))
	}
	return strings.Join(parts, "")
}

func printHexBlock(prefix string, data []byte, wrap int) {
	var parts []string
	for i, b := range data {
		if i > 0 && i%wrap == 0 {
			parts = append(parts, "\n"+prefix)
		}
		parts = append(parts, fmt.Sprintf("%02x:", b))
	}
	// remove last ":"
	if len(parts) > 0 {
		str := strings.Join(parts, "")
		fmt.Printf("%s%s\n", prefix, str[:len(str)-1])
	}
}

// infoCmd represents the info command
var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display information about the XCA tool",
	Long: `Display information about Certificate, like 'openssl x509 -noout -text -in xxx.crt' including version, and basic information.

Examples:
  xca info <path-of>/root-ca.crt`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		certfilePath = args[0]

		// Read the certificate file
		certPEM, err := os.ReadFile(certfilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading certificate file: %v\n", err)
			os.Exit(1)
		}

		// Decode the PEM-encoded certificate
		block, _ := pem.Decode(certPEM)
		if block == nil || block.Type != "CERTIFICATE" {
			fmt.Fprintf(os.Stderr, "Failed to decode PEM block containing certificate\n")
			os.Exit(1)
		}

		// Parse the certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing certificate: %v\n", err)
			os.Exit(1)
		}

		// Print certificate details
		printCertificateInfo(cert)
	},
}
