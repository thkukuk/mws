// Copyright 2022 Thorsten Kukuk
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mws

import (
	"crypto/tls"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"time"
	"math/big"
	"os"
	// "net"
	// "strings"
)

func publicKey(key interface{}) interface{} {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func loadCertificateFromFile(tlsCert string, tlsKey string) *tls.Certificate {

	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		logerr.Printf("Could not load x509 key pair: %v\n", err)
		return nil
	}
	return &cert
}

func getOrCreateTLSCertificate(tlsCert string, tlsKey string) tls.Certificate {

	if tlsKey != "" && tlsCert != "" {
		if cert := loadCertificateFromFile(tlsKey, tlsCert); cert != nil {
			return *cert
		}
	}

	logger.Println("Key for TLS not found. Creating new one.")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logerr.Printf("Failed to generate private key: %v\n", err)
	}

	validFor := 365*24*time.Hour
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logerr.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"mws Dummy CA"},
		},
		DNSNames:  []string{"localhost"},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	host, _ := os.Hostname()
	template.DNSNames = append(template.DNSNames, host)
	// XXX should the IP addresses of the interfaces be really added?
	// addrs, _ := net.InterfaceAddrs()
	// for _, addr := range addrs {
	//	template.DNSNames = append(template.DNSNames, strings.Split(addr.String(), "/")[0])
	// }
	// log.Printf("DNSNames = %v\n", template.DNSNames)

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(privateKey), privateKey)
	if err != nil {
		logerr.Fatalf("Failed to create certificate: %v\n", err)
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		logerr.Fatalln("Failed to encode certificate to PEM")
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		logerr.Fatalf("Unable to marshal private key: %v\n", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemKey == nil {
		logerr.Fatalln("Failed to encode key to PEM")
	}

	cert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		logerr.Fatalf("Failed to encode private key: %s\n", err)
	}

	// if err := os.WriteFile("cert.pem", pemCert, 0644); err != nil {
	//	log.Fatal(err)
	//}
	//log.Print("wrote cert.pem\n")
	//if err := os.WriteFile("key.pem", pemKey, 0600); err != nil {
	//	log.Fatal(err)
	//}
	//log.Print("wrote key.pem\n")

	return cert
}
