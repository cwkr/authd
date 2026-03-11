package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	var hostname = "localhost"
	if len(os.Args) > 1 {
		hostname = os.Args[1]
	}
	var cert = &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: hostname,
		},
		IPAddresses:        []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(2, 0, 0),
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:           x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	if privKey, err := rsa.GenerateKey(rand.Reader, 4096); err == nil {
		var privKeyBytes = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		})
		if certRawBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &privKey.PublicKey, privKey); err == nil {
			var certBytes = pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certRawBytes,
			})
			if err := os.WriteFile(hostname+".crt", certBytes, 0644); err != nil {
				panic(err)
			}
			if err := os.WriteFile(hostname+".key", privKeyBytes, 0600); err != nil {
				panic(err)
			}
		} else {
			panic(err)
		}
	} else {
		panic(err)
	}
}
