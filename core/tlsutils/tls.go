// Package tlsutils provides utilities for managing TLS configurations and certificates.
package tlsutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"
)

const oneYearDuration = 365 * 24 * time.Hour

// RedirectToHTTPS redirects an HTTP request to HTTPS.
func RedirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		targetURL := "https://" + r.Host + r.RequestURI
		http.Redirect(w, r, targetURL, http.StatusMovedPermanently)
	}
}

// GenerateSelfSignedCert creates a self-signed certificate and writes it to provided paths.
func GenerateSelfSignedCert(certPath, keyPath string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(oneYearDuration)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Local Development"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	if err := writeFile(certPath, "CERTIFICATE", certDER); err != nil {
		return err
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	return writeFile(keyPath, "EC PRIVATE KEY", privBytes)
}

// writeFile writes data as PEM-encoded information to the specified path.
func writeFile(path, pemType string, data []byte) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", path, err)
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{Type: pemType, Bytes: data})
}

// VerifyClientCertificate ensures the client's certificate is valid and not a CA.
func VerifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("missing client certificate")
	}

	for _, chain := range verifiedChains {
		for _, cert := range chain {
			if cert.IsCA {
				return errors.New("client certificate should not be a CA")
			}
		}
	}
	return nil
}
