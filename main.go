package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tyree-z/monstera/core/domains"
	"github.com/tyree-z/monstera/core/middleware"
	"github.com/tyree-z/monstera/core/proxy"
	"golang.org/x/crypto/acme/autocert"
)

const (
	UpdateInterval = 1 * time.Minute
)

func main() {
	localMode := flag.Bool("local", false, "Run in local mode with self-signed certificates.")
	flag.Parse()

	go domains.UpdateBackendMapPeriodically(UpdateInterval)

	mux := http.NewServeMux()
	mux.HandleFunc("/", proxy.HandleRequest)
	mux.Handle("/metrics", middleware.AllowLocalOnly(promhttp.Handler()))

	// // Redirect HTTP to HTTPS
	// redirectTLS := func(w http.ResponseWriter, r *http.Request) {
	// 	http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
	// }

	// go func() {
	// 	log.Printf("Redirecting all http requests on port 80 to https")
	// 	if err := http.ListenAndServe(":80", http.HandlerFunc(redirectTLS)); err != nil {
	// 		log.Println("HTTP redirection server failure:", err)
	// 	}
	// }()

	var tlsConfig *tls.Config

	if *localMode {
		certPath := "selfsigned/cert.pem"
		keyPath := "selfsigned/key.pem"

		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			log.Println("No self-signed certificates found. Generating new ones.")
			if err := generateSelfSignedCert(certPath, keyPath); err != nil {
				log.Fatalf("Failed to generate self-signed certificates: %v", err)
			}
		}

		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			log.Fatalf("Failed to load self-signed certificates: %v", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		// tlsConfig.ClientAuth = tls.NoClientCert
		tlsConfig.VerifyPeerCertificate = verifyClientCertificate
	} else {
		m := &autocert.Manager{
			Cache:  autocert.DirCache("./cached"),
			Prompt: autocert.AcceptTOS,
			HostPolicy: func(ctx context.Context, host string) error {
				activeDomains := domains.GetActiveDomains()
				for _, d := range activeDomains {
					if host == d {
						return nil
					}
				}
				return fmt.Errorf("acme/autocert: host %q not configured in custom whitelist", host)
			},
		}
		tlsConfig = &tls.Config{
			GetCertificate:       m.GetCertificate,
			ClientAuth:           tls.RequireAndVerifyClientCert,
			VerifyPeerCertificate: verifyClientCertificate,
		}
	}

	s443 := &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	log.Println("Monstera is listening on port 443")
	log.Fatal(s443.ListenAndServeTLS("", ""))
}



func generateSelfSignedCert(certPath, keyPath string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 1 year validity

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
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
		return err
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err != nil {
		return err
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}

	return pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
}

func verifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("missing client certificate")
	}

	for _, chain := range verifiedChains {
		for _, cert := range chain {
			if cert.IsCA {
				return fmt.Errorf("client certificate should not be a CA")
			}
		}
	}

	// More Certificate verification logic

	return nil
}