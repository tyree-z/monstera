package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tyree-z/monstera/core/domains"
	"github.com/tyree-z/monstera/core/middleware"
	"github.com/tyree-z/monstera/core/proxy"
	"github.com/tyree-z/monstera/core/tlsutils"
	"golang.org/x/crypto/acme/autocert"
)

const (
	UpdateInterval = 1 * time.Minute
)

func StartHTTPUpgradeServer() {
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/", tlsutils.RedirectToHTTPS)
	log.Printf("Listening for upgrade requests on port 80")
	if err := http.ListenAndServe(":80", httpMux); err != nil {
		log.Println("HTTP server failure:", err)
	}
}

func StartMainServer(localMode bool) error {
	go domains.UpdateBackendMapPeriodically(UpdateInterval)

	mux := http.NewServeMux()
	mux.HandleFunc("/", proxy.HandleRequest)
	mux.Handle("/metrics", middleware.AllowLocalOnly(promhttp.Handler()))

	var tlsConfig *tls.Config

	if localMode {
		certPath := "selfsigned/cert.pem"
		keyPath := "selfsigned/key.pem"

		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			log.Println("No self-signed certificates found. Generating new ones.")
			if err := tlsutils.GenerateSelfSignedCert(certPath, keyPath); err != nil {
				log.Fatalf("Failed to generate self-signed certificates: %v", err)
			}
		}

		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			log.Fatalf("Failed to load self-signed certificates: %v", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		// tlsConfig.ClientAuth = tls.NoClientCert
		tlsConfig.VerifyPeerCertificate = tlsutils.VerifyClientCertificate
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
			VerifyPeerCertificate: tlsutils.VerifyClientCertificate,
		}
	}
	s443 := &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	log.Println("Monstera is listening on port 443")
	return s443.ListenAndServeTLS("", "")
}
