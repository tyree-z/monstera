package main

import (
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tyree-z/monstera/core/domains"
	"github.com/tyree-z/monstera/core/middleware"
	"github.com/tyree-z/monstera/core/proxy"
)

const (
	UpdateInterval = 1 * time.Minute
)

func main() {
	go domains.UpdateBackendMapPeriodically(UpdateInterval)

	http.HandleFunc("/", proxy.HandleRequest)
	http.Handle("/metrics", middleware.AllowLocalOnly(promhttp.Handler()))
	log.Println("Monstera is listening on port 80 and 443")
	log.Fatal(http.ListenAndServe(":80", nil))
	log.Fatal(http.ListenAndServeTLS(":443", "./ssl/cert.pem", "./ssl/key.pem", nil))
}
