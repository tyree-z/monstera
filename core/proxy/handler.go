package proxy

import (
	"context"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/tyree-z/monstera/core/domains"
	"github.com/tyree-z/monstera/core/metrics"
	"github.com/tyree-z/monstera/core/pages"
)


func HandleRequest(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	userAgent := r.Header.Get("User-Agent")
		if userAgent != "" {
			metrics.RecordUserAgentRequest(userAgent)
		}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Println(err)
		return
	}
	backendURL, exists := domains.GetBackendURL(host)

    if !exists {
        data := pages.ErrorPageData{
            Title:   "404 Not Found",
            Heading: "Domain Not Found",
            Message: "The domain you requested seems to be pointing to a Monstera instance, but no backend URL has been configured for it.",
        }
        pages.RenderErrorPage(w, http.StatusNotFound, "pages/errors/404.html", data)
        return
    }

	proxy := httputil.NewSingleHostReverseProxy(backendURL)

	// Director function to add x-forwarded headers
	proxy.Director = func(req *http.Request) {
		if clientIP := req.Header.Get("X-Forwarded-For"); clientIP != "" {
			req.Header.Set("X-Forwarded-For", clientIP+", "+req.RemoteAddr)
		} else {
			req.Header.Set("X-Forwarded-For", req.RemoteAddr)
		}
		req.Header.Set("X-Forwarded-Host", req.Host)
		if req.TLS != nil {
			req.Header.Set("X-Forwarded-Proto", "https")
		} else {
			req.Header.Set("X-Forwarded-Proto", "http")
		}
		req.URL.Scheme = backendURL.Scheme
		req.URL.Host = backendURL.Host
	}


	// Set a timeout for the proxy
	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
	}

	proxy.ErrorLog = log.New(log.Writer(), "PROXY:", log.LstdFlags)

	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, err error) {
		if err == context.Canceled {
			log.Println("Request was canceled by the client.")
			return
		}
	
		log.Printf("Error during proxying request: %v", err)
		data := pages.ErrorPageData{
            Title:   "502 Bad Gateway",
            Heading: "Bad Gateway",
            Message: "Monstera was unable to proxy your request, the backend server may be down or unresponsive at the moment.",
        }
        pages.RenderErrorPage(w, http.StatusBadGateway, "pages/errors/502.html", data)
        return
	}
	    // Modify the response before it's written to the client
    proxy.ModifyResponse = func(resp *http.Response) error {
        resp.Header.Set("X-Proxied-By", "Monstera/0.1")
        return nil
    }


	proxy.ServeHTTP(w, r)
	metrics.RecordDomainRequest(r.Host)
	metrics.RecordEndpointRequest(r.URL.Path)
	metrics.RecordIPRequest(ip)
}
