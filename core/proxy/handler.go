package proxy

import (
	"log"
	"net"
	"net/http"
	"net/http/httputil"

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
