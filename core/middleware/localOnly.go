package middleware

import (
	"net"
	"net/http"

	"github.com/tyree-z/monstera/core/pages"
)

func AllowLocalOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
        	data := pages.ErrorPageData{
            	Title:   "500 Internal Server Error",
            	Heading: "Internal Server Error",
            	Message: "Monstera was unable to parse your IP address. Unfortunately, this is a fatal error and you will not be able to access this domain.",
        	}
        	pages.RenderErrorPage(w, http.StatusInternalServerError, "pages/errors/500.html", data)
			return
		}

		if !isLocalIP(ip) {
        	data := pages.ErrorPageData{
            	Title:   "403 Forbidden",
            	Heading: "Access Denied",
            	Message: "This endpoint is an internal endpoint and can only be accessed from the local network.",
        	}
        	pages.RenderErrorPage(w, http.StatusForbidden, "pages/errors/403.html", data)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)

	// Check for localhost
	if ip.IsLoopback() {
		return true
	}
	
	blacklistedCIDRs := []string{
		"192.168.0.0/16",
		"10.0.0.0/16",
		"172.16.0.0/12",
	}

	for _, cidr := range blacklistedCIDRs {
		_, net, _ := net.ParseCIDR(cidr)
		if net.Contains(ip) {
			return true
		}
	}

	return false
}

