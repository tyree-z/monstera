package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/html"
)

type Configuration map[string]string
type ConfigCache struct {
    Data      Configuration
    Timestamp time.Time
}

var (
	config     Configuration
	configLock sync.RWMutex
	configCache ConfigCache
    cacheLock   sync.RWMutex
)

func main() {
	var err error
	log.Println("Fetching initial configuration...")
	config, err = fetchConfigFromAPI("http://100.81.68.139:3333/v1/monstera/list")
	if err != nil {
        log.Fatalf("Failed to fetch initial configuration: %v", err)
	}

	http.HandleFunc("/", setHeaders(handleRequest))

	certManager := autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache("certs"),
		HostPolicy: func(ctx context.Context, host string) error {
			configLock.RLock()
			defer configLock.RUnlock()
			if _, ok := config[host]; ok {
				return nil
			}
			return fmt.Errorf("acme/autocert: host %q not configured", host)
		},
	}
	
    tlsConfig := certManager.TLSConfig()

    tlsConfig.MinVersion = tls.VersionTLS12
    tlsConfig.MaxVersion = tls.VersionTLS13

	server := &http.Server{
		Addr:      ":https",
		TLSConfig: tlsConfig,
	}

	go func() {
		httpHandlerFunc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/acme-challenge/" {
				// Handle ACME challenge
				certManager.HTTPHandler(nil).ServeHTTP(w, r)
			} else {
				// Redirect all other requests to HTTPS
				httpsURL := "https://" + r.Host + r.URL.String()
				http.Redirect(w, r, httpsURL, http.StatusFound)
			}
		})

		log.Println("Monstera Listening on :http")
		log.Fatal(http.ListenAndServe(":http", httpHandlerFunc))
	}()

	go updateConfigPeriodically()

	log.Println("Monstera Listening on :https")
	log.Fatal(server.ListenAndServeTLS("", "")) // Key and cert are coming from Let's Encrypt
}

func fetchConfigFromAPI(apiURL string) (Configuration, error) {
	log.Printf("Fetching new configuration from API: %s", apiURL)
    cacheLock.RLock()
    cachedData := configCache.Data
    lastUpdated := configCache.Timestamp
    cacheLock.RUnlock()

    // Check if the cache is still valid
    if time.Since(lastUpdated) < 1*time.Hour {
        return cachedData, nil
    }

    // If cache is not valid, try fetching new data
    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Get(apiURL)
    if err != nil {
        // If API call fails, return cached data as a fallback
        if cachedData != nil {
            return cachedData, nil
        }
        return nil, err
    }
    defer resp.Body.Close()

    var config Configuration
    err = json.NewDecoder(resp.Body).Decode(&config)
    if err != nil {
        return nil, err
    }

    // Update cache
    cacheLock.Lock()
    configCache.Data = config
    configCache.Timestamp = time.Now()
    cacheLock.Unlock()

    return config, nil
}


func setHeaders(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			// Handle error
			return
		}
		serverVersion := fmt.Sprintf("Monstera / %s / 2023-12-20", Version)

        // Basic Security Headers
        w.Header().Set("X-Frame-Options", "DENY") // Prevent clickjacking attacks
        w.Header().Set("X-Content-Type-Options", "nosniff") // Prevent MIME type sniffing
        w.Header().Set("X-XSS-Protection", "1; mode=block") // Basic XSS protection
        w.Header().Set("Referrer-Policy", "no-referrer-when-downgrade") // Control referrer header

        // CORS Headers
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

        // Proxy Headers
        w.Header().Set("Server", serverVersion)
        w.Header().Set("X-Forwarded-For", ip)
        w.Header().Set("X-Forwarded-Host", r.Host)
        w.Header().Set("X-Forwarded-Proto", r.URL.Scheme)

        // Caching Control
        w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate") // Disable caching
        w.Header().Set("Pragma", "no-cache") // HTTP 1.0 backward compatibility
        w.Header().Set("Expires", "0")

        next(w, r)
    }
}


func handleRequest(w http.ResponseWriter, r *http.Request) {
	log.Printf("Handling request for %s", r.Host)
	configLock.RLock()
	targetURL, ok := config[r.Host]
	configLock.RUnlock()

	if !ok {
		http.Error(w, "Unknown host", http.StatusBadGateway)
		return
	}

	url, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "Error parsing target URL", http.StatusInternalServerError)
		log.Println(err)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(url)


    proxy.ModifyResponse = func(response *http.Response) error {
        if strings.Contains(response.Header.Get("Content-Type"), "text/html") {
            body, err := ioutil.ReadAll(response.Body)
            if err != nil {
                return err // handle error
            }
            err = response.Body.Close()
            if err != nil {
                return err // handle error
            }

            modifiedBody, err := insertScript(body)
            if err != nil {
                return err // handle error
            }

            response.Body = ioutil.NopCloser(bytes.NewReader(modifiedBody))
            response.ContentLength = int64(len(modifiedBody))
            response.Header.Set("Content-Length", strconv.Itoa(len(modifiedBody)))
        }
        return nil
    }


	proxy.ServeHTTP(w, r)
}

func updateConfigPeriodically() {
    log.Println("Starting periodic configuration updater...")
    for {
        time.Sleep(10 * time.Second) // Interval for updating the configuration
        newConfig, err := fetchConfigFromAPI("http://100.81.68.139:3333/v1/monstera/list")
        if err != nil {
            log.Println("Error fetching config:", err)
            continue
        }


        cacheLock.Lock()
        configCache.Data = newConfig
        configCache.Timestamp = time.Now()
        log.Println("Configuration updated successfully")
        cacheLock.Unlock()
    }
}

func insertScript(body []byte) ([]byte, error) {
    doc, err := html.Parse(bytes.NewReader(body))
    if err != nil {
        return nil, err
    }

    // Traverse the HTML nodes
    traverseNodes(doc, func(n *html.Node) {
        if n.Type == html.ElementNode && n.Data == "body" {
            insertGAScript(n)
        }
    })

    var buf bytes.Buffer
    err = html.Render(&buf, doc)
    if err != nil {
        return nil, err
    }

    return buf.Bytes(), nil
}

func traverseNodes(n *html.Node, f func(*html.Node)) {
    if n.Type == html.ElementNode && n.Data == "body" {
        f(n)
        return
    }

    for child := n.FirstChild; child != nil; child = child.NextSibling {
        traverseNodes(child, f)
    }
}

func insertGAScript(bodyNode *html.Node) {
    script1 := &html.Node{
        Type: html.ElementNode,
        Data: "script",
        Attr: []html.Attribute{
            {Key: "async", Val: ""},
            {Key: "src", Val: "https://www.googletagmanager.com/gtag/js?id=Bonk"},
        },
    }

    script2 := &html.Node{
        Type: html.ElementNode,
        Data: "script",
    }
    script2Content := &html.Node{
        Type: html.TextNode,
        Data: `
          window.dataLayer = window.dataLayer || [];
          function gtag(){dataLayer.push(arguments);}
          gtag('js', new Date());

          gtag('config', 'Bonk');
        `,
    }
    script2.AppendChild(script2Content)

    bodyNode.AppendChild(script1)
    bodyNode.AppendChild(script2)
}


