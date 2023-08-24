package domains

import (
	"log"
	"net/url"
	"sync"
	"time"
)

var (
	backendMap = make(map[string]*url.URL)
	mapMutex   = &sync.RWMutex{}
)

func GetBackendURL(host string) (*url.URL, bool) {
	mapMutex.RLock()
	defer mapMutex.RUnlock()
	url, exists := backendMap[host]
	return url, exists
}

func UpdateBackendMapPeriodically(interval time.Duration) {
	for {
		newBackends, err := fetchBackendsFromAPI()
		if err != nil {
			log.Printf("Error fetching backends: %s", err)
			time.Sleep(interval)
			continue
		}

		mapMutex.Lock()
		for domain, backendURLStr := range newBackends {
			backendURL, err := url.Parse(backendURLStr)
			if err != nil {
				log.Printf("Error parsing URL %s for domain %s: %s", backendURLStr, domain, err)
				continue
			}
			backendMap[domain] = backendURL
		}
		mapMutex.Unlock()

		time.Sleep(interval)
	}
}
