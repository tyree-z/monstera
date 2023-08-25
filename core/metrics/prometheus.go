package metrics

import (
	"sort"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	endpointRequestCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "endpoint_request_count",
			Help: "Number of requests per endpoint",
		},
		[]string{"endpoint"},
	)

	domainRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "domain_requests_total",
			Help: "Number of HTTP requests per domain",
		},
		[]string{"domain"},
	)
	ipRequestCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "top_ip_request_count",
			Help: "Number of requests for top IP addresses (top 10)",
		},
		[]string{"ip"},
	)
	userAgentRequestCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "user_agent_request_count",
			Help: "Number of requests per user agent (top 50))",
		},
		[]string{"user_agent"},
	)

	userAgents = make(map[string]int)
	topIPs = make(map[string]int)
	endpoints    = make(map[string]int)
	exportedEPs  = make(map[string]bool)
	topEndpoints = make(map[string]int)
	endpointRequestCountThreshold = 2
	
	mu = &sync.RWMutex{}
)

func RecordEndpointRequest(endpoint string) {
	mu.Lock()
	defer mu.Unlock()

	endpoints[endpoint]++

	if endpoints[endpoint] == endpointRequestCountThreshold && !exportedEPs[endpoint] {
		exportedEPs[endpoint] = true
	}

	if exportedEPs[endpoint] {
		endpointRequestCount.WithLabelValues(endpoint).Inc()
	}

    // Update topEndpoints map
    topEndpoints[endpoint] = endpoints[endpoint]

    // Prune if we have more than 50 endpoints
	if len(topEndpoints) > 50 {
		pruneEndpoints()
	}
}

func RecordDomainRequest(domain string) {
	domainRequestsTotal.WithLabelValues(domain).Inc()
}

func RecordIPRequest(ip string) {
	mu.Lock()
	defer mu.Unlock()

	topIPs[ip]++
	if len(topIPs) > 10 {
		// Logic to remove the least frequent IP
		var leastFrequentIP string
		var minCount int = int(^uint(0) >> 1)
		for k, v := range topIPs {
			if v < minCount {
				minCount = v
				leastFrequentIP = k
			}
		}
		delete(topIPs, leastFrequentIP)
	}

	for ip, count := range topIPs {
		ipRequestCount.WithLabelValues(ip).Set(float64(count))
	}
}

func RecordUserAgentRequest(userAgent string) {
	mu.Lock()
	defer mu.Unlock()

	userAgents[userAgent]++
	userAgentRequestCount.WithLabelValues(userAgent).Inc()

	if len(userAgents) > 50 {
		pruneUserAgents()
	}
}

// pruneUserAgents will keep the top 50 user agents based on their frequency.
func pruneUserAgents() {
	type userAgentFreq struct {
		ua    string
		count int
	}

	// Convert the map to a slice for sorting
	var uafList []userAgentFreq
	for ua, freq := range userAgents {
		uafList = append(uafList, userAgentFreq{ua, freq})
	}

	// Sort based on frequency
	sort.Slice(uafList, func(i, j int) bool {
		return uafList[i].count > uafList[j].count
	})

	// Keep only the top 50 user agents
	for i := 50; i < len(uafList); i++ {
		delete(userAgents, uafList[i].ua)
		userAgentRequestCount.DeleteLabelValues(uafList[i].ua)
	}
}

func pruneEndpoints() {
	type endpointFreq struct {
		ep    string
		count int
	}

	// Convert the map to a slice for sorting
	var epfList []endpointFreq
	for ep, freq := range topEndpoints {
		epfList = append(epfList, endpointFreq{ep, freq})
	}

	// Sort based on frequency
	sort.Slice(epfList, func(i, j int) bool {
		return epfList[i].count > epfList[j].count
	})

	// Keep only the top 50 endpoints
	for i := 50; i < len(epfList); i++ {
		delete(topEndpoints, epfList[i].ep)
		endpointRequestCount.DeleteLabelValues(epfList[i].ep)
	}
}