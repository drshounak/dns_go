package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"golang.org/x/time/rate"
)

var (
	dnsProviders = map[string][]string{
		"google":     {"8.8.8.8:53", "8.8.4.4:53"},
		"cloudflare": {"1.1.1.1:53", "1.0.0.1:53"},
		"opendns":    {"208.67.222.222:53", "208.67.220.220:53"},
		"root": {
			"a.root-servers.net:53", "b.root-servers.net:53", "c.root-servers.net:53",
			"d.root-servers.net:53", "e.root-servers.net:53", "f.root-servers.net:53",
			"g.root-servers.net:53", "h.root-servers.net:53", "i.root-servers.net:53",
			"j.root-servers.net:53", "k.root-servers.net:53", "l.root-servers.net:53",
			"m.root-servers.net:53",
		},
	}

	basicRecordTypes = []uint16{
		dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeNS, dns.TypeMX, dns.TypeTXT, dns.TypeSOA,
	}

	allRecordTypes = append(basicRecordTypes,
		dns.TypePTR, dns.TypeNAPTR, dns.TypeCAA, dns.TypeSRV, dns.TypeDNSKEY, dns.TypeDS,
		dns.TypeNSEC, dns.TypeNSEC3, dns.TypeRRSIG, dns.TypeOPT, dns.TypeTLSA,
	)

	dnsCache    *cache.Cache
	ipLimiters  = sync.Map{}
	logger      *log.Logger
)

type RateLimiterWithLastUse struct {
	limiter *rate.Limiter
	lastUse time.Time
}

func init() {
	// Initialize cache with 5 minutes default expiration and 10 minutes cleanup interval
	dnsCache = cache.New(5*time.Minute, 10*time.Minute)

	// Initialize logger
	logger = log.New(log.Writer(), "DNS_API: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func main() {
	r := gin.Default()

	r.Use(rateLimitMiddleware())

	r.GET("/lookup", handleBasicLookup)
	r.GET("/lookup/detailed", handleDetailedLookup)
	r.GET("/lookup/raw", handleRawLookup)
	r.GET("/lookup/reverse", handleReverseLookup)

	for _, recordType := range []string{"a", "aaaa", "cname", "ns", "txt"} {
		r.GET(fmt.Sprintf("/lookup/%s", recordType), handleIndividualRecordLookup(recordType))
	}

	for provider := range dnsProviders {
		r.GET(fmt.Sprintf("/lookup/%s", provider), handleProviderLookup(provider))
	}

	go cleanupIPLimiters() // Start the cleanup goroutine

	logger.Println("Starting DNS API server on :8080")
	if err := r.Run(":8080"); err != nil {
		logger.Fatalf("Failed to start server: %v", err)
	}
}

func getIPLimiter(ip string) *RateLimiterWithLastUse {
	limiter, exists := ipLimiters.Load(ip)
	if !exists {
		// Allow 10 requests per second with a burst of 20
		newLimiter := &RateLimiterWithLastUse{
			limiter: rate.NewLimiter(rate.Limit(10), 20),
			lastUse: time.Now(),
		}
		limiter, _ = ipLimiters.LoadOrStore(ip, newLimiter)
	}
	return limiter.(*RateLimiterWithLastUse)
}

func rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		limiter := getIPLimiter(ip)
		if !limiter.limiter.Allow() {
			c.JSON(429, gin.H{"error": "Rate limit exceeded"})
			c.Abort()
			return
		}
		limiter.lastUse = time.Now()
		c.Next()
	}
}

func cleanupIPLimiters() {
	for {
		time.Sleep(time.Hour) // Run cleanup every hour
		ipLimiters.Range(func(key, value interface{}) bool {
			ip := key.(string)
			limiter := value.(*RateLimiterWithLastUse)
			if time.Since(limiter.lastUse) > time.Hour {
				ipLimiters.Delete(ip)
			}
			return true
		})
	}
}


func handleBasicLookup(c *gin.Context) {
	domain := c.Query("domain")
	if domain == "" {
		c.JSON(400, gin.H{"error": "Domain parameter is required"})
		return
	}

	cacheKey := fmt.Sprintf("basic:%s", domain)
	if cachedRecords, found := dnsCache.Get(cacheKey); found {
		c.JSON(200, cachedRecords)
		return
	}

	records, err := performLookup(domain, dnsProviders["google"], basicRecordTypes)
	if err != nil {
		records, err = performLookup(domain, dnsProviders["cloudflare"], basicRecordTypes)
		if err != nil {
			logger.Printf("DNS lookup failed for domain %s: %v", domain, err)
			c.JSON(500, gin.H{"error": "DNS lookup failed"})
			return
		}
	}

	dnsCache.Set(cacheKey, records, cache.DefaultExpiration)
	c.JSON(200, records)
}

func handleDetailedLookup(c *gin.Context) {
	domain := c.Query("domain")
	if domain == "" {
		c.JSON(400, gin.H{"error": "Domain parameter is required"})
		return
	}

	cacheKey := fmt.Sprintf("detailed:%s", domain)
	if cachedRecords, found := dnsCache.Get(cacheKey); found {
		c.JSON(200, cachedRecords)
		return
	}

	records, err := performLookup(domain, dnsProviders["google"], allRecordTypes)
	if err != nil {
		logger.Printf("Detailed DNS lookup failed for domain %s: %v", domain, err)
		c.JSON(500, gin.H{"error": "DNS lookup failed"})
		return
	}

	dnsCache.Set(cacheKey, records, cache.DefaultExpiration)
	c.JSON(200, records)
}

func handleRawLookup(c *gin.Context) {
	domain := c.Query("domain")
	if domain == "" {
		c.JSON(400, gin.H{"error": "Domain parameter is required"})
		return
	}

	cacheKey := fmt.Sprintf("raw:%s", domain)
	if cachedRecords, found := dnsCache.Get(cacheKey); found {
		c.JSON(200, cachedRecords)
		return
	}

	records, err := performRawLookup(domain, dnsProviders["google"], basicRecordTypes)
	if err != nil {
		logger.Printf("Raw DNS lookup failed for domain %s: %v", domain, err)
		c.JSON(500, gin.H{"error": "DNS lookup failed"})
		return
	}

	dnsCache.Set(cacheKey, records, cache.DefaultExpiration)
	c.JSON(200, records)
}

func handleReverseLookup(c *gin.Context) {
	ip := c.Query("ip")
	if ip == "" {
		c.JSON(400, gin.H{"error": "IP parameter is required"})
		return
	}

	cacheKey := fmt.Sprintf("reverse:%s", ip)
	if cachedRecords, found := dnsCache.Get(cacheKey); found {
		c.JSON(200, cachedRecords)
		return
	}

	names, err := net.LookupAddr(ip)
	if err != nil {
		logger.Printf("Reverse DNS lookup failed for IP %s: %v", ip, err)
		c.JSON(500, gin.H{"error": "Reverse DNS lookup failed"})
		return
	}

	result := map[string][]string{"PTR": names}
	dnsCache.Set(cacheKey, result, cache.DefaultExpiration)
	c.JSON(200, result)
}

func handleIndividualRecordLookup(recordType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		domain := c.Query("domain")
		if domain == "" {
			c.JSON(400, gin.H{"error": "Domain parameter is required"})
			return
		}

		cacheKey := fmt.Sprintf("%s:%s", recordType, domain)
		if cachedRecords, found := dnsCache.Get(cacheKey); found {
			c.JSON(200, cachedRecords)
			return
		}

		dnsType := dns.StringToType[strings.ToUpper(recordType)]
		records, err := performLookup(domain, dnsProviders["google"], []uint16{dnsType})
		if err != nil {
			logger.Printf("DNS lookup failed for domain %s and record type %s: %v", domain, recordType, err)
			c.JSON(500, gin.H{"error": "DNS lookup failed"})
			return
		}

		dnsCache.Set(cacheKey, records, cache.DefaultExpiration)
		c.JSON(200, records)
	}
}

func handleProviderLookup(provider string) gin.HandlerFunc {
	return func(c *gin.Context) {
		domain := c.Query("domain")
		if domain == "" {
			c.JSON(400, gin.H{"error": "Domain parameter is required"})
			return
		}

		cacheKey := fmt.Sprintf("%s:%s", provider, domain)
		if cachedRecords, found := dnsCache.Get(cacheKey); found {
			c.JSON(200, cachedRecords)
			return
		}

		records, err := performLookup(domain, dnsProviders[provider], basicRecordTypes)
		if err != nil {
			logger.Printf("DNS lookup failed for domain %s using provider %s: %v", domain, provider, err)
			c.JSON(500, gin.H{"error": "DNS lookup failed"})
			return
		}

		dnsCache.Set(cacheKey, records, cache.DefaultExpiration)
		c.JSON(200, records)
	}
}

func performLookup(domain string, servers []string, types []uint16) (map[string][]string, error) {
	records := make(map[string][]string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstError error

	for _, server := range servers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			for _, recordType := range types {
				msg := new(dns.Msg)
				msg.SetQuestion(dns.Fqdn(domain), recordType)
				msg.SetEdns0(4096, true) // Enable DNSSEC

				client := &dns.Client{}
				resp, _, err := client.Exchange(msg, server)
				if err != nil {
					mu.Lock()
					if firstError == nil {
						firstError = err
					}
					mu.Unlock()
					continue
				}

				if resp.Rcode != dns.RcodeSuccess {
					continue
				}

				mu.Lock()
				for _, answer := range resp.Answer {
					recordTypeStr := dns.TypeToString[answer.Header().Rrtype]
					switch answer.Header().Rrtype {
					case dns.TypeA:
						records[recordTypeStr] = append(records[recordTypeStr], answer.(*dns.A).A.String())
					case dns.TypeAAAA:
						records[recordTypeStr] = append(records[recordTypeStr], answer.(*dns.AAAA).AAAA.String())
					case dns.TypeCNAME:
						records[recordTypeStr] = append(records[recordTypeStr], answer.(*dns.CNAME).Target)
					case dns.TypeMX:
						mx := answer.(*dns.MX)
						records[recordTypeStr] = append(records[recordTypeStr], fmt.Sprintf("%d %s", mx.Preference, mx.Mx))
					case dns.TypeNS:
						records[recordTypeStr] = append(records[recordTypeStr], answer.(*dns.NS).Ns)
					case dns.TypeTXT:
						records[recordTypeStr] = append(records[recordTypeStr], strings.Join(answer.(*dns.TXT).Txt, " "))
					case dns.TypeSOA:
						soa := answer.(*dns.SOA)
						records[recordTypeStr] = append(records[recordTypeStr], fmt.Sprintf("%s %s %d %d %d %d %d",
							soa.Ns, soa.Mbox, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minttl))
					default:
						records[recordTypeStr] = append(records[recordTypeStr], answer.String())
					}
				}
				mu.Unlock()
			}
		}(server)
	}

	wg.Wait()

	if len(records) == 0 && firstError != nil {
		return nil, firstError
	}

	return records, nil
}

func performRawLookup(domain string, servers []string, types []uint16) (map[string][]string, error) {
	records := make(map[string][]string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstError error

	for _, server := range servers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			for _, recordType := range types {
				msg := new(dns.Msg)
				msg.SetQuestion(dns.Fqdn(domain), recordType)
				msg.SetEdns0(4096, true) // Enable DNSSEC

				client := &dns.Client{}
				resp, _, err := client.Exchange(msg, server)
				if err != nil {
					mu.Lock()
					if firstError == nil {
						firstError = err
					}
					mu.Unlock()
					continue
				}

				if resp.Rcode != dns.RcodeSuccess {
					continue
				}

				mu.Lock()
				for _, answer := range resp.Answer {
					recordTypeStr := dns.TypeToString[answer.Header().Rrtype]
					records[recordTypeStr] = append(records[recordTypeStr], answer.String())
				}
				mu.Unlock()
			}
		}(server)
	}

	wg.Wait()

	if len(records) == 0 && firstError != nil {
		return nil, firstError
	}

	return records, nil
}
