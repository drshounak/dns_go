package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Database models
type User struct {
	gorm.Model
	Email     string `gorm:"unique"`
	Password  string
	IsActive  bool
	APIKeys   []APIKey
	CreatedAt time.Time
	UpdatedAt time.Time
}

type APIKey struct {
	gorm.Model
	UserID      uint
	Key         string `gorm:"unique"`
	Description string
	DailyQuota  int       // Default 2500
	LastReset   time.Time // When the count was last reset
	Count       int       // Current count since last reset
	IsActive    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Config for multi-server deployment
type ServerConfig struct {
	Port          string
	RedisURL      string
	DatabaseURL   string
	Environment   string
	ServerID      string
	LoadBalanced  bool
	MasterServer  bool
}

var (
	dnsProviders = map[string][]string{
		"google":     {"8.8.8.8:53", "8.8.4.4:53"},
		"cloudflare": {"1.1.1.1:53", "1.0.0.1:53"},
		"opendns":    {"208.67.222.222:53", "208.67.220.220:53"},
	}

	basicRecordTypes = []uint16{
		dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeNS, dns.TypeMX, dns.TypeTXT, dns.TypeSOA,
	}

	allRecordTypes = append(basicRecordTypes,
		dns.TypePTR, dns.TypeNAPTR, dns.TypeCAA, dns.TypeSRV, dns.TypeDNSKEY, dns.TypeDS,
		dns.TypeNSEC, dns.TypeNSEC3, dns.TypeRRSIG, dns.TypeOPT, dns.TypeTLSA,
	)

	dnsCache   *cache.Cache
	ipLimiters = sync.Map{}
	db         *gorm.DB
	redisClient *redis.Client
	config     ServerConfig
)

type RateLimiterWithLastUse struct {
	limiter *rate.Limiter
	lastUse time.Time
}

// Request structure for authentication and API usage
type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RegisterRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type APIKeyRequest struct {
	Description string `json:"description"`
}

func init() {
	dnsCache = cache.New(10*time.Second, 30*time.Second)
	
	// Load configuration
	config = loadConfig()
	
	// Setup database connection
	setupDatabase()
	
	// Setup Redis for distributed rate limiting
	setupRedis()
	
	// Start background tasks
	go cleanupIPLimiters()
	go resetDailyQuotas()
}

func loadConfig() ServerConfig {
	return ServerConfig{
		Port:         getEnv("PORT", "5001"),
		RedisURL:     getEnv("REDIS_URL", "redis://localhost:6379"),
		DatabaseURL:  getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/dnsapi"),
		Environment:  getEnv("ENVIRONMENT", "development"),
		ServerID:     getEnv("SERVER_ID", "server1"),
		LoadBalanced: getEnvBool("LOAD_BALANCED", false),
		MasterServer: getEnvBool("MASTER_SERVER", true),
	}
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value == "true" || value == "1" || value == "yes"
}

func setupDatabase() {
	var err error
	db, err = gorm.Open(postgres.Open(config.DatabaseURL), &gorm.Config{})
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to database: %v", err))
	}
	
	// Auto migrate the schema
	db.AutoMigrate(&User{}, &APIKey{})
}

func setupRedis() {
	opt, err := redis.ParseURL(config.RedisURL)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse Redis URL: %v", err))
	}
	
	redisClient = redis.NewClient(opt)
}

func main() {
	r := gin.Default()

	// Set trusted proxies if behind load balancer
	if config.LoadBalanced {
		r.SetTrustedProxies([]string{"0.0.0.0/0"})
	}

	// Public routes
	r.GET("/", handleHome)
	r.POST("/api/register", handleRegister)
	r.POST("/api/login", handleLogin)
	
	// Limited public access
	publicAPI := r.Group("/api")
	publicAPI.Use(publicRateLimitMiddleware())
	publicAPI.Use(corsMiddleware())
	publicAPI.GET("/lookup", handlePublicLookup)
	
	// Protected routes (require API key)
	authAPI := r.Group("/api/v1")
	authAPI.Use(apiKeyAuthMiddleware())
	authAPI.Use(apiQuotaMiddleware())
	authAPI.Use(corsMiddleware())
	authAPI.GET("/lookup", handleLookup)
	authAPI.GET("/lookup/:type", handleTypedLookup)
	authAPI.GET("/lookup/provider/:provider", handleProviderLookup)
	
	// User dashboard API (requires session auth)
	dashboard := r.Group("/dashboard/api")
	dashboard.Use(sessionAuthMiddleware())
	dashboard.GET("/keys", handleGetAPIKeys)
	dashboard.POST("/keys", handleCreateAPIKey)
	dashboard.DELETE("/keys/:id", handleDeleteAPIKey)
	dashboard.GET("/usage", handleGetUsage)
	
	// Start server
	if err := r.Run(":" + config.Port); err != nil {
		fmt.Printf("Failed to start server: %v\n", err)
	}
}

func handleHome(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "Welcome to DNS API Service",
		"status": "online",
		"free_quota": 25,
		"signup_url": "/api/register",
	})
}

func handleRegister(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request data"})
		return
	}
	
	// Check if email already exists
	var existingUser User
	if result := db.Where("email = ?", req.Email).First(&existingUser); result.RowsAffected > 0 {
		c.JSON(409, gin.H{"error": "Email already registered"})
		return
	}
	
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to process registration"})
		return
	}
	
	// Create user
	newUser := User{
		Email:    req.Email,
		Password: string(hashedPassword),
		IsActive: true,
	}
	
	if err := db.Create(&newUser).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to create user"})
		return
	}
	
	// Generate initial API key
	apiKey, err := generateAPIKey(newUser.ID, "Default API Key")
	if err != nil {
		c.JSON(500, gin.H{"error": "User created but failed to generate API key"})
		return
	}
	
	c.JSON(201, gin.H{
		"message": "Registration successful",
		"api_key": apiKey,
		"daily_quota": 2500,
	})
}

func handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request data"})
		return
	}
	
	// Find user
	var user User
	if result := db.Where("email = ?", req.Email).First(&user); result.RowsAffected == 0 {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}
	
	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}
	
	// Create session token
	token, err := generateSessionToken()
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate session"})
		return
	}
	
	// Store in Redis with 24h expiry
	ctx := c.Request.Context()
	err = redisClient.Set(ctx, "session:"+token, user.ID, 24*time.Hour).Err()
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create session"})
		return
	}
	
	c.JSON(200, gin.H{
		"message": "Login successful",
		"token": token,
	})
}

func handleGetAPIKeys(c *gin.Context) {
	userID, _ := c.Get("userID")
	
	var apiKeys []APIKey
	if err := db.Where("user_id = ?", userID).Find(&apiKeys).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to retrieve API keys"})
		return
	}
	
	c.JSON(200, gin.H{"keys": apiKeys})
}

func handleCreateAPIKey(c *gin.Context) {
	userID, _ := c.Get("userID")
	
	var req APIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request data"})
		return
	}
	
	// Count existing keys
	var count int64
	db.Model(&APIKey{}).Where("user_id = ?", userID).Count(&count)
	if count >= 5 {
		c.JSON(400, gin.H{"error": "Maximum API key limit reached (5)"})
		return
	}
	
	description := req.Description
	if description == "" {
		description = fmt.Sprintf("API Key %d", count+1)
	}
	
	key, err := generateAPIKey(userID.(uint), description)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate API key"})
		return
	}
	
	c.JSON(201, gin.H{
		"message": "API key created",
		"api_key": key,
		"daily_quota": 2500,
	})
}

func handleDeleteAPIKey(c *gin.Context) {
	userID, _ := c.Get("userID")
	keyID := c.Param("id")
	
	var apiKey APIKey
	if err := db.Where("id = ? AND user_id = ?", keyID, userID).First(&apiKey).Error; err != nil {
		c.JSON(404, gin.H{"error": "API key not found"})
		return
	}
	
	if err := db.Delete(&apiKey).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to delete API key"})
		return
	}
	
	c.JSON(200, gin.H{"message": "API key deleted"})
}

func handleGetUsage(c *gin.Context) {
	userID, _ := c.Get("userID")
	
	var apiKeys []APIKey
	if err := db.Where("user_id = ?", userID).Find(&apiKeys).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to retrieve usage data"})
		return
	}
	
	var totalUsage int
	var keyUsage []map[string]interface{}
	
	for _, key := range apiKeys {
		totalUsage += key.Count
		keyUsage = append(keyUsage, map[string]interface{}{
			"id":          key.ID,
			"key":         maskAPIKey(key.Key),
			"description": key.Description,
			"quota":       key.DailyQuota,
			"used":        key.Count,
			"remaining":   key.DailyQuota - key.Count,
			"active":      key.IsActive,
		})
	}
	
	c.JSON(200, gin.H{
		"total_usage": totalUsage,
		"keys": keyUsage,
	})
}

func handlePublicLookup(c *gin.Context) {
	domain := c.Query("domain")
	if domain == "" {
		c.JSON(400, gin.H{"error": "Domain parameter is required"})
		return
	}
	
	// Perform basic lookup with limited data
	records, err := performLookup(domain, dnsProviders["google"], basicRecordTypes[:2]) // Just A and AAAA
	if err != nil {
		c.JSON(500, gin.H{"error": "DNS lookup failed"})
		return
	}
	
	// Add signup message
	c.JSON(200, gin.H{
		"data": records,
		"message": "Free tier limited to 25 queries per day. Sign up for an API key to increase your limit to 2500 queries per day.",
		"signup_url": "/api/register",
	})
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func publicRateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		
		// Get limit from Redis if load balanced
		ctx := c.Request.Context()
		key := fmt.Sprintf("ip_limit:%s", ip)
		
		// Check if IP has reached limit
		var count int64
		var err error
		
		if config.LoadBalanced {
			count, err = redisClient.Get(ctx, key).Int64()
			if err != nil && err != redis.Nil {
				c.JSON(500, gin.H{"error": "Rate limiting error"})
				c.Abort()
				return
			}
		} else {
			limiter := getIPLimiter(ip)
			if !limiter.limiter.Allow() {
				c.JSON(429, gin.H{"error": "Rate limit exceeded", "message": "Sign up for an API key to increase your limit"})
				c.Abort()
				return
			}
			limiter.lastUse = time.Now()
			
			// Update count
			count = int64(25 - limiter.limiter.Tokens())
		}
		
		// Check if exceeded daily limit (25 for public API)
		if count >= 25 {
			c.JSON(429, gin.H{"error": "Daily limit exceeded", "message": "Sign up for an API key to increase your limit to 2500 queries per day"})
			c.Abort()
			return
		}
		
		// Increment counter in Redis if load balanced
		if config.LoadBalanced {
			pipe := redisClient.Pipeline()
			pipe.Incr(ctx, key)
			// Set expiry to end of day if not already set
			pipe.Expire(ctx, key, time.Until(endOfDay()))
			_, err = pipe.Exec(ctx)
			if err != nil {
				c.JSON(500, gin.H{"error": "Rate limiting error"})
				c.Abort()
				return
			}
		}
		
		c.Next()
	}
}

func apiKeyAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("Authorization")
		if apiKey == "" {
			apiKey = c.Query("api_key")
		}
		
		if apiKey == "" {
			c.JSON(401, gin.H{"error": "API key required"})
			c.Abort()
			return
		}
		
		// Remove "Bearer " prefix if present
		apiKey = strings.TrimPrefix(apiKey, "Bearer ")
		
		// Find API key in database
		var key APIKey
		if err := db.Where("key = ? AND is_active = true", apiKey).First(&key).Error; err != nil {
			c.JSON(401, gin.H{"error": "Invalid or inactive API key"})
			c.Abort()
			return
		}
		
		// Store API key info in context
		c.Set("apiKey", key)
		c.Set("userID", key.UserID)
		
		c.Next()
	}
}

func sessionAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(401, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}
		
		// Remove "Bearer " prefix if present
		token = strings.TrimPrefix(token, "Bearer ")
		
		// Get user ID from Redis
		ctx := c.Request.Context()
		userID, err := redisClient.Get(ctx, "session:"+token).Int64()
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid or expired session"})
			c.Abort()
			return
		}
		
		// Store user ID in context
		c.Set("userID", uint(userID))
		
		c.Next()
	}
}

func apiQuotaMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey, exists := c.Get("apiKey")
		if !exists {
			c.JSON(500, gin.H{"error": "Internal server error"})
			c.Abort()
			return
		}
		
		key := apiKey.(APIKey)
		
		// Check if it's a new day, reset count if needed
		if time.Since(key.LastReset) > 24*time.Hour {
			// In a load balanced environment, use Redis for atomic update
			if config.LoadBalanced {
				ctx := c.Request.Context()
				redisKey := fmt.Sprintf("apikey_reset:%d", key.ID)
				
				// Only reset if not already done by another server
				if _, err := redisClient.Get(ctx, redisKey).Result(); err == redis.Nil {
					// Reset counter and update last reset time
					db.Model(&key).Updates(map[string]interface{}{
						"count":      0,
						"last_reset": time.Now(),
					})
					
					// Mark as reset in Redis
					redisClient.Set(ctx, redisKey, 1, 24*time.Hour)
				}
			} else {
				// Reset counter and update last reset time
				db.Model(&key).Updates(map[string]interface{}{
					"count":      0,
					"last_reset": time.Now(),
				})
			}
			
			// Refresh key data
			db.First(&key, key.ID)
		}
		
		// Check if quota exceeded
		if key.Count >= key.DailyQuota {
			c.JSON(429, gin.H{
				"error": "Daily API quota exceeded", 
				"limit": key.DailyQuota,
				"reset_at": key.LastReset.Add(24 * time.Hour),
			})
			c.Abort()
			return
		}
		
		// In load balanced environment, use Redis for atomic increment
		if config.LoadBalanced {
			ctx := c.Request.Context()
			redisKey := fmt.Sprintf("apikey_count:%d", key.ID)
			
			// Get current count from Redis
			count, err := redisClient.Get(ctx, redisKey).Int64()
			if err != nil && err != redis.Nil {
				c.JSON(500, gin.H{"error": "Quota tracking error"})
				c.Abort()
				return
			}
			
			// If key doesn't exist, initialize with DB value
			if err == redis.Nil {
				redisClient.Set(ctx, redisKey, key.Count, 24*time.Hour)
				count = int64(key.Count)
			}
			
			// Check quota against Redis value
			if count >= int64(key.DailyQuota) {
				c.JSON(429, gin.H{
					"error": "Daily API quota exceeded", 
					"limit": key.DailyQuota,
					"reset_at": key.LastReset.Add(24 * time.Hour),
				})
				c.Abort()
				return
			}
			
			// Increment count in Redis
			newCount, err := redisClient.Incr(ctx, redisKey).Result()
			if err != nil {
				c.JSON(500, gin.H{"error": "Quota tracking error"})
				c.Abort()
				return
			}
			
			// Periodically sync Redis count to DB (every 10 requests)
			if newCount%10 == 0 {
				db.Model(&key).Update("count", newCount)
			}
		} else {
			// Increment count directly in DB
			db.Model(&key).Update("count", key.Count+1)
		}
		
		c.Next()
	}
}

func getIPLimiter(ip string) *RateLimiterWithLastUse {
	limiter, exists := ipLimiters.Load(ip)
	if !exists {
		newLimiter := &RateLimiterWithLastUse{
			limiter: rate.NewLimiter(rate.Limit(2), 25), // 25 requests at 2 per second
			lastUse: time.Now(),
		}
		limiter, _ = ipLimiters.LoadOrStore(ip, newLimiter)
	}
	return limiter.(*RateLimiterWithLastUse)
}

func cleanupIPLimiters() {
	for {
		time.Sleep(time.Hour)
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

func resetDailyQuotas() {
	// Only run on master server if in load-balanced mode
	if config.LoadBalanced && !config.MasterServer {
		return
	}
	
	for {
		// Sleep until next day (midnight)
		now := time.Now()
		nextMidnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
		time.Sleep(time.Until(nextMidnight))
		
		// Reset all API key counters
		db.Model(&APIKey{}).Updates(map[string]interface{}{
			"count":      0,
			"last_reset": time.Now(),
		})
		
		// If using Redis, clear all API key count keys
		if config.LoadBalanced {
			ctx := redisClient.Context()
			// Get all apikey_count:* keys
			iter := redisClient.Scan(ctx, 0, "apikey_count:*", 100).Iterator()
			for iter.Next(ctx) {
				redisClient.Del(ctx, iter.Val())
			}
		}
	}
}

func generateAPIKey(userID uint, description string) (string, error) {
	// Generate random bytes
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	
	// Encode to base64
	key := base64.StdEncoding.EncodeToString(b)
	
	// Create API key in database
	apiKey := APIKey{
		UserID:      userID,
		Key:         key,
		Description: description,
		DailyQuota:  2500,
		LastReset:   time.Now(),
		Count:       0,
		IsActive:    true,
	}
	
	if err := db.Create(&apiKey).Error; err != nil {
		return "", err
	}
	
	return key, nil
}

func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func maskAPIKey(key string) string {
	if len(key) <= 8 {
		return key
	}
	return key[:4] + "..." + key[len(key)-4:]
}

func endOfDay() time.Time {
	now := time.Now()
	return time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 999999999, now.Location())
}

func handleLookup(c *gin.Context) {
	domain := c.Query("domain")
	if domain == "" {
		c.JSON(400, gin.H{"error": "Domain parameter is required"})
		return
	}

	lookupType := c.DefaultQuery("type", "basic")
	var recordTypes []uint16
	var cacheKey string

	switch lookupType {
	case "detailed":
		recordTypes = allRecordTypes
		cacheKey = fmt.Sprintf("detailed:%s", domain)
	case "raw":
		cacheKey = fmt.Sprintf("raw:%s", domain)
	case "authoritative":
		cacheKey = fmt.Sprintf("authoritative:%s", domain)
	default:
		recordTypes = basicRecordTypes
		cacheKey = fmt.Sprintf("basic:%s", domain)
	}

	if cachedRecords, found := dnsCache.Get(cacheKey); found {
		c.JSON(200, cachedRecords)
		return
	}

	var records map[string][]string
	var err error

	switch lookupType {
	case "raw":
		records, err = performRawLookup(domain, dnsProviders["google"], basicRecordTypes)
	case "authoritative":
		authServers, err := getAuthoritativeServers(domain)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to get authoritative servers"})
			return
		}
		records, err = performLookup(domain, authServers, allRecordTypes)
	default:
		records, err = performLookup(domain, dnsProviders["google"], recordTypes)
		if err != nil {
			records, err = performLookup(domain, dnsProviders["cloudflare"], recordTypes)
		}
	}

	if err != nil {
		c.JSON(500, gin.H{"error": "DNS lookup failed"})
		return
	}

	dnsCache.Set(cacheKey, records, cache.DefaultExpiration)
	c.JSON(200, records)
}

func handleTypedLookup(c *gin.Context) {
	domain := c.Query("domain")
	if domain == "" {
		c.JSON(400, gin.H{"error": "Domain parameter is required"})
		return
	}

	recordType := c.Param("type")
	dnsType, ok := dns.StringToType[strings.ToUpper(recordType)]
	if !ok {
		c.JSON(400, gin.H{"error": "Invalid record type"})
		return
	}

	cacheKey := fmt.Sprintf("%s:%s", recordType, domain)
	if cachedRecords, found := dnsCache.Get(cacheKey); found {
		c.JSON(200, cachedRecords)
		return
	}

	records, err := performLookup(domain, dnsProviders["google"], []uint16{dnsType})
	if err != nil {
		c.JSON(500, gin.H{"error": "DNS lookup failed"})
		return
	}

	dnsCache.Set(cacheKey, records, cache.DefaultExpiration)
	c.JSON(200, records)
}

func handleProviderLookup(c *gin.Context) {
	domain := c.Query("domain")
	if domain == "" {
		c.JSON(400, gin.H{"error": "Domain parameter is required"})
		return
	}

	provider := c.Param("provider")
	servers, ok := dnsProviders[provider]
	if !ok {
		c.JSON(400, gin.H{"error": "Invalid DNS provider"})
		return
	}

	cacheKey := fmt.Sprintf("%s:%s", provider, domain)
	if cachedRecords, found := dnsCache.Get(cacheKey); found {
		c.JSON(200, cachedRecords)
		return
	}

	records, err := performLookup(domain, servers, basicRecordTypes)
	if err != nil {
		c.JSON(500, gin.H{"error": "DNS lookup failed"})
		return
	}

	dnsCache.Set(cacheKey, records, cache.DefaultExpiration)
	c.JSON(200, records)
}

func performLookup(domain string, servers []string, types []uint16) (map[string][]string, error) {
	records := make(map[string]map[string]struct{})
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
				msg.SetEdns0(4096, true)

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
					if records[recordTypeStr] == nil {
						records[recordTypeStr] = make(map[string]struct{})
					}
					var value string
					switch answer.Header().Rrtype {
					case dns.TypeA:
						value = answer.(*dns.A).A.String()
					case dns.TypeAAAA:
						value = answer.(*dns.AAAA).AAAA.String()
					case dns.TypeCNAME:
						value = answer.(*dns.CNAME).Target
					case dns.TypeMX:
						mx := answer.(*dns.MX)
						value = fmt.Sprintf("%d %s", mx.Preference, mx.Mx)
					case dns.TypeNS:
						value = answer.(*dns.NS).Ns
					case dns.TypeTXT:
						value = strings.Join(answer.(*dns.TXT).Txt, " ")
					case dns.TypeSOA:
						soa := answer.(*dns.SOA)
						value = fmt.Sprintf("%s %s %d %d %d %d %d",
							soa.Ns, soa.Mbox, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minttl)
					default:
						value = answer.String()
					}
					records[recordTypeStr][value] = struct{}{}
				}
				mu.Unlock()
			}
		}(server)
	}

	wg.Wait()

	if len(records) == 0 && firstError != nil {
		return nil, firstError
	}

	result := make(map[string][]string)
	for recordType, uniqueValues := range records {
		for value := range uniqueValues {
			result[recordType] = append(result[recordType], value)
		}
	}

	return result, nil
}

func performRawLookup(domain string, servers []string, types []uint16) (map[string][]string, error) {
	records := make(map[string]map[string]struct{})
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
				msg.SetEdns0(4096, true)

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
					if records[recordTypeStr] == nil {
						records[recordTypeStr] = make(map[string]struct{})
					}
					records[recordTypeStr][answer.String()] = struct{}{}
				}
				mu.Unlock()
			}
		}(server)
	}

	wg.Wait()

	if len(records) == 0 && firstError != nil {
		return nil, firstError
	}

	result := make(map[string][]string)
	for recordType, uniqueValues := range records {
		for value := range uniqueValues {
			result[recordType] = append(result[recordType], value)
		}
	}

	return result, nil
}

func getAuthoritativeServers(domain string) ([]string, error) {
	var authServers []string
	var client dns.Client
	var m dns.Msg

	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	m.RecursionDesired = true

	r, _, err := client.Exchange(&m, "8.8.8.8:53")
	if err != nil {
		return nil, err
	}

	if len(r.Answer) == 0 {
		return nil, fmt.Errorf("no NS records found for %s", domain)
	}

	for _, ans := range r.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			authServers = append(authServers, ns.Ns+":53")
		}
	}

	if len(authServers) == 0 {
		return nil, fmt.Errorf("no authoritative servers found for %s", domain)
	}

	return authServers, nil
}
