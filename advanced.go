package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/smtp"
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

type EmailVerification struct {
	gorm.Model
	Email     string    `gorm:"index"`
	Token     string    `gorm:"index"`
	ExpiresAt time.Time
	Used      bool
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

	approvedEmailDomains = []string{
		"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com",
		"aol.com", "protonmail.com", "pm.me", "zoho.com", "msn.com",
		"live.com", "mail.com", "yandex.com", "gmx.com", "tutanota.com",
	}

	dnsCache    *cache.Cache
	ipLimiters  = sync.Map{}
	db          *gorm.DB
	redisClient *redis.Client
	config      ServerConfig

	ipqsAPIKey   = getEnv("IPQS_API_KEY", "")
	smtpHost     = getEnv("SMTP_HOST", "smtp.example.com")
	smtpPort     = getEnv("SMTP_PORT", "587")
	smtpUsername = getEnv("SMTP_USERNAME", "noreply@example.com")
	smtpPassword = getEnv("SMTP_PASSWORD", "")
	smtpFrom     = getEnv("SMTP_FROM", "DNS API Service <noreply@example.com>")
	siteURL      = getEnv("SITE_URL", "https://dnsapi.example.com")
)

type RateLimiterWithLastUse struct {
	limiter *rate.Limiter
	lastUse time.Time
}

// Request structures
type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type APIKeyRequest struct {
	Description string `json:"description"`
}

func init() {
	dnsCache = cache.New(10*time.Second, 30*time.Second)
	
	config = loadConfig()
	setupDatabase()
	setupRedis()
	
	go cleanupIPLimiters()
	go resetDailyQuotas()
	go cleanupExpiredVerifications()
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
	
	db.AutoMigrate(&User{}, &APIKey{}, &EmailVerification{})
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

	if config.LoadBalanced {
		r.SetTrustedProxies([]string{"0.0.0.0/0"})
	}

	r.GET("/", handleHome)
	r.POST("/api/register", handleRegister)
	r.POST("/api/login", handleLogin)
	r.GET("/verify-email", handleVerifyEmail)
	r.POST("/resend-verification", handleResendVerification)
	
	publicAPI := r.Group("/api")
	publicAPI.Use(publicRateLimitMiddleware())
	publicAPI.Use(corsMiddleware())
	publicAPI.GET("/lookup", handlePublicLookup)
	
	authAPI := r.Group("/api/v1")
	authAPI.Use(apiKeyAuthMiddleware())
	authAPI.Use(apiQuotaMiddleware())
	authAPI.Use(corsMiddleware())
	authAPI.GET("/lookup", handleLookup)
	authAPI.GET("/lookup/:type", handleTypedLookup)
	authAPI.GET("/lookup/provider/:provider", handleProviderLookup)
	
	dashboard := r.Group("/dashboard/api")
	dashboard.Use(sessionAuthMiddleware())
	dashboard.GET("/keys", handleGetAPIKeys)
	dashboard.POST("/keys", handleCreateAPIKey)
	dashboard.DELETE("/keys/:id", handleDeleteAPIKey)
	dashboard.GET("/usage", handleGetUsage)
	
	if err := r.Run(":" + config.Port); err != nil {
		fmt.Printf("Failed to start server: %v\n", err)
	}
}

func handleHome(c *gin.Context) {
	c.JSON(200, gin.H{
		"message":    "Welcome to DNS API Service",
		"status":     "online",
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
	
	if !isApprovedEmailDomain(req.Email) {
		c.JSON(400, gin.H{"error": "Email domain not accepted. Please use a major email provider."})
		return
	}
	
	var existingUser User
	if result := db.Where("email = ?", req.Email).First(&existingUser); result.RowsAffected > 0 {
		c.JSON(409, gin.H{"error": "Email already registered"})
		return
	}
	
	clientIP := c.ClientIP()
	if !isValidIP(clientIP) {
		c.JSON(403, gin.H{"error": "Registration not allowed from your current network. VPNs and datacenter IPs are not permitted."})
		return
	}
	
	token, err := generateVerificationToken()
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to process registration"})
		return
	}
	
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to process registration"})
		return
	}
	
	verification := EmailVerification{
		Email:     req.Email,
		Token:     token,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Used:      false,
	}
	
	if err := db.Create(&verification).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to process registration"})
		return
	}
	
	newUser := User{
		Email:    req.Email,
		Password: string(hashedPassword),
		IsActive: false,
	}
	
	if err := db.Create(&newUser).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to create user"})
		return
	}
	
	if err := sendVerificationEmail(req.Email, token); err != nil {
		fmt.Printf("Failed to send verification email: %v\n", err)
	}
	
	c.JSON(201, gin.H{
		"message": "Registration initiated. Please check your email to verify your account.",
		"email":   req.Email,
	})
}

func handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request data"})
		return
	}
	
	var user User
	if result := db.Where("email = ?", req.Email).First(&user); result.RowsAffected == 0 {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}
	
	if !user.IsActive {
		c.JSON(403, gin.H{"error": "Account not activated. Please check your email for the verification link."})
		return
	}
	
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}
	
	token, err := generateSessionToken()
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate session"})
		return
	}
	
	ctx := c.Request.Context()
	err = redisClient.Set(ctx, "session:"+token, user.ID, 24*time.Hour).Err()
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create session"})
		return
	}
	
	c.JSON(200, gin.H{
		"message": "Login successful",
		"token":   token,
	})
}

func handleVerifyEmail(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(400, gin.H{"error": "Verification token is required"})
		return
	}
	
	var verification EmailVerification
	if err := db.Where("token = ? AND used = ? AND expires_at > ?", token, false, time.Now()).First(&verification).Error; err != nil {
		c.JSON(400, gin.H{"error": "Invalid or expired verification token"})
		return
	}
	
	var user User
	if err := db.Where("email = ? AND is_active = ?", verification.Email, false).First(&user).Error; err != nil {
		c.JSON(404, gin.H{"error": "User not found or already activated"})
		return
	}
	
	if err := db.Model(&user).Update("is_active", true).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to activate account"})
		return
	}
	
	if err := db.Model(&verification).Update("used", true).Error; err != nil {
		fmt.Printf("Failed to mark verification as used: %v\n", err)
	}
	
	apiKey, err := generateAPIKey(user.ID, "Default API Key")
	if err != nil {
		c.JSON(500, gin.H{"error": "User activated but failed to generate API key"})
		return
	}
	
	c.JSON(200, gin.H{
		"message":     "Email verified and account activated successfully",
		"api_key":     apiKey,
		"daily_quota": 2500,
	})
}

func handleResendVerification(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid email address"})
		return
	}
	
	var user User
	if err := db.Where("email = ? AND is_active = ?", req.Email, false).First(&user).Error; err != nil {
		c.JSON(200, gin.H{"message": "If your email exists in our system and is not yet verified, a new verification email has been sent."})
		return
	}
	
	db.Where("email = ?", req.Email).Delete(&EmailVerification{})
	
	token, err := generateVerificationToken()
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to process request"})
		return
	}
	
	verification := EmailVerification{
		Email:     req.Email,
		Token:     token,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Used:      false,
	}
	
	if err := db.Create(&verification).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to process request"})
		return
	}
	
	if err := sendVerificationEmail(req.Email, token); err != nil {
		fmt.Printf("Failed to send verification email: %v\n", err)
	}
	
	c.JSON(200, gin.H{"message": "If your email exists in our system and is not yet verified, a new verification email has been sent."})
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
		"message":     "API key created",
		"api_key":     key,
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
		"keys":        keyUsage,
	})
}

func handlePublicLookup(c *gin.Context) {
	domain := c.Query("domain")
	if domain == "" {
		c.JSON(400, gin.H{"error": "Domain parameter is required"})
		return
	}
	
	records, err := performLookup(domain, dnsProviders["google"], basicRecordTypes[:2])
	if err != nil {
		c.JSON(500, gin.H{"error": "DNS lookup failed"})
		return
	}
	
	c.JSON(200, gin.H{
		"data":       records,
		"message":    "Free tier limited to 25 queries per day. Sign up for an API key to increase your limit to 2500 queries per day.",
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
		
		ctx := c.Request.Context()
		key := fmt.Sprintf("ip_limit:%s", ip)
		
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
			count = int64(25 - limiter.limiter.Tokens())
		}
		
		if count >= 25 {
			c.JSON(429, gin.H{"error": "Daily limit exceeded", "message": "Sign up for an API key to increase your limit to 2500 queries per day"})
			c.Abort()
			return
		}
		
		if config.LoadBalanced {
			pipe := redisClient.Pipeline()
			pipe.Incr(ctx, key)
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
		
		apiKey = strings.TrimPrefix(apiKey, "Bearer ")
		
		var key APIKey
		if err := db.Where("key = ? AND is_active = true", apiKey).First(&key).Error; err != nil {
			c.JSON(401, gin.H{"error": "Invalid or inactive API key"})
			c.Abort()
			return
		}
		
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
		
		token = strings.TrimPrefix(token, "Bearer ")
		
		ctx := c.Request.Context()
		userID, err := redisClient.Get(ctx, "session:"+token).Int64()
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid or expired session"})
			c.Abort()
			return
		}
		
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
		
		if time.Since(key.LastReset) > 24*time.Hour {
			if config.LoadBalanced {
				ctx := c.Request.Context()
				redisKey := fmt.Sprintf("apikey_reset:%d", key.ID)
				
				if _, err := redisClient.Get(ctx, redisKey).Result(); err == redis.Nil {
					db.Model(&key).Updates(map[string]interface{}{
						"count":      0,
						"last_reset": time.Now(),
					})
					redisClient.Set(ctx, redisKey, 1, 24*time.Hour)
				}
			} else {
				db.Model(&key).Updates(map[string]interface{}{
					"count":      0,
					"last_reset": time.Now(),
				})
			}
			db.First(&key, key.ID)
		}
		
		if key.Count >= key.DailyQuota {
			c.JSON(429, gin.H{
				"error":    "Daily API quota exceeded",
				"limit":    key.DailyQuota,
				"reset_at": key.LastReset.Add(24 * time.Hour),
			})
			c.Abort()
			return
		}
		
		if config.LoadBalanced {
			ctx := c.Request.Context()
			redisKey := fmt.Sprintf("apikey_count:%d", key.ID)
			
			count, err := redisClient.Get(ctx, redisKey).Int64()
			if err != nil && err != redis.Nil {
				c.JSON(500, gin.H{"error": "Quota tracking error"})
				c.Abort()
				return
			}
			
			if err == redis.Nil {
				redisClient.Set(ctx, redisKey, key.Count, 24*time.Hour)
				count = int64(key.Count)
			}
			
			if count >= int64(key.DailyQuota) {
				c.JSON(429, gin.H{
					"error":    "Daily API quota exceeded",
					"limit":    key.DailyQuota,
					"reset_at": key.LastReset.Add(24 * time.Hour),
				})
				c.Abort()
				return
			}
			
			newCount, err := redisClient.Incr(ctx, redisKey).Result()
			if err != nil {
				c.JSON(500, gin.H{"error": "Quota tracking error"})
				c.Abort()
				return
			}
			
			if newCount%10 == 0 {
				db.Model(&key).Update("count", newCount)
			}
		} else {
			db.Model(&key).Update("count", key.Count+1)
		}
		
		c.Next()
	}
}

func getIPLimiter(ip string) *RateLimiterWithLastUse {
	limiter, exists := ipLimiters.Load(ip)
	if !exists {
		newLimiter := &RateLimiterWithLastUse{
			limiter: rate.NewLimiter(rate.Limit(2), 25),
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
	if config.LoadBalanced && !config.MasterServer {
		return
	}
	
	for {
		now := time.Now()
		nextMidnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
		time.Sleep(time.Until(nextMidnight))
		
		db.Model(&APIKey{}).Updates(map[string]interface{}{
			"count":      0,
			"last_reset": time.Now(),
		})
		
		if config.LoadBalanced {
			ctx := redisClient.Context()
			iter := redisClient.Scan(ctx, 0, "apikey_count:*", 100).Iterator()
			for iter.Next(ctx) {
				redisClient.Del(ctx, iter.Val())
			}
		}
	}
}

func cleanupExpiredVerifications() {
	for {
		time.Sleep(6 * time.Hour)
		db.Delete(&EmailVerification{}, "expires_at < ? OR used = ?", time.Now(), true)
	}
}

func generateAPIKey(userID uint, description string) (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	
	key := base64.StdEncoding.EncodeToString(b)
	
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

func generateVerificationToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
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

func isApprovedEmailDomain(email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	
	domain := strings.ToLower(parts[1])
	
	for _, approved := range approvedEmailDomains {
		if domain == approved {
			return true
		}
	}
	
	return false
}

func isValidIP(ip string) bool {
	if ipqsAPIKey == "" {
		return !isDatacenterIP(ip)
	}
	
	url := fmt.Sprintf("https://www.ipqualityscore.com/api/json/ip/%s/%s", ipqsAPIKey, ip)
	
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error checking IP: %v\n", err)
		return !isDatacenterIP(ip)
	}
	defer resp.Body.Close()
	
	var result struct {
		Proxy      bool `json:"proxy"`
		VPN        bool `json:"vpn"`
		TOR        bool `json:"tor"`
		Datacenter bool `json:"is_datacenter"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Printf("Error parsing IP check response: %v\n", err)
		return !isDatacenterIP(ip)
	}
	
	if result.Proxy || result.VPN || result.TOR || result.Datacenter {
		return false
	}
	
	return true
}

func isDatacenterIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	
	datacenterRanges := []string{
		"3.0.0.0/8", "13.0.0.0/8", "34.0.0.0/8", "35.0.0.0/8", "50.0.0.0/8", "52.0.0.0/8",
		"104.196.0.0/14", "104.42.0.0/16", "157.56.0.0/16", "168.61.0.0/16", "169.254.0.0/16",
		"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8",
	}
	
	for _, cidr := range datacenterRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			return true
		}
	}
	
	return false
}

func sendVerificationEmail(email, token string) error {
	emailTemplate := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Verify Your DNS API Account</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; background: #f9f9f9; border: 1px solid #eee; border-radius: 5px; padding: 20px;">
        <h1 style="color: #2c3e50; margin-top: 0;">Verify Your Email Address</h1>
        <p>Thank you for registering for a DNS API account. To complete your registration, please verify your email address by clicking the button below:</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{.VerificationURL}}" style="background-color: #3498db; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">Verify Email Address</a>
        </div>
        <p>Alternatively, you can copy and paste the following URL into your browser:</p>
        <p style="word-break: break-all; background: #eee; padding: 10px; border-radius: 4px;">{{.VerificationURL}}</p>
        <p>This link will expire in 24 hours.</p>
        <p>If you didn't request this verification, please ignore this email.</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="font-size: 12px; color: #777;">This is an automated message, please do not reply to this email.</p>
    </div>
</body>
</html>
`
	
	tmpl, err := template.New("verification").Parse(emailTemplate)
	if err != nil {
		return err
	}
	
	verificationURL := fmt.Sprintf("%s/verify-email?token=%s", siteURL, token)
	
	data := struct {
		VerificationURL string
	}{
		VerificationURL: verificationURL,
	}
	
	var emailBody bytes.Buffer
	if err := tmpl.Execute(&emailBody, data); err != nil {
		return err
	}
	
	headers := make(map[string]string)
	headers["From"] = smtpFrom
	headers["To"] = email
	headers["Subject"] = "Verify Your DNS API Account"
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=UTF-8"
	
	var message string
	for key, value := range headers {
		message += fmt.Sprintf("%s: %s\r\n", key, value)
	}
	message += "\r\n" + emailBody.String()
	
	auth := smtp.PlainAuth("", smtpUsername, smtpPassword, smtpHost)
	return smtp.SendMail(
		smtpHost+":"+smtpPort,
		auth,
		smtpUsername,
		[]string{email},
		[]byte(message),
	)
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
