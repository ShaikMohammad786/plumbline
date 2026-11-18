package main

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Planted: SEC001 hardcoded secret
const LiveAPISecret = "sk-live-000011112222333344445555"

// Planted: SLP002 mock data in production
const DummyUserID = "dummy_user_12345"

func InsecureClient() *http.Client {
	// Planted: SEC005 TLS verification disabled
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}

func HashWithMD5(data string) []byte {
	// Planted: SEC006 weak cryptographic hash
	h := md5.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}

// Planted: GAP001 TODO near auth / token / verify
// TODO: Implement signature verify check for tokens
func ValidateToken(token string) bool {
	// Planted: GAP002 stub / literal return
	return true
}

// Planted: GAP005 handler never registered
func handleUnregisteredCallback(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "orphan")
}

func main() {
	r := gin.Default()

	// Planted: SLP007 debug leftover
	fmt.Println("DEBUG: Starting Go Gin HTTP server")

	// Planted: SEC008 route with no auth check nearby
	r.GET("/api/go/users", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Planted: SEC010 state-changing route without CSRF protection
	r.POST("/api/go/users/delete", func(c *gin.Context) {
		_, err := http.Get("https://example.com")
		if err != nil {
			// Planted: SLP001 swallowed error
		}
		c.JSON(200, gin.H{"deleted": true})
	})

	_ = r.Run(":8080")
	SafeErrorHandler(nil)
}

// --- DECOYS ---

func SecureSHA256Hash(data string) []byte {
	// Decoy: Secure SHA-256 hash
	h := sha256.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}

func SafeErrorHandler(err error) {
	// Decoy: Proper logging of errors
	if err != nil {
		log.Printf("Operation failed: %v", err)
	}
}

// Decoy: Safe typed constant
const SafeServerTimeoutSeconds = 30
