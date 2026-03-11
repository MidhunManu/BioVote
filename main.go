package main

import (
	"context"
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	ctx := context.Background()

	// ── Firebase Init ──────────────────────────────────────────
	Init(ctx)

	// ── Services ───────────────────────────────────────────────
	voterSvc := NewVoterService(ctx)
	authSvc := NewAuthService(ctx)

	// Seed mock data if flag is set (for hackathon demo)
	if os.Getenv("SEED_DATA") == "true" {
		SeedMockData(ctx)
	}

	// ── Router ─────────────────────────────────────────────────
	if os.Getenv("GIN_MODE") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	r.Use(CORS())

	h := NewHandler(voterSvc, authSvc)

	// Public routes
	r.GET("/health", h.HealthCheck)
	r.POST("/api/v1/auth/login", h.Login)

	// Protected routes (require JWT)
	auth := r.Group("/api/v1")
	auth.Use(AuthMiddleware(authSvc))
	{
		// Voter endpoints
		auth.GET("/voters/lookup", h.LookupVoter)
		auth.POST("/voters/verify", h.VerifyVoter)

		// Booth endpoints
		auth.GET("/booth/dashboard", h.GetDashboard)
		auth.GET("/booth/audit", h.GetAuditLogs)
	}

	// ── Start Server ───────────────────────────────────────────
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("ECI Voter Verification API running on :%s", port)
	log.Printf("Endpoints:")
	log.Printf("   POST /api/v1/auth/login")
	log.Printf("   GET  /api/v1/voters/lookup?aadhaar=<12digit>")
	log.Printf("   POST /api/v1/voters/verify")
	log.Printf("   GET  /api/v1/booth/dashboard")
	log.Printf("   GET  /api/v1/booth/audit")

	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
