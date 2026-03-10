package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/eci/voter-verification/internal/services"
)

const (
	CtxOfficerID    = "officer_id"
	CtxEmployeeCode = "employee_code"
	CtxBoothID      = "booth_id"
	CtxRole         = "role"
)

// AuthMiddleware validates JWT tokens on protected routes
func AuthMiddleware(authSvc *services.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "UNAUTHORIZED",
				"message": "Authorization header required",
			})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "INVALID_TOKEN_FORMAT",
				"message": "Use: Authorization: Bearer <token>",
			})
			return
		}

		claims, err := authSvc.ValidateToken(parts[1])
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "TOKEN_EXPIRED_OR_INVALID",
				"message": "Please log in again",
			})
			return
		}

		// Inject officer info into request context
		c.Set(CtxOfficerID, claims.OfficerID)
		c.Set(CtxEmployeeCode, claims.EmployeeCode)
		c.Set(CtxBoothID, claims.BoothID)
		c.Set(CtxRole, claims.Role)
		c.Next()
	}
}

// RoleRequired restricts access to specific roles
func RoleRequired(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]bool)
	for _, r := range roles {
		allowed[r] = true
	}
	return func(c *gin.Context) {
		role, _ := c.Get(CtxRole)
		if !allowed[role.(string)] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "FORBIDDEN",
				"message": "Insufficient permissions for this action",
			})
			return
		}
		c.Next()
	}
}

// RequestLogger logs all incoming requests
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}

// CORS middleware
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
