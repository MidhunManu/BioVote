package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/eci/voter-verification/internal/middleware"
	"github.com/eci/voter-verification/internal/models"
	"github.com/eci/voter-verification/internal/services"
)

type Handler struct {
	voterSvc *services.VoterService
	authSvc  *services.AuthService
}

func New(voterSvc *services.VoterService, authSvc *services.AuthService) *Handler {
	return &Handler{voterSvc: voterSvc, authSvc: authSvc}
}

// HealthCheck godoc
// GET /health
func (h *Handler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": "ECI Voter Verification API",
		"version": "1.0.0",
	})
}

// Login godoc
// POST /api/v1/auth/login
// Body: { "employee_code": "ECI-MH-042", "password": "officer123" }
func (h *Handler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "INVALID_REQUEST",
			Message: err.Error(),
		})
		return
	}

	resp, err := h.authSvc.Login(req)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Error:   "AUTH_FAILED",
			Message: "Invalid employee code or password",
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// LookupVoter godoc
// GET /api/v1/voters/lookup?aadhaar=234567890123
// Returns voter details before biometric scan
func (h *Handler) LookupVoter(c *gin.Context) {
	aadhaar := c.Query("aadhaar")
	if len(aadhaar) != 12 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "INVALID_AADHAAR",
			Message: "Aadhaar number must be exactly 12 digits",
		})
		return
	}

	voter, err := h.voterSvc.GetVoterByAadhaar(aadhaar)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "LOOKUP_ERROR",
			Message: "Database error during voter lookup",
		})
		return
	}
	if voter == nil {
		c.JSON(http.StatusNotFound, models.ErrorResponse{
			Error:   "NOT_FOUND",
			Message: "No voter record found for this Aadhaar number",
		})
		return
	}

	c.JSON(http.StatusOK, voter)
}

// VerifyVoter godoc
// POST /api/v1/voters/verify
// Body: { "aadhaar_number": "234567890123", "iris_scan": "IRIS_PRIYA_SHARMA_2024", "biometric_type": "IRIS" }
// Requires: Authorization: Bearer <token>
func (h *Handler) VerifyVoter(c *gin.Context) {
	var req models.VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "INVALID_REQUEST",
			Message: err.Error(),
		})
		return
	}

	// Sanitize Aadhaar (remove spaces/dashes)
	clean := ""
	for _, ch := range req.AadhaarNumber {
		if ch >= '0' && ch <= '9' {
			clean += string(ch)
		}
	}
	if len(clean) != 12 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "INVALID_AADHAAR",
			Message: "Aadhaar number must be exactly 12 digits",
		})
		return
	}
	req.AadhaarNumber = clean

	if req.BiometricType == "" {
		req.BiometricType = "IRIS"
	}

	// Extract officer info from JWT context
	officerID, _ := c.Get(middleware.CtxOfficerID)
	boothID, _ := c.Get(middleware.CtxBoothID)
	ipAddr := c.ClientIP()

	resp, err := h.voterSvc.VerifyVoter(req, officerID.(string), boothID.(string), ipAddr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "VERIFICATION_ERROR",
			Message: "Internal server error during verification",
		})
		return
	}

	// Return appropriate HTTP status
	statusCode := http.StatusOK
	if resp.Result == services.ResultNotFound {
		statusCode = http.StatusNotFound
	} else if resp.Result == services.ResultDuplicate || resp.Result == services.ResultWrongBooth || resp.Result == services.ResultBioFail {
		statusCode = http.StatusConflict
	}

	c.JSON(statusCode, resp)
}

// GetDashboard godoc
// GET /api/v1/booth/dashboard
// Returns live stats for the officer's assigned booth
func (h *Handler) GetDashboard(c *gin.Context) {
	boothID, _ := c.Get(middleware.CtxBoothID)

	stats, err := h.voterSvc.GetBoothStats(boothID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "STATS_ERROR",
			Message: "Failed to fetch booth statistics",
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// GetAuditLogs godoc
// GET /api/v1/booth/audit?limit=50
// Returns audit logs for this booth
func (h *Handler) GetAuditLogs(c *gin.Context) {
	boothID, _ := c.Get(middleware.CtxBoothID)
	limit := 50
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}

	logs, err := h.voterSvc.GetAuditLogs(boothID.(string), limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "LOG_ERROR",
			Message: "Failed to fetch audit logs",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"booth_id": boothID,
		"count":    len(logs),
		"logs":     logs,
	})
}
