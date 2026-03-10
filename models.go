package models

import "time"

// Voter represents a registered voter in Firestore
type Voter struct {
	AadhaarHash   string    `firestore:"aadhaar_hash" json:"aadhaar_hash"`
	Name          string    `firestore:"name" json:"name"`
	DOB           string    `firestore:"dob" json:"dob"`
	Gender        string    `firestore:"gender" json:"gender"`
	VoterID       string    `firestore:"voter_id" json:"voter_id"`
	Constituency  string    `firestore:"constituency" json:"constituency"`
	BoothID       string    `firestore:"booth_id" json:"booth_id"`
	BoothName     string    `firestore:"booth_name" json:"booth_name"`
	Address       string    `firestore:"address" json:"address"`
	PhotoURL      string    `firestore:"photo_url" json:"photo_url"`
	HasVoted      bool      `firestore:"has_voted" json:"has_voted"`
	VotedAt       *time.Time `firestore:"voted_at,omitempty" json:"voted_at,omitempty"`
	IrisTemplate  string    `firestore:"iris_template" json:"iris_template"` // hashed iris reference
	CreatedAt     time.Time `firestore:"created_at" json:"created_at"`
}

// AuditLog represents an immutable verification event
type AuditLog struct {
	ID            string    `firestore:"id" json:"id"`
	AadhaarHash   string    `firestore:"aadhaar_hash" json:"aadhaar_hash"`
	VoterName     string    `firestore:"voter_name" json:"voter_name"`
	VoterID       string    `firestore:"voter_id" json:"voter_id"`
	BoothID       string    `firestore:"booth_id" json:"booth_id"`
	BoothName     string    `firestore:"booth_name" json:"booth_name"`
	OfficerID     string    `firestore:"officer_id" json:"officer_id"`
	Result        string    `firestore:"result" json:"result"` // VERIFIED | DUPLICATE | NOT_FOUND | WRONG_BOOTH
	BiometricType string    `firestore:"biometric_type" json:"biometric_type"` // IRIS | FINGERPRINT
	IPAddress     string    `firestore:"ip_address" json:"ip_address"`
	TxHash        string    `firestore:"tx_hash" json:"tx_hash"` // SHA256 of payload
	Timestamp     time.Time `firestore:"timestamp" json:"timestamp"`
}

// BoothOfficer represents a polling officer account
type BoothOfficer struct {
	ID           string    `firestore:"id" json:"id"`
	Name         string    `firestore:"name" json:"name"`
	EmployeeCode string    `firestore:"employee_code" json:"employee_code"`
	BoothID      string    `firestore:"booth_id" json:"booth_id"`
	BoothName    string    `firestore:"booth_name" json:"booth_name"`
	PasswordHash string    `firestore:"password_hash" json:"-"`
	Role         string    `firestore:"role" json:"role"` // OFFICER | SUPERVISOR | ADMIN
	IsActive     bool      `firestore:"is_active" json:"is_active"`
	CreatedAt    time.Time `firestore:"created_at" json:"created_at"`
}

// Booth represents a polling booth
type Booth struct {
	ID           string    `firestore:"id" json:"id"`
	Name         string    `firestore:"name" json:"name"`
	Constituency string    `firestore:"constituency" json:"constituency"`
	Address      string    `firestore:"address" json:"address"`
	TotalVoters  int       `firestore:"total_voters" json:"total_voters"`
	VotesCast    int       `firestore:"votes_cast" json:"votes_cast"`
	IsActive     bool      `firestore:"is_active" json:"is_active"`
	OpenedAt     *time.Time `firestore:"opened_at,omitempty" json:"opened_at,omitempty"`
}

// ---- Request/Response DTOs ----

type LoginRequest struct {
	EmployeeCode string `json:"employee_code" binding:"required"`
	Password     string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Token     string       `json:"token"`
	Officer   BoothOfficer `json:"officer"`
	ExpiresAt time.Time    `json:"expires_at"`
}

type VerifyRequest struct {
	AadhaarNumber string `json:"aadhaar_number" binding:"required"` // raw 12-digit
	IrisScan      string `json:"iris_scan" binding:"required"`      // base64 iris data
	BiometricType string `json:"biometric_type"`                    // IRIS | FINGERPRINT
}

type VerifyResponse struct {
	Result       string    `json:"result"`
	Voter        *VoterPublic `json:"voter,omitempty"`
	Message      string    `json:"message"`
	TxHash       string    `json:"tx_hash"`
	Timestamp    time.Time `json:"timestamp"`
}

// VoterPublic is the safe public-facing voter info (no biometric data)
type VoterPublic struct {
	Name         string     `json:"name"`
	VoterID      string     `json:"voter_id"`
	DOB          string     `json:"dob"`
	Gender       string     `json:"gender"`
	Constituency string     `json:"constituency"`
	BoothID      string     `json:"booth_id"`
	BoothName    string     `json:"booth_name"`
	Address      string     `json:"address"`
	PhotoURL     string     `json:"photo_url"`
	HasVoted     bool       `json:"has_voted"`
	VotedAt      *time.Time `json:"voted_at,omitempty"`
}

type DashboardStats struct {
	BoothID      string  `json:"booth_id"`
	BoothName    string  `json:"booth_name"`
	TotalVoters  int     `json:"total_voters"`
	VotesCast    int     `json:"votes_cast"`
	Pending      int     `json:"pending"`
	TurnoutPct   float64 `json:"turnout_pct"`
	LastUpdated  time.Time `json:"last_updated"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Message string `json:"message"`
}
