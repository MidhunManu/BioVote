package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthService struct {
	ctx       context.Context
	jwtSecret []byte
}

type Claims struct {
	OfficerID    string `json:"officer_id"`
	EmployeeCode string `json:"employee_code"`
	BoothID      string `json:"booth_id"`
	Role         string `json:"role"`
	jwt.RegisteredClaims
}

func NewAuthService(ctx context.Context) *AuthService {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "hackathon-dev-secret-change-in-prod" // default for dev
	}
	return &AuthService{ctx: ctx, jwtSecret: []byte(secret)}
}

// Login authenticates a booth officer and returns a JWT
func (s *AuthService) Login(req LoginRequest) (*LoginResponse, error) {
	fs := Get().Firestore

	// Find officer by employee code
	docs, err := fs.Collection(ColOfficers).
		Where("employee_code", "==", req.EmployeeCode).
		Where("is_active", "==", true).
		Limit(1).
		Documents(s.ctx).GetAll()

	if err != nil || len(docs) == 0 {
		return nil, fmt.Errorf("invalid credentials")
	}

	var officer BoothOfficer
	if err := docs[0].DataTo(&officer); err != nil {
		return nil, fmt.Errorf("officer data error")
	}

	// Verify password
	pwHash := fmt.Sprintf("%x", sha256.Sum256([]byte(req.Password)))
	if pwHash != officer.PasswordHash {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Generate JWT
	expiresAt := time.Now().Add(12 * time.Hour) // valid for full election day
	claims := Claims{
		OfficerID:    officer.ID,
		EmployeeCode: officer.EmployeeCode,
		BoothID:      officer.BoothID,
		Role:         officer.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   officer.ID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("token generation failed")
	}

	return &LoginResponse{
		Token:     signed,
		Officer:   officer,
		ExpiresAt: expiresAt,
	}, nil
}

// ValidateToken verifies JWT and returns claims
func (s *AuthService) ValidateToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

// GetOfficerByID fetches officer details
func (s *AuthService) GetOfficerByID(id string) (*BoothOfficer, error) {
	fs := Get().Firestore
	doc, err := fs.Collection(ColOfficers).Doc(id).Get(s.ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, nil
		}
		return nil, err
	}
	var officer BoothOfficer
	if err := doc.DataTo(&officer); err != nil {
		return nil, err
	}
	return &officer, nil
}
