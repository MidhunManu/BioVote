package services

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/google/uuid"
	fb "github.com/eci/voter-verification/internal/firebase"
	"github.com/eci/voter-verification/internal/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Firestore collection names
const (
	ColVoters   = "voters"
	ColAudit    = "audit_logs"
	ColOfficers = "booth_officers"
	ColBooths   = "booths"
)

// VerificationResult constants
const (
	ResultVerified   = "VERIFIED"
	ResultDuplicate  = "DUPLICATE"
	ResultNotFound   = "NOT_FOUND"
	ResultWrongBooth = "WRONG_BOOTH"
	ResultBioFail    = "BIOMETRIC_MISMATCH"
)

// VoterService handles all voter verification logic
type VoterService struct {
	ctx context.Context
	fs  *firestore.Client
}

func NewVoterService(ctx context.Context) *VoterService {
	return &VoterService{
		ctx: ctx,
		fs:  fb.Get().Firestore,
	}
}

// hashAadhaar creates a SHA-256 hash of the Aadhaar number
// Real system: use UIDAI's tokenization — never store raw Aadhaar
func hashAadhaar(aadhaar string) string {
	h := sha256.Sum256([]byte("SALT_ECI_2024_" + aadhaar))
	return fmt.Sprintf("%x", h)
}

// hashIris creates a hash of the iris biometric template
func hashIris(irisData string) string {
	h := sha256.Sum256([]byte(irisData))
	return fmt.Sprintf("%x", h)
}

// generateTxHash generates an immutable transaction hash for audit trail
func generateTxHash(aadhaarHash, result, boothID string, ts time.Time) string {
	payload := fmt.Sprintf("%s|%s|%s|%d", aadhaarHash, result, boothID, ts.UnixNano())
	h := sha256.Sum256([]byte(payload))
	return fmt.Sprintf("%x", h)
}

// VerifyVoter is the core verification function
func (s *VoterService) VerifyVoter(req models.VerifyRequest, officerID, boothID, ipAddr string) (*models.VerifyResponse, error) {
	aadhaarHash := hashAadhaar(req.AadhaarNumber)
	now := time.Now()

	// 1. Look up voter by Aadhaar hash
	voterDoc, err := s.fs.Collection(ColVoters).Doc(aadhaarHash).Get(s.ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			s.writeAuditLog(models.AuditLog{
				AadhaarHash:   aadhaarHash,
				VoterName:     "UNKNOWN",
				BoothID:       boothID,
				OfficerID:     officerID,
				Result:        ResultNotFound,
				BiometricType: req.BiometricType,
				IPAddress:     ipAddr,
				TxHash:        generateTxHash(aadhaarHash, ResultNotFound, boothID, now),
				Timestamp:     now,
			})
			return &models.VerifyResponse{
				Result:    ResultNotFound,
				Message:   "No voter record found for this Aadhaar number",
				TxHash:    generateTxHash(aadhaarHash, ResultNotFound, boothID, now),
				Timestamp: now,
			}, nil
		}
		return nil, fmt.Errorf("firestore lookup error: %w", err)
	}

	var voter models.Voter
	if err := voterDoc.DataTo(&voter); err != nil {
		return nil, fmt.Errorf("voter data parse error: %w", err)
	}

	// 2. Check booth assignment
	if voter.BoothID != boothID {
		s.writeAuditLog(models.AuditLog{
			AadhaarHash:   aadhaarHash,
			VoterName:     voter.Name,
			VoterID:       voter.VoterID,
			BoothID:       boothID,
			OfficerID:     officerID,
			Result:        ResultWrongBooth,
			BiometricType: req.BiometricType,
			IPAddress:     ipAddr,
			TxHash:        generateTxHash(aadhaarHash, ResultWrongBooth, boothID, now),
			Timestamp:     now,
		})
		return &models.VerifyResponse{
			Result:    ResultWrongBooth,
			Message:   fmt.Sprintf("Voter is assigned to %s, not this booth", voter.BoothName),
			Voter:     toPublic(voter),
			TxHash:    generateTxHash(aadhaarHash, ResultWrongBooth, boothID, now),
			Timestamp: now,
		}, nil
	}

	// 3. Check iris biometric (mock: compare hashes)
	incomingIrisHash := hashIris(req.IrisScan)
	if incomingIrisHash != voter.IrisTemplate {
		s.writeAuditLog(models.AuditLog{
			AadhaarHash:   aadhaarHash,
			VoterName:     voter.Name,
			VoterID:       voter.VoterID,
			BoothID:       boothID,
			OfficerID:     officerID,
			Result:        ResultBioFail,
			BiometricType: req.BiometricType,
			IPAddress:     ipAddr,
			TxHash:        generateTxHash(aadhaarHash, ResultBioFail, boothID, now),
			Timestamp:     now,
		})
		return &models.VerifyResponse{
			Result:    ResultBioFail,
			Message:   "Biometric verification failed — iris mismatch",
			TxHash:    generateTxHash(aadhaarHash, ResultBioFail, boothID, now),
			Timestamp: now,
		}, nil
	}

	// 4. Check duplicate vote
	if voter.HasVoted {
		s.writeAuditLog(models.AuditLog{
			AadhaarHash:   aadhaarHash,
			VoterName:     voter.Name,
			VoterID:       voter.VoterID,
			BoothID:       boothID,
			OfficerID:     officerID,
			Result:        ResultDuplicate,
			BiometricType: req.BiometricType,
			IPAddress:     ipAddr,
			TxHash:        generateTxHash(aadhaarHash, ResultDuplicate, boothID, now),
			Timestamp:     now,
		})
		return &models.VerifyResponse{
			Result:    ResultDuplicate,
			Message:   fmt.Sprintf("Vote already cast at %s", voter.VotedAt.Format(time.RFC3339)),
			Voter:     toPublic(voter),
			TxHash:    generateTxHash(aadhaarHash, ResultDuplicate, boothID, now),
			Timestamp: now,
		}, nil
	}

	// 5. All checks passed — mark as voted using Firestore transaction
	txHash := generateTxHash(aadhaarHash, ResultVerified, boothID, now)
	err = s.fs.RunTransaction(s.ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		// Re-read inside transaction to prevent race conditions
		docRef := s.fs.Collection(ColVoters).Doc(aadhaarHash)
		snap, err := tx.Get(docRef)
		if err != nil {
			return err
		}
		var latestVoter models.Voter
		if err := snap.DataTo(&latestVoter); err != nil {
			return err
		}
		if latestVoter.HasVoted {
			return fmt.Errorf("DUPLICATE_RACE") // caught below
		}
		return tx.Update(docRef, []firestore.Update{
			{Path: "has_voted", Value: true},
			{Path: "voted_at", Value: now},
		})
	})

	if err != nil && err.Error() == "DUPLICATE_RACE" {
		return &models.VerifyResponse{
			Result:    ResultDuplicate,
			Message:   "Concurrent duplicate vote attempt detected",
			Voter:     toPublic(voter),
			TxHash:    txHash,
			Timestamp: now,
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("transaction failed: %w", err)
	}

	// 6. Increment booth vote count
	go s.incrementBoothCount(boothID)

	// 7. Write success audit log
	voter.HasVoted = true
	voter.VotedAt = &now
	s.writeAuditLog(models.AuditLog{
		AadhaarHash:   aadhaarHash,
		VoterName:     voter.Name,
		VoterID:       voter.VoterID,
		BoothID:       boothID,
		BoothName:     voter.BoothName,
		OfficerID:     officerID,
		Result:        ResultVerified,
		BiometricType: req.BiometricType,
		IPAddress:     ipAddr,
		TxHash:        txHash,
		Timestamp:     now,
	})

	return &models.VerifyResponse{
		Result:    ResultVerified,
		Message:   "Voter successfully verified. Proceed to ballot.",
		Voter:     toPublic(voter),
		TxHash:    txHash,
		Timestamp: now,
	}, nil
}

// GetVoterByAadhaar retrieves voter info (for officer display before biometric)
func (s *VoterService) GetVoterByAadhaar(aadhaarNumber string) (*models.VoterPublic, error) {
	hash := hashAadhaar(aadhaarNumber)
	doc, err := s.fs.Collection(ColVoters).Doc(hash).Get(s.ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, nil
		}
		return nil, err
	}
	var voter models.Voter
	if err := doc.DataTo(&voter); err != nil {
		return nil, err
	}
	return toPublic(voter), nil
}

// GetBoothStats returns live dashboard stats for a booth
func (s *VoterService) GetBoothStats(boothID string) (*models.DashboardStats, error) {
	doc, err := s.fs.Collection(ColBooths).Doc(boothID).Get(s.ctx)
	if err != nil {
		return nil, err
	}
	var booth models.Booth
	if err := doc.DataTo(&booth); err != nil {
		return nil, err
	}
	turnout := 0.0
	if booth.TotalVoters > 0 {
		turnout = float64(booth.VotesCast) / float64(booth.TotalVoters) * 100
	}
	return &models.DashboardStats{
		BoothID:     booth.ID,
		BoothName:   booth.Name,
		TotalVoters: booth.TotalVoters,
		VotesCast:   booth.VotesCast,
		Pending:     booth.TotalVoters - booth.VotesCast,
		TurnoutPct:  turnout,
		LastUpdated: time.Now(),
	}, nil
}

// GetAuditLogs returns paginated audit logs for a booth
func (s *VoterService) GetAuditLogs(boothID string, limit int) ([]models.AuditLog, error) {
	query := s.fs.Collection(ColAudit).
		Where("booth_id", "==", boothID).
		OrderBy("timestamp", firestore.Desc).
		Limit(limit)

	docs, err := query.Documents(s.ctx).GetAll()
	if err != nil {
		return nil, err
	}
	var logs []models.AuditLog
	for _, d := range docs {
		var l models.AuditLog
		if err := d.DataTo(&l); err != nil {
			continue
		}
		logs = append(logs, l)
	}
	return logs, nil
}

// ---- Internal helpers ----

func (s *VoterService) writeAuditLog(log models.AuditLog) {
	log.ID = uuid.New().String()
	_, err := s.fs.Collection(ColAudit).Doc(log.ID).Set(s.ctx, log)
	if err != nil {
		fmt.Printf("⚠️  Audit log write failed: %v\n", err)
	}
}

func (s *VoterService) incrementBoothCount(boothID string) {
	_, err := s.fs.Collection(ColBooths).Doc(boothID).Update(s.ctx, []firestore.Update{
		{Path: "votes_cast", Value: firestore.Increment(1)},
	})
	if err != nil {
		log.Printf("⚠️  Booth count increment failed: %v", err)
	}
}

func toPublic(v models.Voter) *models.VoterPublic {
	return &models.VoterPublic{
		Name:         v.Name,
		VoterID:      v.VoterID,
		DOB:          v.DOB,
		Gender:       v.Gender,
		Constituency: v.Constituency,
		BoothID:      v.BoothID,
		BoothName:    v.BoothName,
		Address:      v.Address,
		PhotoURL:     v.PhotoURL,
		HasVoted:     v.HasVoted,
		VotedAt:      v.VotedAt,
	}
}

// SeedMockData populates Firestore with hackathon demo data
func SeedMockData(ctx context.Context) {
	fs := fb.Get().Firestore
	log.Println("🌱 Seeding mock data...")

	// Seed booth
	booth := models.Booth{
		ID:           "BOOTH-42",
		Name:         "Booth 42 - Andheri East",
		Constituency: "Mumbai North",
		Address:      "Municipal School, Andheri East, Mumbai",
		TotalVoters:  8,
		VotesCast:    1,
		IsActive:     true,
	}
	fs.Collection(ColBooths).Doc(booth.ID).Set(ctx, booth)

	// Seed officer
	officerPwHash := fmt.Sprintf("%x", sha256.Sum256([]byte("officer123")))
	officer := models.BoothOfficer{
		ID:           "OFF-001",
		Name:         "Rajesh Kumar",
		EmployeeCode: "ECI-MH-042",
		BoothID:      "BOOTH-42",
		BoothName:    "Booth 42 - Andheri East",
		PasswordHash: officerPwHash,
		Role:         "OFFICER",
		IsActive:     true,
		CreatedAt:    time.Now(),
	}
	fs.Collection(ColOfficers).Doc(officer.ID).Set(ctx, officer)

	// Seed voters
	voters := []struct {
		aadhaar string
		iris    string
		voter   models.Voter
	}{
		{"234567890123", "IRIS_PRIYA_SHARMA_2024", models.Voter{Name: "Priya Sharma", DOB: "14/03/1988", Gender: "Female", VoterID: "MH/23/142/098765", Constituency: "Mumbai North", BoothID: "BOOTH-42", BoothName: "Booth 42 - Andheri East", Address: "12, Linking Road, Bandra West, Mumbai - 400050", HasVoted: false}},
		{"345678901234", "IRIS_RAHUL_MEHTA_2024", models.Voter{Name: "Rahul Mehta", DOB: "22/07/1975", Gender: "Male", VoterID: "MH/23/142/112233", Constituency: "Mumbai North", BoothID: "BOOTH-42", BoothName: "Booth 42 - Andheri East", Address: "45, MG Road, Andheri East, Mumbai - 400069", HasVoted: false}},
		{"456789012345", "IRIS_ANANYA_KRISHNAN_2024", models.Voter{Name: "Ananya Krishnan", DOB: "05/11/1992", Gender: "Female", VoterID: "MH/23/142/334455", Constituency: "Mumbai North", BoothID: "BOOTH-42", BoothName: "Booth 42 - Andheri East", Address: "78, Marol Naka, Andheri East, Mumbai - 400059", HasVoted: false}},
		{"567890123456", "IRIS_VIKRAM_SINGH_2024", models.Voter{Name: "Vikram Singh", DOB: "30/01/1965", Gender: "Male", VoterID: "MH/23/142/556677", Constituency: "Mumbai North", BoothID: "BOOTH-42", BoothName: "Booth 42 - Andheri East", Address: "3, Chakala, Andheri East, Mumbai - 400093", HasVoted: false}},
		{"678901234567", "IRIS_MEENA_PATEL_2024", models.Voter{Name: "Meena Patel", DOB: "18/09/1980", Gender: "Female", VoterID: "MH/23/142/778899", Constituency: "Mumbai North", BoothID: "BOOTH-42", BoothName: "Booth 42 - Andheri East", Address: "22, MIDC, Andheri East, Mumbai - 400093", HasVoted: false}},
		{"789012345678", "IRIS_ARJUN_NAIR_2024", models.Voter{Name: "Arjun Nair", DOB: "11/04/1998", Gender: "Male", VoterID: "MH/23/142/990011", Constituency: "Mumbai North", BoothID: "BOOTH-42", BoothName: "Booth 42 - Andheri East", Address: "9, JB Nagar, Andheri East, Mumbai - 400059", HasVoted: false}},
		{"890123456789", "IRIS_SUNITA_REDDY_2024", models.Voter{Name: "Sunita Reddy", DOB: "27/06/1955", Gender: "Female", VoterID: "MH/23/142/221133", Constituency: "Mumbai North", BoothID: "BOOTH-42", BoothName: "Booth 42 - Andheri East", Address: "56, Saki Naka, Andheri East, Mumbai - 400072", HasVoted: true}},
		{"901234567890", "IRIS_DEEPAK_JOSHI_2024", models.Voter{Name: "Deepak Joshi", DOB: "03/12/1970", Gender: "Male", VoterID: "MH/23/142/443355", Constituency: "Mumbai North", BoothID: "BOOTH-42", BoothName: "Booth 42 - Andheri East", Address: "11, Powai, Andheri East, Mumbai - 400076", HasVoted: false}},
	}

	for _, v := range voters {
		aadhaarHash := hashAadhaar(v.aadhaar)
		v.voter.AadhaarHash = aadhaarHash
		v.voter.IrisTemplate = hashIris(v.iris)
		v.voter.CreatedAt = time.Now()
		_, err := fs.Collection(ColVoters).Doc(aadhaarHash).Set(ctx, v.voter)
		if err != nil {
			log.Printf("❌ Failed to seed voter %s: %v", v.voter.Name, err)
		} else {
			log.Printf("✅ Seeded voter: %s (Aadhaar: %s...)", v.voter.Name, v.aadhaar[:4])
		}
	}

	// Print test credentials
	log.Println("\n📋 TEST CREDENTIALS:")
	log.Println("   Officer Code: ECI-MH-042")
	log.Println("   Password:     officer123")
	log.Println("\n📋 TEST AADHAAR NUMBERS + IRIS CODES:")

	testData := []struct{ aadhaar, iris, name string }{
		{"234567890123", "IRIS_PRIYA_SHARMA_2024", "Priya Sharma"},
		{"345678901234", "IRIS_RAHUL_MEHTA_2024", "Rahul Mehta"},
		{"890123456789", "IRIS_SUNITA_REDDY_2024", "Sunita Reddy (already voted)"},
	}
	for _, t := range testData {
		j, _ := json.Marshal(map[string]string{"aadhaar_number": t.aadhaar, "iris_scan": t.iris, "biometric_type": "IRIS"})
		log.Printf("   %s → %s\n", t.name, string(j))
	}
}
