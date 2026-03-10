# 🗳️ ECI Voter Verification System — Backend API
**Tech Stack: GoLang + Firebase Firestore**

---

## 📁 Project Structure

```
voter-verification/
├── cmd/
│   └── main.go                  # Entry point, router setup
├── internal/
│   ├── models/
│   │   └── models.go            # Voter, AuditLog, Officer structs + DTOs
│   ├── firebase/
│   │   └── client.go            # Firebase/Firestore initialization
│   ├── services/
│   │   ├── voter_service.go     # Core verification logic + Firestore ops
│   │   └── auth_service.go      # JWT login/validation for officers
│   ├── middleware/
│   │   └── auth.go              # JWT middleware, CORS, role guard
│   └── handlers/
│       └── handlers.go          # HTTP handlers for all endpoints
├── firestore.rules              # Firestore security rules
├── firestore.indexes.json       # Composite index definitions
├── Dockerfile                   # Container build
├── .env.example                 # Environment variable template
└── README.md
```

---

## ⚡ Quick Start

### 1. Firebase Setup
1. Go to [Firebase Console](https://console.firebase.google.com)
2. Create a new project (e.g., `eci-voter-verification`)
3. Enable **Firestore Database** (Start in test mode for hackathon)
4. Go to **Project Settings → Service Accounts → Generate new private key**
5. Save the JSON file as `config/serviceAccountKey.json`

### 2. Environment Setup
```bash
cp .env.example .env
# Edit .env with your Firebase project ID
```

### 3. Run the Server
```bash
# Install dependencies
go mod tidy

# Seed mock data + start server
SEED_DATA=true go run ./cmd/main.go

# Or with .env file (use godotenv or export vars)
export $(cat .env | xargs) && go run ./cmd/main.go
```

### 4. Deploy Firestore Rules & Indexes
```bash
firebase deploy --only firestore
```

---

## 🔑 API Reference

### Base URL
```
http://localhost:8080
```

---

### `GET /health`
Health check — no auth required.

**Response:**
```json
{ "status": "ok", "service": "ECI Voter Verification API", "version": "1.0.0" }
```

---

### `POST /api/v1/auth/login`
Authenticate a booth officer and receive a JWT token.

**Request:**
```json
{
  "employee_code": "ECI-MH-042",
  "password": "officer123"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "officer": {
    "id": "OFF-001",
    "name": "Rajesh Kumar",
    "employee_code": "ECI-MH-042",
    "booth_id": "BOOTH-42",
    "booth_name": "Booth 42 - Andheri East",
    "role": "OFFICER"
  },
  "expires_at": "2024-11-15T20:00:00Z"
}
```

---

### `GET /api/v1/voters/lookup?aadhaar=234567890123`
Look up voter record before biometric scan.
**Auth required:** `Authorization: Bearer <token>`

**Response (200):**
```json
{
  "name": "Priya Sharma",
  "voter_id": "MH/23/142/098765",
  "dob": "14/03/1988",
  "gender": "Female",
  "constituency": "Mumbai North",
  "booth_id": "BOOTH-42",
  "booth_name": "Booth 42 - Andheri East",
  "address": "12, Linking Road, Bandra West, Mumbai - 400050",
  "has_voted": false
}
```

---

### `POST /api/v1/voters/verify`
Run full verification: Aadhaar lookup → biometric match → duplicate check → mark voted.
**Auth required:** `Authorization: Bearer <token>`

**Request:**
```json
{
  "aadhaar_number": "234567890123",
  "iris_scan": "IRIS_PRIYA_SHARMA_2024",
  "biometric_type": "IRIS"
}
```

**Response — VERIFIED (200):**
```json
{
  "result": "VERIFIED",
  "message": "Voter successfully verified. Proceed to ballot.",
  "voter": { "name": "Priya Sharma", "has_voted": true, ... },
  "tx_hash": "a3f8c92e1b7d...",
  "timestamp": "2024-11-15T09:32:11Z"
}
```

**Response — DUPLICATE (409):**
```json
{
  "result": "DUPLICATE",
  "message": "Vote already cast at 2024-11-15T08:15:00Z",
  "tx_hash": "b7e3a12f4c9d...",
  "timestamp": "2024-11-15T09:45:00Z"
}
```

**Possible result values:**

| Result | HTTP | Meaning |
|--------|------|---------|
| `VERIFIED` | 200 | Voter cleared to vote |
| `DUPLICATE` | 409 | Already voted |
| `NOT_FOUND` | 404 | No Aadhaar record |
| `WRONG_BOOTH` | 409 | Assigned to different booth |
| `BIOMETRIC_MISMATCH` | 409 | Iris scan doesn't match |

---

### `GET /api/v1/booth/dashboard`
Live stats for the officer's assigned booth.
**Auth required:** `Authorization: Bearer <token>`

**Response:**
```json
{
  "booth_id": "BOOTH-42",
  "booth_name": "Booth 42 - Andheri East",
  "total_voters": 8,
  "votes_cast": 3,
  "pending": 5,
  "turnout_pct": 37.5,
  "last_updated": "2024-11-15T10:00:00Z"
}
```

---

### `GET /api/v1/booth/audit?limit=50`
Paginated audit log for this booth.
**Auth required:** `Authorization: Bearer <token>`

**Response:**
```json
{
  "booth_id": "BOOTH-42",
  "count": 3,
  "logs": [
    {
      "id": "uuid-here",
      "voter_name": "Priya Sharma",
      "voter_id": "MH/23/142/098765",
      "result": "VERIFIED",
      "biometric_type": "IRIS",
      "tx_hash": "a3f8c92e...",
      "timestamp": "2024-11-15T09:32:11Z"
    }
  ]
}
```

---

## 🧪 Mock Test Data (seeded automatically with SEED_DATA=true)

### Officer Login
| Field | Value |
|-------|-------|
| Employee Code | `ECI-MH-042` |
| Password | `officer123` |

### Voter Aadhaar + Iris Codes

| Voter Name | Aadhaar | Iris Scan (mock) | Status |
|------------|---------|------------------|--------|
| Priya Sharma | `234567890123` | `IRIS_PRIYA_SHARMA_2024` | Eligible |
| Rahul Mehta | `345678901234` | `IRIS_RAHUL_MEHTA_2024` | Eligible |
| Ananya Krishnan | `456789012345` | `IRIS_ANANYA_KRISHNAN_2024` | Eligible |
| Vikram Singh | `567890123456` | `IRIS_VIKRAM_SINGH_2024` | Eligible |
| Meena Patel | `678901234567` | `IRIS_MEENA_PATEL_2024` | Eligible |
| Arjun Nair | `789012345678` | `IRIS_ARJUN_NAIR_2024` | Eligible |
| Sunita Reddy | `890123456789` | `IRIS_SUNITA_REDDY_2024` | **Already Voted** |
| Deepak Joshi | `901234567890` | `IRIS_DEEPAK_JOSHI_2024` | Eligible |

---

## 🔒 Security Architecture

```
Booth Kiosk
    │
    ▼ HTTPS
GoLang API (Gin)
    │
    ├── JWT Auth (12hr expiry, per-officer)
    ├── SHA-256 Aadhaar hashing (never stored raw)
    ├── SHA-256 Iris template hashing
    ├── Firestore Transaction (prevents race conditions)
    └── Immutable Audit Log (tx_hash for every event)
    │
    ▼
Firebase Firestore
    │
    ├── voters/        (aadhaar_hash as doc ID)
    ├── audit_logs/    (UUID doc IDs, append-only)
    ├── booth_officers/
    └── booths/
```

---

## 🚀 Docker Deployment
```bash
docker build -t voter-api .
docker run -p 8080:8080 \
  -e FIREBASE_PROJECT_ID=your-project-id \
  -e FIREBASE_CREDENTIALS_FILE=/app/config/key.json \
  -v $(pwd)/config:/app/config \
  voter-api
```
