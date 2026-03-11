# 🗳️ BioVote — Biometric Voter Verification System

**A Golang REST API that uses iris biometric verification to prevent duplicate voting, backed by Firebase Firestore.**

Built for the Election Commission of India (ECI) hackathon — enables polling booth officers to verify voters via Aadhaar + iris scan before allowing them to cast their ballot.

---

## 📁 Project Structure

```
BioVote/
├── main.go               # Entry point — server startup, router setup
├── handlers.go           # HTTP request handlers for all endpoints
├── auth.go               # JWT auth middleware, CORS, role guard
├── auth_service.go       # Officer login, JWT token generation/validation
├── voter_service.go      # Core verification logic, Firestore operations, seeding
├── client.go             # Firebase/Firestore client initialization (singleton)
├── models.go             # Data models, request/response DTOs
├── Dockerfile            # Multi-stage Docker build
├── firestore.rules       # Firestore security rules (backend-only access)
├── firestore.indexes.json # Composite index definitions
├── go.mod / go.sum       # Go module dependencies
└── README.md
```

---

## ⚡ Quick Start

### 1. Prerequisites

- **Go 1.21+** installed
- A **Firebase project** with Firestore enabled
- A **service account key** (JSON) from Firebase Console → Project Settings → Service Accounts → Generate New Private Key

### 2. Clone & Install Dependencies

```bash
git clone https://github.com/your-repo/BioVote.git
cd BioVote
go mod tidy
```

### 3. Run the Server

```bash
FIREBASE_PROJECT_ID=biovote-8cb57 \
FIREBASE_CREDENTIALS_FILE=/path/to/your-service-account-key.json \
SEED_DATA=true \
go run .
```

| Environment Variable | Required | Description |
|---------------------|----------|-------------|
| `FIREBASE_PROJECT_ID` | ✅ | Your Firebase project ID |
| `FIREBASE_CREDENTIALS_FILE` | ✅ (prod) | Path to service account JSON key. If omitted, uses Application Default Credentials |
| `SEED_DATA` | ❌ | Set to `true` to populate Firestore with 8 mock voters + 1 officer |
| `JWT_SECRET` | ❌ | Secret for JWT signing. Defaults to a dev secret |
| `PORT` | ❌ | Server port. Defaults to `8080` |
| `GIN_MODE` | ❌ | Set to `release` for production |

The server starts at **http://localhost:8080**

---

## 🔥 How Data is Stored in Firebase Firestore

The app uses **4 Firestore collections**. All data access happens exclusively through the backend service account — no direct client access is allowed (enforced by `firestore.rules`).

### Collection: `voters`

Stores registered voter records. **Document ID = SHA-256 hash of the Aadhaar number** (raw Aadhaar is never stored).

```
📁 voters/
  📄 a3f8c92e1b7d...  (SHA-256 of "234567890123")
    ├── aadhaar_hash: "a3f8c92e1b7d..."     # SHA-256(SALT + Aadhaar)
    ├── name: "Priya Sharma"
    ├── dob: "14/03/1988"
    ├── gender: "Female"
    ├── voter_id: "MH/23/142/098765"
    ├── constituency: "Mumbai North"
    ├── booth_id: "BOOTH-42"
    ├── booth_name: "Booth 42 - Andheri East"
    ├── address: "12, Linking Road, Bandra West..."
    ├── photo_url: ""
    ├── has_voted: false                     # ← flipped to true after verification
    ├── voted_at: null                       # ← timestamp set after verification
    ├── iris_template: "7b2e4f..."           # SHA-256 hash of iris biometric data
    └── created_at: 2026-03-11T12:07:49Z
```

**Key design choices:**
- Aadhaar is salted + hashed (`SALT_ECI_2024_` prefix) before use as document ID — ensures lookup by Aadhaar is O(1) without storing raw PII
- `has_voted` is updated inside a **Firestore transaction** to prevent race conditions from concurrent kiosk requests
- Iris template is stored as a SHA-256 hash, not raw biometric data

---

### Collection: `audit_logs`

Immutable, append-only log of every verification attempt (success or failure). **Document ID = UUID.**

```
📁 audit_logs/
  📄 550e8400-e29b-41d4-a716-446655440000
    ├── id: "550e8400-e29b-41d4..."
    ├── aadhaar_hash: "a3f8c92e1b7d..."
    ├── voter_name: "Priya Sharma"
    ├── voter_id: "MH/23/142/098765"
    ├── booth_id: "BOOTH-42"
    ├── booth_name: "Booth 42 - Andheri East"
    ├── officer_id: "OFF-001"
    ├── result: "VERIFIED"                   # VERIFIED | DUPLICATE | NOT_FOUND | WRONG_BOOTH | BIOMETRIC_MISMATCH
    ├── biometric_type: "IRIS"
    ├── ip_address: "192.168.1.100"
    ├── tx_hash: "d4e5f6..."                 # SHA-256(aadhaar_hash|result|booth_id|timestamp)
    └── timestamp: 2026-03-11T12:08:15Z
```

**Every verification attempt is logged** — even failures (NOT_FOUND, BIOMETRIC_MISMATCH, etc.). The `tx_hash` provides a tamper-evident audit trail by hashing the payload with a nanosecond timestamp.

---

### Collection: `booth_officers`

Polling officer accounts. **Document ID = officer ID.** Passwords are stored as SHA-256 hashes.

```
📁 booth_officers/
  📄 OFF-001
    ├── id: "OFF-001"
    ├── name: "Rajesh Kumar"
    ├── employee_code: "ECI-MH-042"
    ├── booth_id: "BOOTH-42"
    ├── booth_name: "Booth 42 - Andheri East"
    ├── password_hash: "ef92b..."            # SHA-256 of password (never stored in plain text)
    ├── role: "OFFICER"                      # OFFICER | SUPERVISOR | ADMIN
    ├── is_active: true
    └── created_at: 2026-03-11T12:07:43Z
```

---

### Collection: `booths`

Polling booth metadata and live vote counts. **Document ID = booth ID.**

```
📁 booths/
  📄 BOOTH-42
    ├── id: "BOOTH-42"
    ├── name: "Booth 42 - Andheri East"
    ├── constituency: "Mumbai North"
    ├── address: "Municipal School, Andheri East, Mumbai"
    ├── total_voters: 8
    ├── votes_cast: 1                        # ← incremented atomically after each verified vote
    ├── is_active: true
    └── opened_at: null
```

`votes_cast` is incremented using **Firestore's atomic `Increment(1)`** operation to ensure accuracy under concurrent requests.

---

### Firestore Composite Indexes

Defined in `firestore.indexes.json` — required for compound queries:

| Collection | Fields | Purpose |
|-----------|--------|---------|
| `audit_logs` | `booth_id` ↑ + `timestamp` ↓ | Fetch audit logs for a booth, sorted by time |
| `voters` | `booth_id` ↑ + `has_voted` ↑ | Query voters by booth and voted status |
| `booth_officers` | `employee_code` ↑ + `is_active` ↑ | Officer login lookup |

---

## 🔐 Verification Flow

Here's what happens when an officer scans a voter's iris at the booth:

```
Officer scans voter's Aadhaar + Iris
            │
            ▼
  POST /api/v1/voters/verify
            │
            ▼
  ┌─────────────────────────────┐
  │ 1. Hash Aadhaar (SHA-256)   │
  │ 2. Look up voter document   │──── NOT_FOUND → log + return 404
  │ 3. Check booth assignment   │──── WRONG_BOOTH → log + return 409
  │ 4. Compare iris hash        │──── BIOMETRIC_MISMATCH → log + return 409
  │ 5. Check if already voted   │──── DUPLICATE → log + return 409
  │ 6. Mark as voted (txn)      │──── Race condition? → DUPLICATE
  │ 7. Increment booth count    │
  │ 8. Write audit log          │
  └─────────────────────────────┘
            │
            ▼
     VERIFIED → return 200
     "Proceed to ballot"
```

Step 6 uses a **Firestore transaction** — it re-reads the voter doc inside the transaction to guard against two kiosks verifying the same voter simultaneously.

---

## 🔑 API Reference

### Base URL
```
http://localhost:8080
```

All endpoints except `/health` and `/api/v1/auth/login` require:
```
Authorization: Bearer <JWT token>
```

---

### `GET /health`
Health check — no auth needed.

```json
{ "status": "ok", "service": "ECI Voter Verification API", "version": "1.0.0" }
```

---

### `POST /api/v1/auth/login`
Authenticate a booth officer and receive a JWT token (valid for 12 hours).

**Request:**
```json
{
  "employee_code": "ECI-MH-042",
  "password": "officer123"
}
```

**Response (200):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "officer": {
    "id": "OFF-001",
    "name": "Rajesh Kumar",
    "employee_code": "ECI-MH-042",
    "booth_id": "BOOTH-42",
    "booth_name": "Booth 42 - Andheri East",
    "role": "OFFICER"
  },
  "expires_at": "2026-03-12T00:07:50Z"
}
```

---

### `GET /api/v1/voters/lookup?aadhaar=234567890123`
Look up voter details before biometric scan. Returns public-safe info (no biometric data).

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
Full verification pipeline: Aadhaar → booth check → biometric match → duplicate guard → mark voted.

**Request:**
```json
{
  "aadhaar_number": "234567890123",
  "iris_scan": "IRIS_PRIYA_SHARMA_2024",
  "biometric_type": "IRIS"
}
```

**Result codes:**

| Result | HTTP | Meaning |
|--------|------|---------|
| `VERIFIED` | 200 | Voter cleared — proceed to ballot |
| `DUPLICATE` | 409 | Already voted |
| `NOT_FOUND` | 404 | No Aadhaar record in system |
| `WRONG_BOOTH` | 409 | Voter registered at a different booth |
| `BIOMETRIC_MISMATCH` | 409 | Iris scan doesn't match stored template |

---

### `GET /api/v1/booth/dashboard`
Live turnout stats for the officer's assigned booth.

**Response (200):**
```json
{
  "booth_id": "BOOTH-42",
  "booth_name": "Booth 42 - Andheri East",
  "total_voters": 8,
  "votes_cast": 3,
  "pending": 5,
  "turnout_pct": 37.5,
  "last_updated": "2026-03-11T12:10:00Z"
}
```

---

### `GET /api/v1/booth/audit?limit=50`
Paginated audit trail for this booth (max 200 per request).

**Response (200):**
```json
{
  "booth_id": "BOOTH-42",
  "count": 2,
  "logs": [
    {
      "id": "550e8400-...",
      "voter_name": "Priya Sharma",
      "voter_id": "MH/23/142/098765",
      "result": "VERIFIED",
      "biometric_type": "IRIS",
      "tx_hash": "a3f8c92e...",
      "timestamp": "2026-03-11T12:08:15Z"
    }
  ]
}
```

---

## 🧪 Mock Test Data

Seeded automatically when `SEED_DATA=true`.

### Officer Login
| Field | Value |
|-------|-------|
| Employee Code | `ECI-MH-042` |
| Password | `officer123` |

### Test Voters

| Name | Aadhaar | Iris Code (mock) | Status |
|------|---------|-------------------|--------|
| Priya Sharma | `234567890123` | `IRIS_PRIYA_SHARMA_2024` | Eligible |
| Rahul Mehta | `345678901234` | `IRIS_RAHUL_MEHTA_2024` | Eligible |
| Ananya Krishnan | `456789012345` | `IRIS_ANANYA_KRISHNAN_2024` | Eligible |
| Vikram Singh | `567890123456` | `IRIS_VIKRAM_SINGH_2024` | Eligible |
| Meena Patel | `678901234567` | `IRIS_MEENA_PATEL_2024` | Eligible |
| Arjun Nair | `789012345678` | `IRIS_ARJUN_NAIR_2024` | Eligible |
| Sunita Reddy | `890123456789` | `IRIS_SUNITA_REDDY_2024` | **Already Voted** |
| Deepak Joshi | `901234567890` | `IRIS_DEEPAK_JOSHI_2024` | Eligible |

### Quick Test (cURL)

```bash
# 1. Login
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"employee_code":"ECI-MH-042","password":"officer123"}' | jq -r '.token')

# 2. Lookup a voter
curl -s http://localhost:8080/api/v1/voters/lookup?aadhaar=234567890123 \
  -H "Authorization: Bearer $TOKEN" | jq

# 3. Verify a voter (iris scan)
curl -s -X POST http://localhost:8080/api/v1/voters/verify \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"aadhaar_number":"234567890123","iris_scan":"IRIS_PRIYA_SHARMA_2024","biometric_type":"IRIS"}' | jq

# 4. Try duplicate vote (should return DUPLICATE)
curl -s -X POST http://localhost:8080/api/v1/voters/verify \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"aadhaar_number":"234567890123","iris_scan":"IRIS_PRIYA_SHARMA_2024","biometric_type":"IRIS"}' | jq

# 5. Check dashboard
curl -s http://localhost:8080/api/v1/booth/dashboard \
  -H "Authorization: Bearer $TOKEN" | jq

# 6. View audit logs
curl -s http://localhost:8080/api/v1/booth/audit \
  -H "Authorization: Bearer $TOKEN" | jq
```

---

## 🔒 Security Architecture

```
Booth Kiosk / Frontend
        │
        ▼  HTTPS
   Go API (Gin Framework)
        │
        ├── JWT Authentication (HS256, 12hr expiry, per-officer)
        ├── SHA-256 Aadhaar hashing (salted, raw Aadhaar never stored)
        ├── SHA-256 Iris template hashing (raw biometrics never stored)
        ├── Firestore Transactions (prevents race-condition duplicate votes)
        ├── Immutable Audit Trail (tx_hash = SHA-256 of payload + timestamp)
        └── CORS middleware (configurable allowed origins)
        │
        ▼
   Firebase Firestore
        ├── voters/           (doc ID = aadhaar_hash)
        ├── audit_logs/       (doc ID = UUID, append-only)
        ├── booth_officers/   (doc ID = officer ID)
        └── booths/           (doc ID = booth ID)
```

**Firestore security rules** (`firestore.rules`) deny all direct client access — data is only accessible through the backend service account.

---

## 🐳 Docker Deployment

```bash
docker build -t biovote-api .

docker run -p 8080:8080 \
  -e FIREBASE_PROJECT_ID=biovote-8cb57 \
  -e FIREBASE_CREDENTIALS_FILE=/app/config/key.json \
  -e SEED_DATA=true \
  -v /path/to/your/service-account-key.json:/app/config/key.json:ro \
  biovote-api
```

---

## 📄 License

Built for the ECI Hackathon. For educational and demonstration purposes.
