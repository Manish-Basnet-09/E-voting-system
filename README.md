# 🗳️ E-Voting System for University Student Council Elections

> A secure, transparent, and verifiable digital voting platform built for Patan Multiple Campus — Tribhuvan University

---

## 📌 Project Overview

This project is submitted to the **Department of Statistics and Computer Science, Patan Multiple Campus** in partial fulfilment of the requirements for the **Bachelor Degree in Computer Science and Information Technology (B.Sc. CSIT)**.

**Submitted By:**
- Ashutosh Adhikari (79010020)
- Manish Basnet (79010054)
- Snehal Sigdel (79010119)

---

## 🔐 Key Security Features

| Feature | Technology |
|---|---|
| Identity Hashing | SHA-256 with Salt |
| Vote Encryption | RSA Asymmetric Encryption |
| Fraud Detection | Isolation Forest (ML) |
| Authentication | Student ID + Password + OTP |
| Session Management | JWT Tokens |
| API Framework | FastAPI (Async) |
| Frontend | React.js |
| Database | PostgreSQL / SQLite |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     E-Voting System                      │
├──────────────┬──────────────────┬───────────────────────┤
│   Frontend   │     Backend      │      ML Engine        │
│  (React.js)  │   (FastAPI)      │  (Scikit-Learn)       │
│              │                  │                       │
│  - Voter UI  │  - Auth APIs     │  - Isolation Forest   │
│  - Admin UI  │  - Vote APIs     │  - Anomaly Scoring    │
│  - RSA Enc.  │  - Admin APIs    │  - Real-time Audit    │
└──────┬───────┴────────┬─────────┴───────────────────────┘
       │   Encrypted     │   JWT/Responses
       │◄───────────────►│
       │                 │
       │          ┌──────▼──────────────┐
       │          │  Database           │
       │          │  (PostgreSQL/SQLite) │
       └──────────┤  - Hashed IDs       │
                  │  - Encrypted Votes  │
                  │  - Audit Logs       │
                  └─────────────────────┘
```

---

## 📁 Project Structure

```
evoting-system/
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI app entrypoint
│   │   ├── config.py                # Settings & env config
│   │   ├── database.py              # DB connection & session
│   │   ├── routers/
│   │   │   ├── auth.py              # Register, login, OTP
│   │   │   ├── voter.py             # Cast vote, ballot
│   │   │   └── admin.py             # Election management
│   │   ├── models/
│   │   │   ├── user.py              # Voter & Admin models
│   │   │   ├── election.py          # Election model
│   │   │   ├── candidate.py         # Candidate model
│   │   │   └── vote.py              # Vote & audit log models
│   │   ├── schemas/
│   │   │   ├── auth.py              # Auth Pydantic schemas
│   │   │   ├── election.py          # Election schemas
│   │   │   └── vote.py              # Vote schemas
│   │   ├── services/
│   │   │   ├── auth_service.py      # SHA-256, JWT, OTP logic
│   │   │   ├── vote_service.py      # RSA encrypt/decrypt
│   │   │   └── election_service.py  # Election CRUD
│   │   ├── ml/
│   │   │   └── anomaly_detector.py  # Isolation Forest engine
│   │   └── utils/
│   │       ├── crypto.py            # RSA key generation
│   │       └── hashing.py           # SHA-256 salted hashing
│   ├── alembic/                     # DB migrations
│   └── tests/                       # Pytest test suite
├── frontend/
│   ├── public/
│   └── src/
│       ├── components/
│       │   ├── auth/                # Login, Register, OTP
│       │   ├── voter/               # Ballot, Confirmation
│       │   ├── admin/               # Dashboard, Management
│       │   └── common/              # Navbar, Footer, etc.
│       ├── pages/                   # Route-level pages
│       ├── context/                 # Auth & Election context
│       ├── hooks/                   # Custom React hooks
│       └── utils/                   # RSA client-side encrypt
├── requirements.txt
├── .gitignore
├── .env.example
└── README.md
```

---

## ⚙️ Setup & Installation

### Prerequisites
- Python 3.10+
- Node.js 18+
- Git

### Backend Setup

```bash
# Clone the repository
git clone https://github.com/your-repo/evoting-system.git
cd evoting-system

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment variables
cp .env.example .env
# Edit .env with your configuration

# Run database migrations
cd backend
alembic upgrade head

# Generate RSA key pair
python -c "from app.utils.crypto import generate_rsa_keys; generate_rsa_keys()"

# Start the backend server
uvicorn app.main:app --reload --port 8000
```

### Frontend Setup

```bash
cd frontend
npm install
npm start
```

The app will be available at `http://localhost:3000`  
API docs at `http://localhost:8000/docs`

---

## 🔑 Algorithms Explained

### 1. SHA-256 (Identity Hashing)
- Student IDs are **never stored in plain text**
- A unique **random salt** is prepended before hashing
- Prevents rainbow table attacks
- Enforces **One-ID-One-Vote** principle

### 2. RSA Encryption (Vote Privacy)
- Votes are encrypted **on the client side** using the election's public key
- Only the admin's private key can decrypt votes at result tabulation
- Even a database breach reveals no actual vote choices

### 3. Isolation Forest (Fraud Detection)
- Trained on normal voting behavior patterns
- Assigns an **anomaly score** (0–1) to every session
- Score → 1: Definite anomaly (flagged)
- Score < 0.5: Normal voting behavior
- Flags: rapid votes, multiple IPs, bot-like patterns

---

## 🗺️ API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Voter registration with ID hashing |
| POST | `/auth/login` | Login with ID + password + OTP |
| GET  | `/voter/ballot` | Retrieve current election ballot |
| POST | `/voter/cast` | Submit encrypted vote |
| GET  | `/admin/dashboard` | Admin monitoring dashboard |
| POST | `/admin/election` | Create/configure election |
| GET  | `/admin/results` | View decrypted results |
| GET  | `/admin/audit-logs` | View anomaly detection logs |

---

## 🧪 Running Tests

```bash
cd backend
pytest tests/ -v
```

---

## 📄 License

This project is developed for academic purposes under Tribhuvan University.

---

## 📚 References

1. R. Rivest, A. Shamir, and L. Adleman — RSA Algorithm
2. H. K. Fatlawi — Isolation Forest for Fraud Detection (2025)
3. S. Tiangolo — FastAPI Documentation (2025)
4. ENISA — Threat Landscape 2025
5. ResearchGate — RSA-based Online Voting Systems (2024)
6. MDPI — Transparent Verifiable E-Voting (2025)
7. IJERT — Face Recognition & Fraud Detection in Voting (2025)
