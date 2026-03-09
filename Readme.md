# 🛡️ LinkFort - Intelligent URL Risk Detection System

A modern URL shortening service with built-in **3-layer AI threat detection** that protects users from phishing, malware, and malicious links. Create short, safe, and trackable links with advanced security features.

![LinkFort](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)
![Python](https://img.shields.io/badge/Python-3.11-blue)
![Flask](https://img.shields.io/badge/Flask-3.1-lightgrey)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-12+-blue)
![React](https://img.shields.io/badge/React-18-61dafb)

---

## 🚀 Features

### 🔒 **Advanced Security**
- **3-Layer Threat Detection**
  - Layer 1: Heuristic pattern analysis (phishing keywords, suspicious structures)
  - Layer 2: Domain reputation & SSL validation
  - Layer 3: External API integration (Google Safe Browsing, VirusTotal)
- Real-time threat scoring (0.0 - 1.0)
- Automatic blocking of malicious URLs
- Warning pages for suspicious links with user override option

### 🔗 **URL Shortening**
- Auto-generated short codes (base62 encoding)
- Custom short codes (3-20 characters)
- Reserved word protection
- Duplicate URL detection
- URL expiration (1-365 days)
- Instant code availability checking

### 📊 **Analytics & Tracking**
- Click tracking with timestamps
- IP address logging
- Real-time dashboard with statistics
- 7-day threat trend analysis
- Hourly click patterns
- Top blocked domains report

### 👤 **User Management**
- JWT-based authentication (24-hour tokens)
- Bcrypt password hashing
- User dashboard with personal stats
- URL ownership and management
- Rate limiting (10 requests/min per IP)

### ⚡ **Performance**
- Redis caching for popular links (~80% hit rate)
- Sub-100ms response time for cached URLs
- Optimized database queries
- Connection pooling

---

## 🏗️ Architecture
```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│   React     │─────▶│  Flask API   │─────▶│ PostgreSQL  │
│  Frontend   │      │  (Port 5000) │      │  Database   │
│             │◀─────│  + JWT Auth  │◀─────│             │
└─────────────┘      └──────┬───────┘      └─────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │ Redis Cache  │
                     │ Rate Limit   │
                     └──────────────┘
                            │
                            ▼
                  ┌─────────────────┐
                  │ Threat Detection│
                  │   3-Layer AI    │
                  │  ┌──────────┐   │
                  │  │ Layer 1  │   │
                  │  │Heuristic │   │
                  │  └────┬─────┘   │
                  │  ┌────▼─────┐   │
                  │  │ Layer 2  │   │
                  │  │ Domain   │   │
                  │  └────┬─────┘   │
                  │  ┌────▼─────┐   │
                  │  │ Layer 3  │   │
                  │  │External  │   │
                  │  │  APIs    │   │
                  │  └──────────┘   │
                  └─────────────────┘
```

---

## 📋 Tech Stack

**Backend:**
- Python 3.11
- Flask (Web Framework)
- SQLAlchemy (ORM)
- PostgreSQL (Database)
- Redis (Caching & Rate Limiting)
- Flask-JWT-Extended (Authentication)
- Flask-Bcrypt (Password Hashing)
- Validators (URL Validation)

**Frontend:**
- React 18
- Axios (HTTP Client)
- React Router (Navigation)

**Security:**
- 3-Layer AI Threat Detection
- JWT Token Authentication
- Bcrypt Password Hashing
- Rate Limiting
- CORS Protection

---

## 🛠️ Installation

### Prerequisites

- Python 3.11+
- PostgreSQL 12+
- Redis 5+
- Node.js 16+ (for React frontend)

### Backend Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/linkfort.git
cd linkfort

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file
cp .env.example .env
# Edit .env with your configuration
```

### Database Setup
```sql
-- Create PostgreSQL database
CREATE DATABASE linkfort_db;
```
```python
# Initialize database tables
python
>>> from app import app, db
>>> with app.app_context():
>>>     db.create_all()
>>> exit()
```

### Redis Setup
```bash
# Start Redis server
redis-server

# Verify Redis is running
redis-cli ping
# Should return: PONG
```

### Environment Variables

Create a `.env` file in the root directory:
```env
# Database
DATABASE_URL=postgresql://username:password@localhost/linkfort_db

# Security
SECRET_KEY=your-super-secret-key-change-this-in-production
JWT_SECRET_KEY=your-jwt-secret-key-change-this-too

# Redis
REDIS_URL=redis://localhost:6379/0

# Application
BASE_URL=http://localhost:5000
FLASK_ENV=development

# Optional: External API Keys (for enhanced threat detection)
VIRUSTOTAL_API_KEY=your-virustotal-key
GOOGLE_SAFE_BROWSING_KEY=your-google-key
```

---

## 🚀 Running the Application

### Backend (Flask API)
```bash
cd linkfort
venv\Scripts\activate  # Windows
source venv/bin/activate  # macOS/Linux

python app.py
# Server runs on http://localhost:5000
```

### Frontend (React)
```bash
cd frontend
npm install
npm start
# Dashboard opens at http://localhost:3000
```

---


## 🔒 Threat Detection System

### Layer 1: Heuristic Analysis
- Analyzes URL structure and patterns
- Detects suspicious keywords (login, verify, account, security)
- Checks for IP addresses in URLs
- Identifies suspicious character encodings
- Validates against known malicious TLDs

### Layer 2: Domain Reputation
- Checks domain age (new domains = higher risk)
- Validates SSL certificates
- Analyzes WHOIS data
- Cross-references known bad domain lists

### Layer 3: External API Integration
- Google Safe Browsing API
- VirusTotal API
- URLhaus malware database
- PhishTank phishing database

### Threat Scoring

| Score Range | Verdict | Action |
|-------------|---------|--------|
| 0.0 - 0.3 | ✅ SAFE | Direct redirect |
| 0.3 - 0.6 | ⚠️ WARN | Show warning page |
| 0.6 - 1.0 | 🚫 BLOCK | Reject URL |

---

## 📊 Performance Metrics

- **API Response Time:** <100ms (cached), <500ms (uncached with threat detection)
- **Cache Hit Rate:** ~80% for popular links
- **Threat Detection Speed:** 200-500ms (includes external API calls)
- **Rate Limit:** 10 requests/minute per IP
- **Database Queries:** 1-3 per request (optimized with eager loading)

---

## 🧪 Testing

### Manual Testing
```bash
# Test URL shortening
curl -X POST http://localhost:5000/api/shorten \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'

# Test redirection
curl -L http://localhost:5000/{short_code}

# Test authentication
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@test.com","password":"test123"}'
```

### Testing Threat Detection
```python
# Safe URL
POST /api/shorten
{"url": "https://google.com"}
# Expected: threat_score ~0.1, verdict: SAFE

# Suspicious URL (example - don't actually use malicious URLs)
POST /api/shorten
{"url": "http://suspicious-site-login-verify.xyz"}
# Expected: threat_score ~0.5, verdict: WARN

# Known malicious (blocked)
# System will reject and return 403
```

---

## 📁 Project Structure
```
linkfort/
├── app.py                  # Main Flask application
├── models.py              # Database models (User, URL, Click)
├── config.py              # Configuration settings
├── utils.py               # Helper functions
├── cache.py               # Redis caching & rate limiting
├── threat_detection.py    # 3-layer threat detection system
├── requirements.txt       # Python dependencies
├── .env.example          # Example environment variables
├── .gitignore            # Git ignore file
├── README.md             # This file
└── frontend/             # React frontend (separate)
    ├── src/
    ├── public/
    └── package.json
```

---



## 👤 Author

**Your Name**
- GitHub: [@Zapperer04](https://github.com/Zapperer04)
- LinkedIn: [Kaustav Kumar](https://www.linkedin.com/in/kaustavvkumar)
- Email: bitkaustav@gmail.com

---



