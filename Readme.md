# 🛡️ LinkFort — Intelligent URL Risk Detection System

A modern URL shortening service with built-in **3-layer AI threat detection** that protects users from phishing, malware, and malicious links. Create short, safe, and trackable links with advanced security features.

![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)
![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-2.3-lightgrey)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-12+-blue)
![React](https://img.shields.io/badge/React-19-61dafb)

---

## 🚀 Features

### 🔒 Advanced Security
- **3-Layer Threat Detection**
  - Layer 1: Heuristic pattern analysis (phishing keywords, suspicious structures)
  - Layer 2: Domain reputation & SSL validation
  - Layer 3: External API integration (Google Safe Browsing, VirusTotal)
- Real-time threat scoring (0.0 – 1.0)
- Automatic blocking of malicious URLs
- Warning pages for suspicious links with user override

### 🔗 URL Shortening
- Auto-generated short codes (base62 encoding)
- Custom short codes (3–20 characters)
- Reserved word protection & duplicate detection
- URL expiration (1–365 days)

### 📊 Analytics & Tracking
- Click tracking with timestamps and IP logging
- Real-time dashboard with statistics
- 7-day threat trend analysis & hourly click patterns

### 👤 User Management
- JWT-based authentication (24-hour tokens)
- Bcrypt password hashing
- Per-user URL dashboard
- Rate limiting (10 requests/min per IP)

### ⚡ Performance
- Redis caching (~80% hit rate on popular links)
- Sub-100ms response for cached URLs

---

## 🏗️ Architecture

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│   React     │─────▶│  Flask API   │─────▶│ PostgreSQL  │
│  Frontend   │      │  (Port 5000) │      │  Database   │
│ Port 3000   │◀─────│  + JWT Auth  │◀─────│             │
└─────────────┘      └──────┬───────┘      └─────────────┘
                            │
                     ┌──────▼───────┐
                     │ Redis Cache  │
                     │ Rate Limit   │
                     └──────────────┘
                            │
                   ┌────────▼────────┐
                   │ Threat Detection │
                   │   3-Layer AI    │
                   └─────────────────┘
```

---

## 📋 Tech Stack

| Layer    | Technology |
|----------|------------|
| Backend  | Python 3.10+, Flask, SQLAlchemy, Flask-JWT-Extended, Flask-Bcrypt |
| Database | PostgreSQL 12+ |
| Cache    | Redis 5+ |
| Frontend | React 19, Axios |
| ML       | XGBoost, scikit-learn |
| Deploy   | Docker / Render / Vercel |

---

## 🛠️ Local Setup

### Prerequisites
- Python 3.10+
- PostgreSQL 12+
- Redis 5+
- Node.js 18+ (via [nvm](https://github.com/nvm-sh/nvm) recommended)

### 1. Backend

```bash
git clone https://github.com/Zapperer04/linkfort.git
cd linkfort

python3 -m venv venv
source venv/bin/activate          # macOS / Linux

pip install -r requirements.txt

cp .env.example .env              # fill in your values
```

### 2. Database

```sql
-- In psql
CREATE DATABASE linkfort_db;
```

```python
# Then initialise tables once
python3 -c "from app import app, db; app.app_context().push(); db.create_all()"
```

### 3. Redis

```bash
brew install redis   # macOS
redis-server
```

### 4. Frontend

```bash
cd frontend
npm install
npm start            # http://localhost:3000
```

### 5. Start the API

```bash
# From project root, venv active
python app.py        # http://localhost:5000
```

---

## ⚙️ Environment Variables

Copy `.env.example` to `.env` and fill in:

```env
DATABASE_URL=postgresql://user:password@localhost/linkfort_db
SECRET_KEY=change-me
JWT_SECRET_KEY=change-me-too
REDIS_URL=redis://localhost:6379/0
BASE_URL=http://localhost:5000
FLASK_ENV=development

# Optional — enhances threat detection
VIRUSTOTAL_API_KEY=
GOOGLE_SAFE_BROWSING_KEY=
```

---

## 🔒 Threat Scoring

| Score     | Verdict       | Action             |
|-----------|---------------|--------------------|
| 0.0 – 0.3 | ✅ SAFE       | Direct redirect    |
| 0.3 – 0.6 | ⚠️ WARN       | Show warning page  |
| 0.6 – 1.0 | 🚫 BLOCK      | Reject URL (403)   |

---

## 🧪 Testing

```bash
# Run the test suite (requires running DB)
source venv/bin/activate
pytest tests/ -v
```

Quick API smoke tests:

```bash
# Shorten a URL
curl -X POST http://localhost:5000/api/shorten \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'

# Follow a short link
curl -L http://localhost:5000/{short_code}

# Register a user
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@test.com","password":"test123"}'
```

---

## 📁 Project Structure

```
linkfort/
├── app.py                  # Flask application & routes
├── models.py               # SQLAlchemy models (User, URL, Click)
├── config.py               # Configuration
├── cache.py                # Redis caching & rate limiting
├── threat_detection.py     # 3-layer threat detection engine
├── worker.py               # Background job worker
├── utils.py                # Shared helpers
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variable template
├── pyrightconfig.json      # Python type-checker config
├── Dockerfile              # Container build
├── docker-compose.yml      # Local multi-service setup
├── render.yaml             # Render.com deployment config
├── vercel.json             # Vercel deployment config
│
├── scripts/
│   └── train_ml_model.py   # Re-train the phishing detection model
│
├── tests/
│   ├── test_db_urls.py     # URL model & verdict distribution tests
│   └── test_config.py      # App config & short URL generation tests
│
├── docs/
│   └── DEPLOYMENT.md       # Production deployment guide
│
└── frontend/               # React frontend
    ├── src/
    │   ├── components/     # Page components
    │   ├── context/        # Auth context
    │   ├── App.js
    │   └── index.js
    └── package.json
```

---

## 👤 Author

**Kaustav Kumar**
- GitHub: [@Zapperer04](https://github.com/Zapperer04)
- LinkedIn: [Kaustav Kumar](https://www.linkedin.com/in/kaustavvkumar)
- Email: bitkaustav@gmail.com
