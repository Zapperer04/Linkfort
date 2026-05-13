# 🛡️ LinkFort - Production Deployment Guide

## Quick Summary of Production Readiness Changes

✅ **Phase 1: Environment Configuration** - DONE
- Created environment variable system for all URLs
- Removed hardcoded localhost references  
- Backend now uses `SHORT_URL_BASE`, `API_BASE_URL`, `FRONTEND_URL` env vars
- Frontend now uses `REACT_APP_API_BASE`, `REACT_APP_SHORT_URL_BASE`, `REACT_APP_APP_BASE` env vars

✅ **Phase 2: Security & Configuration** - DONE
- Disabled debug mode (`debug=True` removed)
- Improved CORS to support multiple origins
- Created `.env.example` templates for documentation
- Separated local dev config from production config

✅ **Phase 3: Dependencies & Deployment** - DONE
- Created `requirements.txt` with all Python dependencies
- Added `axios` to frontend package.json
- Created `Dockerfile` for backend containerization
- Created `docker-compose.yml` for local testing
- Created `render.yaml` for Render deployment
- Created `vercel.json` for Vercel frontend deployment

---

## 🚀 DEPLOYMENT ROADMAP

### **Step 1: Local Testing**

Test everything works locally before deploying:

```bash
# Backend (in root directory)
python app.py

# Frontend (in frontend directory)
npm start
```

**Verify:**
- ✅ Backend starts without errors
- ✅ Frontend connects to http://localhost:5000
- ✅ Can register/login
- ✅ Can create short links
- ✅ Short links use http://localhost:5000/abc123
- ✅ Redirects work

### **Step 2: Set Up Neon PostgreSQL (Free)**

1. Go to https://neon.tech
2. Sign up (free tier: 3 databases, 0.5 GB storage)
3. Create a new project called "linkfort"
4. Copy the connection string (looks like: `postgresql://user:password@ep-xxx.neon.tech/linkfort?sslmode=require`)
5. Add `?sslmode=require` to the end if not present

### **Step 3: Set Up Render (Backend + Redis)**

1. Go to https://render.com
2. Sign up (free tier: 1 web service, 1 database, 1 Redis instance, $7 credit/month)
3. Create a new project
4. In the Render dashboard, create these three services:

**3a. PostgreSQL Database**
- Name: `linkfort-db`
- Database: `linkfort`
- User: `linkfort_user`
- Leave password auto-generated
- Region: Choose closest to your location
- Note the connection string

**3b. Redis**
- Name: `linkfort-cache`
- Region: Same as database
- Note the connection string

**3c. Web Service (Backend)**
- Connect your GitHub repo
- Name: `linkfort-api`
- Runtime: `python 3.11`
- Build Command: `pip install -r requirements.txt`
- Start Command: `gunicorn --workers=2 --worker-class=sync --bind=0.0.0.0:$PORT --timeout=30 app:app`
- Environment Variables:
  ```
  FLASK_ENV=production
  SECRET_KEY=<generate-random-32-char-string>
  DATABASE_URL=<from-step-3a>
  REDIS_URL=<from-step-3b>
  BASE_URL=https://linkfort-api.render.com
  SHORT_URL_BASE=https://lf.render.com
  API_BASE_URL=https://api.render.com
  FRONTEND_URL=https://linkfort.vercel.app
  VIRUSTOTAL_API_KEY=<existing-key>
  GOOGLE_SAFE_BROWSING_API_KEY=<existing-key>
  ```
- Auto-deploy: Yes (from main branch)

### **Step 4: Set Up Vercel (Frontend)**

1. Go to https://vercel.com
2. Sign up (free tier: unlimited deployments, serverless functions)
3. Import your GitHub repository
4. Framework: `Create React App`
5. Build Command: `cd frontend && npm run build`
6. Output Directory: `frontend/build`
7. Environment Variables:
   ```
   REACT_APP_API_BASE=https://linkfort-api.render.com
   REACT_APP_SHORT_URL_BASE=https://lf.render.com
   REACT_APP_APP_BASE=https://linkfort.vercel.app
   ```
8. Deploy

### **Step 5: Set Up Custom Domain (Optional)**

If you have a custom domain (e.g., `linkfort.io`):

1. Buy domain from Namecheap (~$10/year)
2. In Vercel: Add custom domain `linkfort.yourdomain.com`
3. In Render: Add custom domain for backend `api.yourdomain.com`
4. Update DNS records as instructed by Vercel/Render

**Until then, use free subdomains:**
- Frontend: `https://linkfort.vercel.app`
- Backend: `https://linkfort-api.render.com`
- Short links: `https://linkfort-api.render.com/abc123`

---

## 📋 LOCAL DEVELOPMENT

### Setup

```bash
# Clone repo
git clone <repo-url>
cd linkfort

# Backend
python -m venv venv
source venv/bin/activate  # or: venv\Scripts\activate (Windows)
pip install -r requirements.txt

# Frontend
cd frontend
npm install
```

### Environment Files

**`.env` (Backend - LOCAL)**
```
FLASK_ENV=development
DATABASE_URL=postgresql://linkfort_user:postgres@localhost:5432/linkfort
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=dev-secret-key-change-in-production
BASE_URL=http://localhost:5000
SHORT_URL_BASE=http://localhost:5000
API_BASE_URL=http://localhost:5000
FRONTEND_URL=http://localhost:3000
```

**`frontend/.env` (Frontend - LOCAL)**
```
REACT_APP_API_BASE=http://localhost:5000
REACT_APP_SHORT_URL_BASE=http://localhost:5000
REACT_APP_APP_BASE=http://localhost:3000
```

### Run Locally

**Terminal 1: Backend**
```bash
python app.py
# Server runs on http://localhost:5000
```

**Terminal 2: Frontend**
```bash
cd frontend
npm start
# App runs on http://localhost:3000
```

### Run with Docker

```bash
# Make sure Docker and Docker Desktop are running
docker-compose up

# Backend: http://localhost:5000
# Frontend: http://localhost:3000 (not exposed in compose, use npm start instead)
```

---

## 🔐 Production Secrets Management

### Never commit these:
- `.env` (use `.env.example` template instead)
- API keys
- Database passwords
- JWT secret

### For production, set environment variables in:

**Render:**
- Web Service → Environment
- Database → Use Render's managed PostgreSQL
- Redis → Use Render's managed Redis

**Vercel:**
- Project Settings → Environment Variables
- Set values for: `REACT_APP_API_BASE`, `REACT_APP_SHORT_URL_BASE`, `REACT_APP_APP_BASE`

---

## ✅ PRODUCTION CHECKLIST

### Before First Deploy:
- [ ] Backend runs locally with `python app.py`
- [ ] Frontend builds with `npm run build`
- [ ] No secrets in `.env` file committed
- [ ] `.env` is in `.gitignore`
- [ ] Database migrations tested (if any)
- [ ] Test with production URLs locally

### After Render Backend Deploy:
- [ ] Test `/api/health` endpoint responds
- [ ] Test `/api/auth/register` works
- [ ] Test `/api/auth/login` works
- [ ] Test `/api/shorten` creates short URL with production domain
- [ ] Test short URL redirect works

### After Vercel Frontend Deploy:
- [ ] Frontend loads on custom domain
- [ ] Login/signup works
- [ ] Can create short URL
- [ ] Short URL displays production domain
- [ ] Clicking short URL redirects correctly

---

## 🐛 Troubleshooting

### "Connection refused" when frontend calls backend
- Check `REACT_APP_API_BASE` env var is correct
- Check backend CORS allows your frontend domain
- Check backend is actually running

### "Database connection failed"
- Check `DATABASE_URL` env var is correct
- Check PostgreSQL is running (Neon or local)
- Test connection: `psql <DATABASE_URL>`

### "Short URLs show localhost instead of production domain"
- Check `SHORT_URL_BASE` env var is set
- Check backend is running with production config
- Restart backend after changing env vars

### "CORS error in browser console"
- Frontend domain must be in `FRONTEND_URL` env var
- Backend uses this to configure CORS
- Restart backend after changing CORS config

---

## 📚 Environment Variables Reference

### Backend (.env)

| Variable | Local Value | Production Value | Purpose |
|----------|-------------|------------------|---------|
| `FLASK_ENV` | `development` | `production` | Enable/disable debug mode |
| `DATABASE_URL` | `postgresql://...@localhost/linkfort` | `postgresql://...@neon.tech/linkfort` | Database connection |
| `REDIS_URL` | `redis://localhost:6379/0` | `redis://...render.com...` | Cache connection |
| `SECRET_KEY` | `dev-secret-key...` | Generated 32-char string | JWT signing key |
| `BASE_URL` | `http://localhost:5000` | `https://api.yourdomain.com` | API base (fallback) |
| `SHORT_URL_BASE` | `http://localhost:5000` | `https://lf.yourdomain.com` | Short link domain |
| `FRONTEND_URL` | `http://localhost:3000` | `https://yourdomain.com` | CORS origin |
| `VIRUSTOTAL_API_KEY` | Your test key | Your production key | Threat detection API |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Your test key | Your production key | Threat detection API |

### Frontend (.env.production)

| Variable | Value |  Purpose |
|----------|-------|---------|
| `REACT_APP_API_BASE` | `https://api.yourdomain.com` | Backend API endpoint |
| `REACT_APP_SHORT_URL_BASE` | `https://lf.yourdomain.com` | Short URL display |
| `REACT_APP_APP_BASE` | `https://yourdomain.com` | Frontend domain |

---

## 🎯 Final Architecture

```
┌─────────────────────────────────────────────────┐
│ User Browser: https://linkfort.vercel.app      │
│ (Vercel - Frontend React app)                  │
└────────────────┬────────────────────────────────┘
                 │
        ┌────────┴────────┐
        │                 │
        ▼                 ▼
   ┌─────────────┐  ┌──────────────────┐
   │ API Calls   │  │ View Short Links │
   │ GET /api/*  │  │ https://lf.xx/   │
   │             │  │                  │
   └────────┬────┘  └────────┬─────────┘
            │                │
            ▼                ▼
   ┌──────────────────────────────────────┐
   │ Backend: https://linkfort-api.render │
   │ (Render - Flask application)         │
   │ with Gunicorn                        │
   └───────────────┬──────────────────────┘
                   │
        ┌──────────┼──────────┐
        │          │          │
        ▼          ▼          ▼
   ┌─────────────┐ ┌──────────┐ ┌──────────┐
   │ PostgreSQL  │ │  Redis   │ │ External │
   │  (Neon)     │ │ (Render) │ │   APIs   │
   └─────────────┘ └──────────┘ └──────────┘
```

---

## Next Steps

1. ✅ **Code is production-ready** (you are here)
2. ⬜ Set up Neon PostgreSQL
3. ⬜ Deploy backend to Render
4. ⬜ Deploy frontend to Vercel
5. ⬜ Test production flow
6. ⬜ Add custom domain (optional)

Let me know when you're ready for the next step!
