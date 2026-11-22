# PHASE 1: REPOSITORY & DEPENDENCY NORMALIZATION REPORT
**Project**: CyberScout / PhishGuard Pro (Unified AI Cyber Defence System)  
**Workspace**: `P:\Phishing-Url-and-Spam-Email-Detection-`  
**Challenge**: PromptWars × Techverse Solutions Defence and Security Challenge  
**Date**: November 22, 2026  
**Status**: COMPLETED – PENDING USER APPROVAL  

---

## 1. Executive Summary

Phase 1 (Repository & Dependency Normalization) has been successfully executed without breaking any existing features, replacing frontend components, or altering machine learning weights. All API ports across the frontend, backend, deployment manifests, and browser extension have been unified to **Port 8000** with environment-variable override support (`PORT`). A minimal, reproducible `requirements.txt` was created, exposed database credentials were removed, and both frontend production compilation and backend startup smoke tests were verified passing.

---

## 2. Files Created, Modified, and Removed

| File Path | Action | Description |
| :--- | :---: | :--- |
| `requirements.txt` | **Created** | Pinned, reproducible Python dependencies compatible with Python 3.11/3.12 |
| `PHASE1_REPOSITORY_NORMALIZATION_REPORT.md` | **Created** | Comprehensive Phase 1 verification documentation |
| `src/api_fastapi.py` | **Modified** | Removed hardcoded MongoDB credentials comment; added dynamic `PORT` execution block; added defensive SHAP/LIME import guards |
| `frontend/src/utils/api.js` | **Modified** | Standardized `API_BASE_URL` fallback from port 5000 to port 8000 |
| `extension/manifest.json` | **Modified** | Granted `host_permissions` for `http://localhost:8000/*` and `http://127.0.0.1:8000/*` |
| `extension/background.js` | **Modified** | Standardized `API_BASE` from port 5000 to port 8000 |
| `extension/popup.js` | **Modified** | Standardized connection and error text from port 5000 to port 8000 |
| `start_api.sh` | **Modified** | Standardized port from 8001 to 8000 with dynamic `$PORT` and `$HOST` fallback |
| `build.sh` | **Modified** | Corrected build script to install `requirements.txt` cleanly |
| `render.yaml` | **Modified** | Renamed service to `cyberscout-api`, standardized health check `/` and port 8000 |
| `.gitignore` | **Modified** | Added exclusions for `node_modules/`, `.pytest_cache/`, `dist/`, `.env*`, and whitelisted `!requirements.txt`, `!.env.example` |
| `.env.example` | **Modified** | Added standardized documentation for `PORT=8000`, `HOST=0.0.0.0`, and `VITE_API_URL` |
| `src/__pycache__/` | **Cleaned** | Purged untracked compiled `.pyc` caches from disk |

---

## 3. Dependency Changes

### Python Dependencies (`requirements.txt`)
Previously, `requirements.txt` was missing from the repository, causing automated CI/CD and container builds to fail. A clean, pinned manifest was created:

```text
fastapi>=0.111.0,<0.116.0
uvicorn[standard]>=0.30.0,<0.35.0
pydantic>=2.7.0,<3.0.0
requests>=2.31.0,<3.0.0
beautifulsoup4>=4.12.0,<5.0.0
tldextract>=5.1.0,<6.0.0
scikit-learn>=1.4.0,<1.9.0
joblib>=1.3.0,<2.0.0
pandas>=2.1.0,<3.0.0
numpy>=1.26.0,<2.3.0
pymongo>=4.6.0,<5.0.0
python-dotenv>=1.0.0,<2.0.0
shap>=0.44.0,<0.51.0
lime>=0.2.0.1,<0.3.0
matplotlib>=3.8.0,<4.0.0
seaborn>=0.13.0,<0.14.0
lxml>=5.1.0,<6.0.0
```
*Note on NumPy constraint*: `numpy>=1.26.0,<2.3.0` was specified to prevent Numba/SHAP C-extension incompatibilities under NumPy 2.x while remaining fully compatible with scikit-learn 1.4+.

### Frontend Dependencies (`frontend/package.json`)
- Verified consistency between `package.json` and `package-lock.json`.
- Installed cleanly (290 packages audited).
- No new or unrelated dependencies were introduced.

---

## 4. Port Configuration Changes (Decision 1)

All inconsistent port references were unified across the codebase:

| Component | Prior Port Reference | Standardized Configuration |
| :--- | :---: | :--- |
| **FastAPI Server** (`src/api_fastapi.py`) | Unspecified in file | Port **8000** (overridable via `PORT` environment variable) |
| **Backend Startup Script** (`start_api.sh`) | `8001` | Port **8000** (overridable via `${PORT:-8000}`) |
| **Frontend API Client** (`frontend/src/utils/api.js`) | `5000` | `http://localhost:8000` (overridable via `VITE_API_URL`) |
| **Extension Service Worker** (`extension/background.js`) | `5000` | `http://localhost:8000` |
| **Extension Popup Client** (`extension/popup.js`) | `5000` | `http://localhost:8000` |
| **Extension Permissions** (`extension/manifest.json`) | `8000` only | `http://localhost:8000/*` and `http://127.0.0.1:8000/*` |
| **Cloud Deployment** (`render.yaml`) | `10000` | Port **8000** (mapped to `$PORT` at runtime) |

---

## 5. Environment Configuration & Secret Remediation

1. **Credential Sanitization**:
   - In `src/api_fastapi.py` (Line 43), a commented-out production MongoDB Atlas connection string (`mongodb+srv://punamproject:punamproject%40123@...`) was **permanently removed**.
   - No `.env` files or private keys are staged in version control.
2. **Environment Template (`.env.example`)**:
   - Updated with standardized development defaults:
     ```ini
     # MongoDB Connection String
     MONGO_URI=mongodb://localhost:27017/

     # Features
     ENABLE_EMAIL_ANALYSIS=true
     VITE_ENABLE_EMAIL_ANALYSIS=true

     # API Server Configuration
     PORT=8000
     HOST=0.0.0.0
     VITE_API_URL=http://localhost:8000
     ```
3. **Ignore Hardening**:
   - `.gitignore` was configured to ignore all `.env*` files while explicitly retaining `!.env.example` and `!requirements.txt`.

---

## 6. Repository Size Measurement

| Metric | Before Phase 1 | After Phase 1 | Challenge Constraint |
| :--- | :---: | :---: | :---: |
| **Tracked Git Files** | 84 files | 86 files | Exactly 1 branch (`main`) |
| **Tracked Working Tree Size** | 5.30 MB | **5.31 MB** | **< 10.0 MB** |
| **Git Object Packfile Size** | 3.55 MiB | **3.55 MiB** | **< 10.0 MB** |
| **Status** | **PASS** | **PASS** | **COMPLIANT (53% of budget)** |

---

## 7. Validation & Test Results

### 1. Python Syntax & Import Check
- **Command**: `py -3.12 -m py_compile src/*.py train_model.py verify_ml.py`
- **Result**: **PASSED** (Exit code: 0 across all files).

### 2. Backend Startup Smoke Test (FastAPI TestClient)
- **Execution**: In-process HTTP simulation of FastAPI application:
  - `GET /` -> Status: **200 OK** (`{"status": "API is running", "model_loaded": True}`)
  - `POST /predict` (`https://google.com`) -> Status: **200 OK** (`{"prediction": "legitimate"}`)
  - `GET /api/check-blocked-url` (`https://google.com`) -> Status: **200 OK** (`{"blocked": False}`)
- **ML Model Initialization**:
  - `model/rf_model.pkl` loaded successfully.
  - `model/phishing_detector.pkl` loaded successfully.
- **MongoDB Connection**: Verified ping on configured URI.
- **Result**: **PASSED**.

### 3. Frontend Production Build (Vite 6 + React 19)
- **Command**: `npm run build` in `frontend/`
- **Output**:
  - `dist/index.html` (0.69 kB)
  - `dist/assets/index-ahKxkwy1.css` (48.71 kB)
  - `dist/assets/index-Ck2n058r.js` (854.70 kB)
  - Transformation: 2,801 modules compiled successfully in 11.40s.
- **Result**: **PASSED**.

---

## 8. Exact Commands to Start the Application

### Option A: Local Development
```bash
# 1. Start the FastAPI Backend (Port 8000)
# Linux/macOS:
./start_api.sh
# Windows PowerShell:
py -3.12 -m uvicorn src.api_fastapi:app --reload --host 0.0.0.0 --port 8000

# 2. Start the Frontend Dev Server (Port 5173)
cd frontend
npm run dev

# 3. Load Browser Extension
# Open chrome://extensions -> Enable Developer Mode -> "Load unpacked" -> Select the /extension directory
```

### Option B: Cloud Production Build
```bash
# Backend Build
./build.sh
# Backend Start
python -m uvicorn src.api_fastapi:app --host 0.0.0.0 --port $PORT
```

---

## 9. Remaining Issues for Phase 2 (Security Hardening)

With repository hygiene, ports, and dependencies normalized, the system is primed for **Phase 2: Backend Security Hardening**:
1. **SSRF Guard**: Add isolated URL resolver blocking loopback (127.0.0.1) and private RFC1918 subnets in `fetch_live_html`.
2. **Auto-Block Corroboration**: Replace naive password-input auto-blocking with multi-factor risk corroboration.
3. **Authentication Layer**: Replace client-side `localStorage` auth with Argon2id + short-lived JWTs backed by MongoDB `users` collection.
4. **CORS & Rate Limiting**: Restrict wildcard CORS and add rate limiting to intensive endpoints.

---

### Phase 1 Completion Confirmation
In strict adherence to instructions:
- No changes have been pushed to GitHub.
- Working features have been preserved.
- Code is clean, validated, and ready for your review.
