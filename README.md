# 🛡️ CyberScout – Unified AI Cyber Defence System
*(Formerly PhishGuard Pro – Upgraded for PromptWars × Techverse Solutions Defence & Security Challenge)*

CyberScout is an integrated, production-oriented AI Cyber Defence Platform designed to protect individuals and organizations against phishing websites, email scams, malicious links, and compromised credentials.

Built on a hardened **FastAPI** backend, **React 19 + Vite** frontend, and **MongoDB** telemetry store, CyberScout unites pre-trained machine learning classifiers with explainable AI (XAI), SSRF-protected link inspection, Argon2id authentication, and real-time browser extension enforcement.

---

## 🏛️ System Architecture

```
                                 ┌────────────────────────────────────────────────────────┐
                                 │                   Client Layer                         │
                                 │  • React 19 + Vite Web Application                     │
                                 │  • Real-Time Chromium Browser Extension                │
                                 └───────────┬────────────────────────────────┬───────────┘
                                             │ HTTP/REST                      │ Chrome API
                                             ▼                                ▼
                                 ┌────────────────────────────────────────────────────────┐
                                 │              FastAPI Security Gateway                  │
                                 │  • Sliding-Window Rate Limiter (Brute-Force Defense)   │
                                 │  • RFC 9106 Argon2id Password Hasher                   │
                                 │  • RFC 7519 JWT Access & Refresh Token Rotation        │
                                 │  • Exact Origin CORS Enforcement                       │
                                 └───────────┬────────────────────────────────┬───────────┘
                                             │                                │
                     ┌───────────────────────┴──────────────┐                 │
                     ▼                                      ▼                 ▼
  ┌──────────────────────────────────────┐  ┌─────────────────────────┐  ┌──────────────┐
  │         Detection & ML Core          │  │  SSRF & Forensics Guard │  │  Data Store  │
  │ • URL Classifier (Random Forest)     │  │ • Pre-flight DNS Checks │  │ • MongoDB    │
  │ • Email NLP Model (Pre-trained)      │  │ • RFC 1918 Private IP   │  │   - Users    │
  │ • Explainable AI (SHAP / LIME)       │  │ • 5 MB Stream Boundary  │  │   - History  │
  │ • Multi-Signal Threat Policy         │  │ • Redirect Inspection   │  │   - Blocks   │
  │ • Trusted Domain Allowlist           │  │ • DOM Structural Tree   │  └──────────────┘
  └──────────────────────────────────────┘  └─────────────────────────┘
```

---

## 🌟 Key Defensive Modules

### 1. Website Intelligence & URL Forensics
- **Multi-Modal Detection**: Combines a trained Random Forest lexical classifier with heuristic inspection and DOM structure analysis.
- **Explainable AI (XAI)**: Generates human-understandable SHAP/LIME feature importance breakdowns explaining why a website is flagged.
- **Decision 3 Multi-Signal Policy**: Replaces crude single-signal password field blocking. Auto-blocking requires confirmed malicious scores ($\ge 90$) with multi-signal corroboration.
- **Trusted Domain Allowlist**: Verified legitimate authentication portals (Google, GitHub, Microsoft, Apple, Amazon, Banking) are protected from false-positive blocks.

### 2. Scam & Phishing Email Intelligence
- **Behavioral NLP ML Engine**: Analyzes incoming emails, SMS messages, and raw text for psychological urgency, brand impersonation, and fraudulent payment prompts.
- **Risk Tier Mapping**: Classifies threats into `LOW`, `MEDIUM`, `HIGH`, and `CONFIRMED_MALICIOUS`.
- **Signal Extraction**: Isolates extracted links, generic greetings, and sensitive data requests.

### 3. Link Safety & SSRF Neutralization
- **Strict Network Boundary**: Validates all outbound analysis requests against loopback (`127.0.0.1`), cloud metadata (`169.254.169.254`), private IP subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and non-HTTP protocols.
- **Redirect Validation**: Validates every redirect target (up to 5 hops) before following to prevent DNS rebinding.
- **Streaming Limit**: Limits downloads to 5 MB to prevent compression bomb denial-of-service.

### 4. Client-Side Password Security Intelligence
- **Zero-Knowledge Evaluation**: Password strength and mathematical Shannon entropy are computed 100% in the client browser. Plaintext credentials are **never** transmitted, hashed, or stored externally.
- **Pattern & Dictionary Auditing**: Detects sequences, repeated characters, and common passwords.
- **Offline GPU Crack Time Estimation**: Models brute-force resilience against 100-billion-guesses/sec clusters.
- **High-Entropy Passphrase Generator**: One-click generation of strong cryptographic multi-word passphrases.

### 5. Enterprise Authentication & Access Control
- **Argon2id Hashing**: Uses RFC 9106 recommended parameters (64 MiB memory, 3 iterations, 4 parallelism lanes).
- **Session Management**: 15-minute JWT access tokens paired with rotating 7-day cryptographic refresh tokens.
- **Role-Based Access Control (RBAC)**: Distinguishes `admin` and `analyst` clearance levels for registry management and override capabilities.

### 6. Real-Time Browser Extension
- **Pre-Navigation Interception**: Chrome extension monitors web navigation events via `webNavigation.onBeforeNavigate`.
- **Immediate Threat Quarantine**: Diverts navigation away from confirmed malicious domains to a secure warning blockpage.

---

## 🛠️ Technology Stack

| Component | Technology |
| :--- | :--- |
| **Frontend Framework** | React 19, Vite 6, Tailwind CSS |
| **Animation & Charts** | Framer Motion, Recharts, Lucide Icons |
| **Backend Framework** | Python 3.12, FastAPI, Uvicorn |
| **Authentication & Crypto** | Argon2id (`argon2-cffi`), PyJWT (`pyjwt`) |
| **Machine Learning** | Scikit-learn, Joblib, NumPy, Pandas, SHAP, LIME |
| **Forensics & Parsing** | BeautifulSoup4, TLDextract, Requests |
| **Database** | MongoDB (Pymongo) with in-memory resilient fallback |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm
- MongoDB service (optional; backend includes resilient simulated store if MongoDB is offline)

### 1. Repository Setup
```bash
git clone https://github.com/nikhil-0123/CyberScout-Unified-AI-Cyber-Defence-System.git
cd CyberScout-Unified-AI-Cyber-Defence-System
```

### 2. Backend Installation & Startup
```bash
# Install Python dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env

# Start FastAPI backend (Default Port: 8000)
uvicorn src.api_fastapi:app --host 0.0.0.0 --port 8000 --reload
```
The interactive API documentation is available at `http://localhost:8000/docs`.

### 3. Frontend Installation & Startup
```bash
cd frontend

# Install Node modules
npm install

# Start Vite development server (Default Port: 5173)
npm run dev
```
Open `http://localhost:5173` in your browser.

### 4. Browser Extension Setup
1. Open Google Chrome (or any Chromium browser) and navigate to `chrome://extensions`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the `extension/` directory.
4. The CyberScout extension icon will appear in your browser toolbar.

---

## 🔒 Security Policy & Limitations

- **False-Positive Philosophy**: CyberScout believes a password input form is standard for web applications and does not unilaterally indicate a malicious site. True blocking requires multi-signal corroboration.
- **No Absolute Guarantee**: While CyberScout provides advanced heuristic and AI classification, no scanner can guarantee 100% detection of zero-day vulnerabilities or advanced social engineering.
- **SSRF Boundary**: Internal network scanning and cloud instance metadata access are strictly blocked by design.

---

## 🧪 Demonstration Workflow

1. **Security Registration**: Navigate to `http://localhost:5173/register` and create an analyst profile using a strong password conforming to the security policy.
2. **Dashboard Overview**: Explore live telemetry counters, weekly detection distribution charts, and the live forensic log.
3. **URL Forensics**: Test a suspicious link in `URL Forensics`. Observe the SHAP lexical factor breakdown and DOM hierarchy mapping.
4. **Link Safety Inspector**: Test `https://accounts.google.com` to observe the Verified Allowlist badge and false-positive prevention in action.
5. **Email Intelligence**: Paste a deceptive email payload into `Email Analysis` to inspect behavioral urgency and sensitive data triggers.
6. **Password Intelligence**: Open `Password Security` to evaluate password entropy and generate a cryptographic multi-word passphrase.
7. **Threat Registry**: Review the active blocklist and exercise the administrator override mark-safe action.

---

## 📄 License & Attribution

Developed by **Nikhil Chaugule** for the **PromptWars × Techverse Solutions Defence and Security Challenge**.  
All code and trained models are provided for legitimate defense and educational cybersecurity research.
