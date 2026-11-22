from fastapi import FastAPI, HTTPException, Depends, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import pandas as pd
import pickle
import os
import uuid
import numpy as np
import joblib
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

# Feature Flags & Environment
ENABLE_EMAIL_ANALYSIS = os.getenv("ENABLE_EMAIL_ANALYSIS", "true").lower() == "true"
ENVIRONMENT = os.getenv("ENVIRONMENT", os.getenv("NODE_ENV", "development")).lower()
IS_PRODUCTION = ENVIRONMENT in ("production", "prod")

from .analysis_engine import (
    fetch_live_html, extract_suspicious_snippets, analyze_phishing,
    extract_email_signals, analyze_email_phishing, extract_dom_tree
)
from .feature_url import extract_url_features
from .security import (
    validate_safe_url, safe_fetch_html, is_ip_blocked,
    hash_password, verify_password, validate_password_policy,
    create_access_token, create_refresh_token, decode_token,
    get_auth_dependency, validate_production_security_config,
    create_csrf_token, verify_csrf_token, get_cookie_configuration,
    auth_rate_limiter, scan_rate_limiter, general_rate_limiter,
    RiskLevel, PolicyAction, is_domain_trusted, evaluate_threat_policy
)

try:
    import shap
except Exception as e:
    shap = None

try:
    import lime
    import lime.lime_tabular
except Exception as e:
    lime = None
import warnings
warnings.filterwarnings("ignore")

# 1. Enforce Production Security Invariants (JWT secret strength, CORS sanity)
validate_production_security_config()

app = FastAPI(
    title="CyberScout Unified AI Cyber Defence API",
    description="Production-grade AI threat detection, forensics, SSRF protection and security operations API",
    version="2.0.0"
)

# 2. CORS Configuration (Explicit origin allowlisting, no wildcard * with credentials)
cors_env = os.getenv("CORS_ORIGINS", "")
if cors_env:
    allowed_origins = [o.strip() for o in cors_env.split(",") if o.strip()]
else:
    allowed_origins = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
        "https://cyberscout-gilt.vercel.app",
        "https://cyberscout.pages.dev"
    ]

# Ensure active deployed frontend domains are explicitly allowlisted
for domain in ["https://cyberscout-gilt.vercel.app", "https://cyberscout.pages.dev"]:
    if domain not in allowed_origins:
        allowed_origins.append(domain)

# Fail startup if wildcard CORS is attempted with credentials
if "*" in allowed_origins:
    if IS_PRODUCTION:
        raise RuntimeError("CRITICAL SECURITY FATAL: Wildcard CORS origin '*' cannot be used with credentials in production.")
    allowed_origins = [o for o in allowed_origins if o != "*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"^(chrome-extension://[a-z]{32}|http://localhost:[0-9]+|http://127\.0\.0\.1:[0-9]+|https://[a-zA-Z0-9-]+\.pages\.dev|https://[a-zA-Z0-9-]+\.vercel\.app)$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# 3. MongoDB Configuration
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
client = None
_memory_users = {}

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    try:
        default_db = client.get_default_database()
        db = default_db if default_db.name not in ('test', 'admin') else client['phishing_detector']
    except Exception:
        db = client['phishing_detector']
    history_collection = db['scan_history']
    blocklist_collection = db['blocklist']
    users_collection = db['users']
    
    # Ensure database indexes
    try:
        users_collection.create_index("email", unique=True)
        users_collection.create_index("id", unique=True)
        blocklist_collection.create_index("url", unique=True)
        history_collection.create_index([("timestamp", -1)])
        history_collection.create_index("user_id")
    except Exception:
        pass

    print("Connected to MongoDB successfully with secure collections initialized!")
except Exception as e:
    if IS_PRODUCTION:
        raise RuntimeError(
            f"CRITICAL FATAL: MongoDB is unavailable at {MONGO_URI}. "
            f"Production requires a connected, authenticated database instance. Startup aborted. Error: {e}"
        )
    print(f"CRITICAL: MongoDB is NOT running at {MONGO_URI}. Fallback in-memory development mode active.")
    client = None
    history_collection = None
    blocklist_collection = None
    users_collection = None

# Initialize RBAC dependencies bound to MongoDB users collection or development memory
get_current_user_optional, require_current_user, require_admin = get_auth_dependency(users_collection, _memory_users)

def is_database_healthy() -> bool:
    """Checks live database connectivity."""
    if client is None:
        return False
    try:
        client.admin.command('ping')
        return True
    except Exception:
        return False

# DATA FLOW: URL → HTML Fetch → Analysis → Unified Risk Score → Auto Blocklist → Extension Enforcement

def log_to_db(type, input, prediction, score, reasons, user_id=None):
    if history_collection is not None:
        try:
            doc = {
                "type": type,
                "input": input,
                "prediction": prediction,
                "risk_score": score,
                "reasons": reasons,
                "timestamp": datetime.now(timezone.utc)
            }
            if user_id:
                doc["user_id"] = str(user_id)
                
            history_collection.insert_one(doc)
        except Exception as e:
            print(f"Failed to log to MongoDB: {e}")

class PredictionRequest(BaseModel):
    url: str
    email_text: str = ""
    html: str = ""
    user_id: Optional[str] = None

class URLRequest(BaseModel):
    url: str

class EmailRequest(BaseModel):
    email_text: str
    user_id: Optional[str] = None

class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)

class LoginRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=1, max_length=128)

class RefreshRequest(BaseModel):
    refresh_token: Optional[str] = None

# Load URL Random Forest model (Rule-based features)
model_path = "model/rf_model.pkl"
background_path = "model/background_data.pkl"
model = None
explainer_shap = None
explainer_lime = None
background_data = None

if os.path.exists(model_path):
    try:
        with open(model_path, "rb") as f:
            model = pickle.load(f)
        print(f"ML Model loaded from {model_path}")
        
        # Load background data for LIME/SHAP
        if os.path.exists(background_path):
            with open(background_path, "rb") as f:
                background_data = pickle.load(f)
            
            # Initialize explainers
            # SHAP
            if shap is not None and hasattr(shap, "TreeExplainer"):
                explainer_shap = shap.TreeExplainer(model)
            
            # LIME
            feature_names = ["url_length", "domain_length", "dot_count", "digit_count", "has_ip", "is_https", "susp_keywords"]
            if lime is not None and hasattr(lime, "lime_tabular"):
                if hasattr(background_data, 'values'):
                    bg_values = background_data.values
                else:
                    bg_values = background_data
                explainer_lime = lime.lime_tabular.LimeTabularExplainer(
                    training_data=np.array(bg_values),
                    feature_names=feature_names,
                    class_names=["Legitimate", "Phishing"],
                    mode="classification"
                )
    except Exception as e:
        print(f"Error loading model or explainers: {e}")
        model = None
else:
    print(f"Model file not found at {model_path}. Using rule-based fallback.")

# Load Email Model if enabled
email_ml_model = None
if ENABLE_EMAIL_ANALYSIS:
    email_model_path = "model/phishing_detector.pkl"
    if os.path.exists(email_model_path):
        try:
            email_ml_model = joblib.load(email_model_path)
            print(f"Email ML Model loaded from {email_model_path}")
        except Exception as e:
            print(f"Error loading email ML model: {e}")
    else:
        print(f"Email model file not found at {email_model_path}")

def simple_url_features(url):
    """Fallback rule-based heuristic check for URLs."""
    risk_score = 0
    if not url:
        return risk_score
        
    url_lower = url.lower()
    
    # Check for IP address in URL
    import re
    if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url):
        risk_score += 2
        
    # Check length
    if len(url) > 75:
        risk_score += 1
        
    # Check suspicious keywords
    suspicious_words = ['secure', 'account', 'update', 'login', 'verify', 'banking', 'signin', 'support']
    for word in suspicious_words:
        if word in url_lower:
            risk_score += 1
            break
            
    # Check special characters
    if url.count('@') > 0 or url.count('-') > 3:
        risk_score += 1
        
    return 1 if risk_score >= 2 else 0

def analyze_text_content(text):
    """Analyzes text for typical spam/phishing keywords."""
    if not text:
        return 0
    text_lower = text.lower()
    suspicious_phrases = [
        'urgent', 'act immediately', 'account suspended', 'verify your identity',
        'click here', 'reset password', 'wire transfer', 'cryptocurrency', 'winner'
    ]
    matches = sum(1 for phrase in suspicious_phrases if phrase in text_lower)
    return matches

def analyze_html_content(html):
    """Parses HTML to find hidden forms, fake inputs, and suspicious scripts."""
    if not html:
        return 0, False
    html_lower = html.lower()
    risk_score = 0
    
    # Password field detection
    has_password_field = 'type="password"' in html_lower or "type='password'" in html_lower or "password" in html_lower
    if has_password_field:
        risk_score += 1
        
    # Form action to external/IP
    if '<form' in html_lower and 'action=' in html_lower:
        risk_score += 1
        
    # JavaScript suspicious patterns
    if '<script' in html_lower:
        if 'document.location' in html_lower or 'window.location' in html_lower:
            risk_score += 2
            
    return risk_score, has_password_field

# --- Health Check Endpoints ---

@app.get("/")
def root():
    db_healthy = is_database_healthy()
    if IS_PRODUCTION and not db_healthy:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "UNHEALTHY",
                "database": "DISCONNECTED",
                "error": "Required MongoDB service is unavailable in production."
            }
        )
    return {
        "status": "API is running",
        "environment": ENVIRONMENT,
        "database": "connected" if db_healthy else "in_memory_dev",
        "model_loaded": model is not None,
        "features": {
            "email_analysis": ENABLE_EMAIL_ANALYSIS
        }
    }

@app.get("/api/health")
def api_health():
    return root()

@app.post("/predict", dependencies=[Depends(scan_rate_limiter)])
def predict(
    data: PredictionRequest,
    current_user: Optional[dict] = Depends(get_current_user_optional)
):
    try:
        # SSRF Protection
        if data.url:
            is_safe, ssrf_reason, _ = validate_safe_url(data.url, skip_dns_check=True)
            if not is_safe:
                raise HTTPException(status_code=400, detail=f"SSRF Security Violation: {ssrf_reason}")

        # Check existing blocklist
        if blocklist_collection is not None and data.url:
            if blocklist_collection.find_one({"url": data.url}):
                return {
                    "prediction": "phishing",
                    "risk_level": RiskLevel.CONFIRMED_MALICIOUS,
                    "blocked": True,
                    "risk_score": 100,
                    "reasons": ["URL is present in active threat intelligence blocklist"]
                }

        # Analyze components
        url_risk = simple_url_features(data.url)
        text_risk = analyze_text_content(data.email_text)
        html_risk, has_password = analyze_html_content(data.html)

        ml_pred_str = "phishing" if url_risk == 1 else "legitimate"
        ml_conf = 0.85 if url_risk == 1 else 0.80

        policy = evaluate_threat_policy(
            url=data.url,
            url_heuristic_score=url_risk * 40,
            html_score=html_risk * 15,
            html_reasons=["HTML contains password input field"] if has_password else [],
            ml_prediction=ml_pred_str,
            ml_confidence=ml_conf,
            has_password_field=has_password
        )

        result = policy["prediction"]
        # Derive user_id from server-side authenticated token
        authenticated_user_id = current_user["id"] if current_user else None
        log_to_db("predict_v2", data.url, result, policy["risk_score"], policy["audit_reasons"], user_id=authenticated_user_id)

        return {
            "prediction": result,
            "risk_score": policy["risk_score"],
            "risk_level": policy["risk_level"],
            "action": policy["action"],
            "is_trusted": policy["is_trusted_domain"],
            "reasons": policy["audit_reasons"]
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in prediction: {e}")
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

# ============================================================================
# --- AUTHENTICATION & ACCESS CONTROL ENDPOINTS (Argon2id + HTTP-Only Cookie) ---
# ============================================================================

@app.post("/api/auth/register", dependencies=[Depends(auth_rate_limiter)])
def auth_register(data: RegisterRequest, request: Request, response: Response):
    """
    Registers a new security user with Argon2id password hashing,
    sets secure HTTP-only refresh cookie, and issues CSRF token.
    """
    is_valid, msg = validate_password_policy(data.password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=msg)

    email_clean = data.email.lower().strip()

    if users_collection is not None:
        if users_collection.find_one({"email": email_clean}):
            raise HTTPException(status_code=409, detail="Conflict Detected: User profile already exists.")
        user_count = users_collection.count_documents({})
    else:
        if email_clean in _memory_users:
            raise HTTPException(status_code=409, detail="Conflict Detected: User profile already exists.")
        user_count = len(_memory_users)

    role = "admin" if user_count == 0 else "analyst"
    user_id = str(uuid.uuid4())
    pw_hash = hash_password(data.password)
    now_iso = datetime.now(timezone.utc).isoformat()

    access_token = create_access_token(user_id=user_id, email=email_clean, role=role)
    refresh_token, jti, exp = create_refresh_token(user_id=user_id)

    user_doc = {
        "id": user_id,
        "name": data.name.strip(),
        "email": email_clean,
        "password_hash": pw_hash,
        "role": role,
        "is_active": True,
        "created_at": now_iso,
        "refresh_tokens": [jti]
    }

    if users_collection is not None:
        users_collection.insert_one(user_doc)
    else:
        _memory_users[email_clean] = user_doc

    # Set secure HTTP-only refresh cookie and CSRF cookie
    cookie_params = get_cookie_configuration(request)
    csrf_token = create_csrf_token()

    response.set_cookie(
        key="cyberscout_refresh_token",
        value=refresh_token,
        **cookie_params
    )
    response.set_cookie(
        key="cyberscout_csrf_token",
        value=csrf_token,
        path="/",
        secure=cookie_params["secure"],
        samesite=cookie_params["samesite"],
        max_age=cookie_params["max_age"],
        httponly=False
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token, # preserved for non-browser/CLI clients
        "token_type": "bearer",
        "csrf_token": csrf_token,
        "user": {
            "id": user_id,
            "name": data.name.strip(),
            "email": email_clean,
            "role": role
        }
    }

@app.post("/api/auth/login", dependencies=[Depends(auth_rate_limiter)])
def auth_login(data: LoginRequest, request: Request, response: Response):
    """
    Authenticates user against Argon2id hash, sets secure HTTP-only refresh cookie,
    and returns short-lived access token with CSRF token.
    """
    email_clean = data.email.lower().strip()

    if users_collection is not None:
        user = users_collection.find_one({"email": email_clean})
    else:
        user = _memory_users.get(email_clean)

    if not user or not verify_password(user.get("password_hash", ""), data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access Denied. Invalid security credentials."
        )

    if not user.get("is_active", True):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Security clearance revoked. Account inactive.")

    role = user.get("role", "analyst")
    access_token = create_access_token(user_id=user["id"], email=email_clean, role=role)
    refresh_token, jti, exp = create_refresh_token(user_id=user["id"])

    # Maintain max 5 active refresh tokens (token rotation / hygiene)
    active_tokens = user.get("refresh_tokens", [])
    active_tokens.append(jti)
    if len(active_tokens) > 5:
        active_tokens = active_tokens[-5:]

    if users_collection is not None:
        users_collection.update_one({"id": user["id"]}, {"$set": {"refresh_tokens": active_tokens}})
    else:
        user["refresh_tokens"] = active_tokens

    # Set secure HTTP-only refresh cookie and CSRF cookie
    cookie_params = get_cookie_configuration(request)
    csrf_token = create_csrf_token()

    response.set_cookie(
        key="cyberscout_refresh_token",
        value=refresh_token,
        **cookie_params
    )
    response.set_cookie(
        key="cyberscout_csrf_token",
        value=csrf_token,
        path="/",
        secure=cookie_params["secure"],
        samesite=cookie_params["samesite"],
        max_age=cookie_params["max_age"],
        httponly=False
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "csrf_token": csrf_token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": role
        }
    }

@app.post("/api/auth/refresh")
def auth_refresh(
    request: Request,
    response: Response,
    data: Optional[RefreshRequest] = None
):
    """
    Rotates access token using a valid, unrevoked refresh token.
    Supports secure HTTP-only cookies with CSRF defense, as well as body fallback.
    """
    token_str = None
    from_cookie = False

    # Check HTTP-only cookie first
    cookie_token = request.cookies.get("cyberscout_refresh_token")
    if cookie_token:
        token_str = cookie_token
        from_cookie = True
    elif data and data.refresh_token:
        token_str = data.refresh_token

    if not token_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing refresh token. Please authenticate."
        )

    # CSRF Verification if using cookie
    if from_cookie:
        client_csrf = request.headers.get("x-csrf-token")
        cookie_csrf = request.cookies.get("cyberscout_csrf_token")
        x_requested_with = request.headers.get("x-requested-with", "").lower()
        
        csrf_ok = verify_csrf_token(client_csrf, cookie_csrf) if (client_csrf and cookie_csrf) else False
        if not csrf_ok and x_requested_with != "xmlhttprequest":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF Protection: Missing or invalid CSRF verification token."
            )

    payload = decode_token(token_str, expected_type="refresh")
    user_id = payload.get("sub")
    jti = payload.get("jti")

    if users_collection is not None:
        user = users_collection.find_one({"id": user_id})
    else:
        user = next((u for u in _memory_users.values() if u["id"] == user_id), None)

    if not user or jti not in user.get("refresh_tokens", []):
        raise HTTPException(status_code=401, detail="Refresh token has been revoked or is invalid.")

    new_access_token = create_access_token(
        user_id=user["id"],
        email=user["email"],
        role=user.get("role", "analyst")
    )
    new_refresh_token, new_jti, exp = create_refresh_token(user_id=user["id"])

    # Rotate token in persistence
    active_tokens = [t for t in user.get("refresh_tokens", []) if t != jti]
    active_tokens.append(new_jti)
    if len(active_tokens) > 5:
        active_tokens = active_tokens[-5:]

    if users_collection is not None:
        users_collection.update_one({"id": user["id"]}, {"$set": {"refresh_tokens": active_tokens}})
    else:
        user["refresh_tokens"] = active_tokens

    # Set rotated refresh cookie
    cookie_params = get_cookie_configuration(request)
    response.set_cookie(
        key="cyberscout_refresh_token",
        value=new_refresh_token,
        **cookie_params
    )

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }

@app.get("/api/auth/me")
def auth_me(user: dict = Depends(require_current_user)):
    """
    Returns current authenticated security user profile.
    """
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user.get("role", "analyst")
    }

@app.post("/api/auth/logout")
def auth_logout(
    request: Request,
    response: Response,
    data: Optional[RefreshRequest] = None,
    user: Optional[dict] = Depends(get_current_user_optional)
):
    """
    Revokes refresh token and clears session cookies.
    """
    token_str = request.cookies.get("cyberscout_refresh_token") or (data.refresh_token if data else None)
    if token_str:
        try:
            payload = decode_token(token_str, expected_type="refresh")
            jti = payload.get("jti")
            uid = payload.get("sub")
            if users_collection is not None:
                users_collection.update_one({"id": uid}, {"$pull": {"refresh_tokens": jti}})
            elif user:
                user["refresh_tokens"] = [t for t in user.get("refresh_tokens", []) if t != jti]
        except Exception:
            pass

    cookie_params = get_cookie_configuration(request)
    response.delete_cookie(
        key="cyberscout_refresh_token",
        path="/api/auth",
        secure=cookie_params["secure"],
        samesite=cookie_params["samesite"]
    )
    response.delete_cookie(
        key="cyberscout_csrf_token",
        path="/",
        secure=cookie_params["secure"],
        samesite=cookie_params["samesite"]
    )
    return {"success": True, "message": "Clearance session terminated."}

# --- Enhanced Secure Endpoints for React Frontend ---

@app.post("/api/fetch-url", dependencies=[Depends(scan_rate_limiter)])
def api_fetch_url(data: URLRequest):
    is_safe, reason, _ = validate_safe_url(data.url)
    if not is_safe:
        raise HTTPException(status_code=400, detail=f"SSRF Security Violation: {reason}")
    html = fetch_live_html(data.url)
    if html.startswith("Error") or "Unable to fetch" in html:
        raise HTTPException(status_code=400, detail=html)
    return {"html": html}

@app.post("/api/extract-url-signals", dependencies=[Depends(scan_rate_limiter)])
def api_extract_url_signals(data: PredictionRequest):
    html = data.html
    if not html and data.url:
        is_safe, reason, _ = validate_safe_url(data.url)
        if not is_safe:
            raise HTTPException(status_code=400, detail=f"SSRF Security Violation: {reason}")
        html = fetch_live_html(data.url)
    
    snippets = extract_suspicious_snippets(html)
    return {"snippets": snippets}

@app.post("/api/fetch-dom-tree", dependencies=[Depends(scan_rate_limiter)])
def api_fetch_dom_tree(data: PredictionRequest):
    html = data.html
    if not html and data.url:
        is_safe, reason, _ = validate_safe_url(data.url)
        if not is_safe:
            raise HTTPException(status_code=400, detail=f"SSRF Security Violation: {reason}")
        html = fetch_live_html(data.url)
    
    tree = extract_dom_tree(html)
    return {"dom_tree": tree}

@app.post("/api/analyze-url", dependencies=[Depends(scan_rate_limiter)])
def api_analyze_url(
    data: PredictionRequest,
    current_user: Optional[dict] = Depends(get_current_user_optional)
):
    """
    Main Multi-Signal Analysis Flow:
    1. Anti-SSRF & DNS Rebinding validation & HTML Fetch
    2. ML Classification & Explainability (SHAP/LIME)
    3. Multi-Signal Threat Policy Evaluation (Decision 3)
    4. Auto-Blocklist only on Confirmed Malicious criteria
    5. Audit logging in scan history (derives user_id from verified server-side user)
    """
    # 1. SSRF Validation
    html = data.html
    if data.url:
        needs_fetch = not html
        is_safe, reason, _ = validate_safe_url(data.url, skip_dns_check=not needs_fetch)
        if not is_safe:
            raise HTTPException(status_code=400, detail=f"SSRF Security Violation: {reason}")

    # 2. Fetch HTML if not provided
    if not html and data.url:
        html = fetch_live_html(data.url)

    # 3. Check Manual Blocklist match
    manual_block = False
    if blocklist_collection is not None and data.url:
        if blocklist_collection.find_one({"url": data.url}):
            manual_block = True

    # 4. Check for external form target (classic credential harvesting pattern)
    is_external_form = False
    has_pwd = False
    if html and not html.startswith("Error"):
        html_low = html.lower()
        has_pwd = ('type="password"' in html_low or "type='password'" in html_low or "password" in html_low)
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")
            target_host = urlparse(data.url).netloc.lower()
            for form in soup.find_all("form"):
                act = (form.get("action") or "").strip()
                if act.startswith("http://") or act.startswith("https://"):
                    act_host = urlparse(act).netloc.lower()
                    if act_host and act_host != target_host:
                        is_external_form = True
                        break
        except Exception:
            pass

    # 5. Extract Feature Vector for URL ML model
    features = extract_url_features(data.url)
    features_df = pd.DataFrame([features]) if isinstance(features, dict) else features
    
    # 6. ML Inference & Explainability
    explanation = {"top_features": []}
    ml_confidence = 0.5
    ml_prediction = "Unknown"
    
    if model is not None and not features_df.empty:
        try:
            pred_idx = model.predict(features_df)[0]
            ml_prediction = "Phishing" if pred_idx == 1 else "Legitimate"
            probs = model.predict_proba(features_df)[0]
            ml_confidence = float(probs[pred_idx])

            # Generate SHAP explanation if available
            if explainer_shap is not None:
                shap_vals = explainer_shap.shap_values(features_df)
                if isinstance(shap_vals, list):
                    phish_shap = shap_vals[1][0] if len(shap_vals) > 1 else shap_vals[0][0]
                elif hasattr(shap_vals, 'ndim') and shap_vals.ndim == 3:
                    phish_shap = shap_vals[0, :, 1]
                else:
                    phish_shap = shap_vals[0]
                
                feat_importance = list(zip(features_df.columns, phish_shap))
                feat_importance.sort(key=lambda x: abs(x[1]), reverse=True)
                explanation["top_features"] = [
                    {"feature": f, "impact": float(v)} for f, v in feat_importance[:5]
                ]
        except Exception as e:
            print(f"Error during ML inference/SHAP: {e}")

    # 7. Evaluate Threat Policy (Decision 3: Multi-signal corroboration, never single-factor block)
    url_score = 0
    if ml_prediction == "Phishing":
        url_score = int(ml_confidence * 75)
    elif ml_prediction == "Legitimate":
        url_score = int((1.0 - ml_confidence) * 40)
    else:
        url_score = simple_url_features(data.url) * 40

    html_score = 0
    html_reasons = []
    if is_external_form:
        html_score += 45
        html_reasons.append("Form action submits to mismatched external domain (credential harvesting vector)")
    if has_pwd and is_external_form:
        html_score += 25
        html_reasons.append("Password input detected with third-party target form action")

    policy = evaluate_threat_policy(
        url=data.url,
        url_heuristic_score=url_score,
        html_score=html_score,
        html_reasons=html_reasons,
        ml_prediction=ml_prediction,
        ml_confidence=ml_confidence if ml_prediction != "Unknown" else 0.5,
        has_password_field=has_pwd
    )

    final_prediction = policy["prediction"]
    final_score = policy["risk_score"]
    should_block = manual_block or (policy["action"] == PolicyAction.BLOCK)

    # Auto-block ONLY when corroborated criteria for CONFIRMED_MALICIOUS are met
    if should_block and blocklist_collection is not None and data.url:
        try:
            blocklist_collection.update_one(
                {"url": data.url},
                {
                    "$set": {
                        "url": data.url,
                        "risk_score": final_score,
                        "risk_level": policy["risk_level"],
                        "reasons": policy["corroborating_signals"],
                        "timestamp": datetime.now(timezone.utc),
                        "auto_blocked": True
                    }
                },
                upsert=True
            )
        except Exception as e:
            print(f"Failed to update blocklist: {e}")

    combined_reasons = list(set(policy["audit_reasons"] + html_reasons))

    # Derive authenticated server-side user_id (never trust arbitrary client input)
    authenticated_user_id = current_user["id"] if current_user else None
    log_to_db("analyze_url", data.url, final_prediction, final_score, combined_reasons, user_id=authenticated_user_id)

    return {
        "url": data.url,
        "prediction": final_prediction.lower(),
        "confidence": ml_confidence if ml_prediction != "Unknown" else (final_score / 100.0),
        "block": should_block,
        "explanation": explanation,
        "risk_score": final_score,
        "risk_level": policy["risk_level"],
        "action": policy["action"],
        "is_trusted_domain": policy["is_trusted_domain"],
        "corroborating_signals": policy["corroborating_signals"],
        "reasons": combined_reasons,
        "auto_blocked": should_block
    }

# --- Real-Time Block Enforcement (Extension) ---
@app.get("/api/check-blocked-url", dependencies=[Depends(scan_rate_limiter)])
def check_blocked_url(url: str):
    """
    Check if a URL is in the blocklist.
    Used by the browser extension for real-time enforcement with rate limiting.
    """
    if blocklist_collection is not None:
        found = blocklist_collection.find_one({"url": url})
        if found:
            return {
                "blocked": True,
                "risk_score": found.get("risk_score", 100),
                "reasons": found.get("reasons", ["Previously flagged as phishing"])
            }
    return {"blocked": False}

# --- Blocklist Management (Authenticated Analysts & Admins) ---
@app.get("/api/blocklist")
def get_blocklist(current_user: dict = Depends(require_current_user)):
    """Returns the list of blocked threats. Requires authenticated user."""
    if blocklist_collection is None:
        return []
    try:
        blocks = list(blocklist_collection.find().sort("timestamp", -1))
        for b in blocks:
            b["_id"] = str(b["_id"])
            if "timestamp" in b:
                b["timestamp"] = b["timestamp"].isoformat()
        return blocks
    except Exception as e:
        return {"error": str(e)}

@app.delete("/api/blocklist")
def remove_from_blocklist(
    url: str,
    current_user: dict = Depends(require_admin)
):
    """Admin privilege required to remove a URL from the blocklist."""
    if blocklist_collection is not None:
        result = blocklist_collection.delete_one({"url": url})
        return {"success": result.deleted_count > 0}
    return {"error": "Database unavailable"}

@app.post("/api/mark-safe")
def mark_url_safe(
    url: str,
    current_user: dict = Depends(require_admin)
):
    """Admin override to mark a URL as safe by removing it from blocklist."""
    if blocklist_collection is not None:
        blocklist_collection.delete_one({"url": url})
        admin_info = current_user.get("email", "administrator")
        log_to_db("admin_override", url, "Legitimate", 0, [f"Marked safe by {admin_info} override"], user_id=current_user["id"])
        return {"success": True}
    return {"error": "Database unavailable"}

@app.post("/api/extract-email-signals")
def api_extract_email_signals(data: EmailRequest):
    if not ENABLE_EMAIL_ANALYSIS:
        raise HTTPException(status_code=403, detail="Email analysis feature is disabled")
    signals = extract_email_signals(data.email_text)
    return {"signals": signals}

@app.post("/api/analyze-email", dependencies=[Depends(scan_rate_limiter)])
def api_analyze_email(
    data: EmailRequest,
    current_user: Optional[dict] = Depends(get_current_user_optional)
):
    if not ENABLE_EMAIL_ANALYSIS:
        raise HTTPException(status_code=403, detail="Email analysis feature is disabled")
    prediction, score, reasons = analyze_email_phishing(data.email_text, ml_model=email_ml_model)
    
    risk_level = (
        RiskLevel.LOW if score < 40 else
        RiskLevel.MEDIUM if score < 70 else
        RiskLevel.HIGH if score < 90 else
        RiskLevel.CONFIRMED_MALICIOUS
    )
    
    authenticated_user_id = current_user["id"] if current_user else None
    log_to_db("email_analysis", data.email_text[:500], prediction, score, reasons, user_id=authenticated_user_id)
    return {
        "prediction": prediction,
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }

@app.get("/api/dashboard-stats")
def get_dashboard_stats(
    user_id: Optional[str] = None,
    current_user: dict = Depends(require_current_user)
):
    """
    Returns telemetry stats for the dashboard.
    Requires authentication.
    Analysts see their personal stats; Admins can view all or filter by user_id.
    """
    if history_collection is None:
        return {
            "total_scans": 0,
            "phishing_count": 0,
            "legitimate_count": 0,
            "url_scans": 0,
            "email_scans": 0,
            "recent_scans": [],
            "weekly_activity": []
        }
    
    try:
        from datetime import timedelta
        
        # Scans access control:
        # Non-admin analysts are restricted to their own telemetry
        if current_user.get("role") != "admin":
            target_user_id = current_user["id"]
        else:
            target_user_id = user_id

        query = {}
        if target_user_id:
            query["user_id"] = str(target_user_id)

        total_scans = history_collection.count_documents(query)
        
        phishing_query = query.copy()
        phishing_query["prediction"] = "Phishing"
        phishing_count = history_collection.count_documents(phishing_query)
        
        legit_query = query.copy()
        legit_query["prediction"] = "Legitimate"
        legitimate_count = history_collection.count_documents(legit_query)
        
        email_query = query.copy()
        email_query["type"] = "email_analysis"
        email_scans = history_collection.count_documents(email_query)
        
        url_query = query.copy()
        url_query["type"] = "url_analysis"
        url_scans = history_collection.count_documents(url_query)
        
        # 7-day activity aggregation
        seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
        match_stage = {"timestamp": {"$gte": seven_days_ago}}
        if target_user_id:
            match_stage["user_id"] = str(target_user_id)
            
        pipeline = [
            {"$match": match_stage},
            {"$group": {
                "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id": 1}}
        ]
        weekly_activity = list(history_collection.aggregate(pipeline))
        
        formatted_activity = []
        for i in range(7):
            date = (datetime.now(timezone.utc) - timedelta(days=6-i)).strftime("%Y-%m-%d")
            day_name = (datetime.now(timezone.utc) - timedelta(days=6-i)).strftime("%a")
            count = next((item['count'] for item in weekly_activity if item['_id'] == date), 0)
            formatted_activity.append({"day": day_name, "date": date, "count": count})

        # Get last 10 scans
        recent_scans_cursor = history_collection.find(query).sort("timestamp", -1).limit(10)
        recent_scans = []
        for scan in recent_scans_cursor:
            scan["_id"] = str(scan["_id"])
            if "timestamp" in scan:
                 scan["timestamp"] = scan["timestamp"].isoformat()
            recent_scans.append(scan)
            
        return {
            "total_scans": total_scans,
            "phishing_count": phishing_count,
            "legitimate_count": legitimate_count,
            "url_scans": url_scans,
            "email_scans": email_scans,
            "recent_scans": recent_scans,
            "weekly_activity": formatted_activity
        }
    except Exception as e:
        print(f"Error fetching stats: {e}")
        return {"error": str(e)}

if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("src.api_fastapi:app", host=host, port=port, reload=True)
