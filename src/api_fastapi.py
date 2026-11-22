from fastapi import FastAPI, HTTPException, Depends, Request, status
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
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

# Feature Flags
ENABLE_EMAIL_ANALYSIS = os.getenv("ENABLE_EMAIL_ANALYSIS", "true").lower() == "true"
REQUIRE_AUTH = os.getenv("REQUIRE_AUTH", "false").lower() == "true"

from .analysis_engine import (
    fetch_live_html, extract_suspicious_snippets, analyze_phishing,
    extract_email_signals, analyze_email_phishing, extract_dom_tree
)
from .feature_url import extract_url_features
from .security import (
    validate_safe_url, safe_fetch_html,
    hash_password, verify_password, validate_password_policy,
    create_access_token, create_refresh_token, decode_token,
    get_auth_dependency,
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

app = FastAPI(
    title="CyberScout Unified AI Cyber Defence API",
    description="Production-grade AI threat detection, forensics, SSRF protection and security operations API",
    version="2.0.0"
)

# Secure CORS configuration (explicit origin allowlisting, no wildcard * with credentials)
cors_env = os.getenv("CORS_ORIGINS", "")
if cors_env:
    allowed_origins = [o.strip() for o in cors_env.split(",") if o.strip()]
else:
    allowed_origins = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000"
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"^(chrome-extension://[a-z]{32}|http://localhost:[0-9]+|http://127\.0\.0\.1:[0-9]+)$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# --- MongoDB Configuration ---
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
    client.admin.command('ping')
    db = client.get_database() if client.get_database().name != 'test' else client['phishing_detector']
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
    print(f"CRITICAL: MongoDB is NOT running at {MONGO_URI}. Fallback in-memory/simulated mode.")
    history_collection = None
    blocklist_collection = None
    users_collection = None

# Initialize RBAC dependencies bound to MongoDB users collection
get_current_user_optional, require_current_user, require_admin = get_auth_dependency(users_collection)

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
                "timestamp": datetime.utcnow()
            }
            if user_id:
                doc["user_id"] = user_id
                
            history_collection.insert_one(doc)
        except Exception as e:
            print(f"Failed to log to MongoDB: {e}")

class PredictionRequest(BaseModel):
    url: str
    email_text: str = ""
    html: str = ""
    user_id: str = None

class URLRequest(BaseModel):
    url: str

class EmailRequest(BaseModel):
    email_text: str
    user_id: str = None

class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)

class LoginRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=1, max_length=128)

class RefreshRequest(BaseModel):
    refresh_token: str

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
                    bg_values,
                    mode='classification',
                    feature_names=feature_names,
                    class_names=['Legitimate', 'Phishing'],
                    discretize_continuous=True
                )
            print("Explainable AI engines checked.")
    except Exception as e:
        print(f"Failed to load ML artifacts: {e}")
        model = None
else:
    print(f"Warning: URL model not found at {model_path}")
    model = None

# Load Pretrained Email ML Model
email_model_path = "model/phishing_detector.pkl"
try:
    if os.path.exists(email_model_path):
        with open(email_model_path, "rb") as f:
            email_ml_model = pickle.load(f)
        print(f"Pretrained Email ML Model loaded successfully from {email_model_path}!")
    else:
        print(f"Warning: Email ML model not found at {email_model_path}")
        email_ml_model = None
except Exception as e:
    print(f"Warning: Could not load pretrained email model from {email_model_path}: {e}")
    # Fallback to joblib if pickle fails (compatibility)
    try:
        email_ml_model = joblib.load(email_model_path)
        print("Loaded with joblib fallback.")
    except:
        email_ml_model = None

def simple_url_features(url):
    """Enhanced phishing detection using multiple heuristics"""
    try:
        url_lower = url.lower()
        parsed = urlparse(url_lower)
        domain = parsed.netloc
        path = parsed.path
        
        risk_score = 0
        
        # 1. Suspicious keywords (banking, payment, verification)
        suspicious_keywords = [
            'paypal', 'bank', 'signin', 'login', 'verify', 'account', 
            'secure', 'update', 'confirm', 'password', 'billing', 'ebay',
            'amazon', 'apple', 'microsoft', 'google', 'facebook', 'netflix',
            'suspended', 'locked', 'unusual', 'alert', 'support-help'
        ]
        keyword_matches = sum(1 for word in suspicious_keywords if word in url_lower)
        if keyword_matches >= 2:
            risk_score += 3
        elif keyword_matches == 1:
            risk_score += 1
            
        # 2. Multiple domains in path (e.g., example.com/realbank.com/)
        if '/' in path and any(tld in path for tld in ['.com', '.net', '.org', '.co.uk', '.co.nz']):
            risk_score += 3
            
        # 3. IP address in URL
        ip_pattern = domain.replace('.', '').replace(':', '')
        if ip_pattern.isdigit() or any(c.isdigit() for c in domain.split('.')[0] if len(domain.split('.')[0]) > 0):
            if sum(c.isdigit() for c in domain) > len(domain) * 0.3:
                risk_score += 2
                
        # 4. Excessive subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            risk_score += 2
        elif subdomain_count > 2:
            risk_score += 1
            
        # 5. Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.link']
        if any(url_lower.endswith(tld) for tld in suspicious_tlds):
            risk_score += 2
            
        # 6. Excessive hyphens
        if domain.count('-') >= 3:
            risk_score += 2
        elif domain.count('-') >= 2:
            risk_score += 1
            
        # 7. Long URL
        if len(url) > 100:
            risk_score += 2
        elif len(url) > 75:
            risk_score += 1
            
        # 8. @ symbol in URL (often used in phishing)
        if '@' in url:
            risk_score += 3
            
        # 9. HTTPS but suspicious domain
        if url_lower.startswith('http://') and any(word in url_lower for word in ['secure', 'banking', 'paypal']):
            risk_score += 2
            
        # 10. Unusual port numbers
        if ':' in domain and any(port in domain for port in [':8080', ':8000', ':3000', ':5000']):
            risk_score += 1
            
        # 11. Blogspot, free hosting in financial context
        free_hosts = ['blogspot', 'wordpress', 'wixsite', 'weebly', 'tripod']
        if any(host in domain for host in free_hosts):
            if any(word in url_lower for word in ['paypal', 'bank', 'secure', 'account']):
                risk_score += 3
                
        # 12. Suspicious patterns
        if 'limited' in domain and any(num.isdigit() for num in domain):
            risk_score += 2
            
        # Classification threshold
        return 1 if risk_score >= 3 else 0
    except Exception as e:
        print(f"Error in url analysis: {e}")
        return 0

def analyze_text_content(text):
    """Analyze email/text content for phishing indicators"""
    if not text or len(text) < 10:
        return 0
        
    text_lower = text.lower()
    risk_score = 0
    
    # Spam/phishing keywords
    spam_keywords = [
        'urgent', 'winner', 'congratulations', 'free money', 'lottery', 
        'viagra', 'cialis', 'weight loss', 'enlarge', 'click here',
        'act now', 'limited time', 'expire', 'suspended account',
        'verify your account', 'confirm your identity', 'unusual activity',
        'security alert', 'your account will be closed', 'reset password',
        'prize', 'million dollars', 'inheritance', 'beneficiary',
        'toll-free', 'call now', 'click below', 'update payment'
    ]
    
    keyword_count = sum(1 for word in spam_keywords if word in text_lower)
    if keyword_count >= 3:
        risk_score += 3
    elif keyword_count >= 2:
        risk_score += 2
    elif keyword_count == 1:
        risk_score += 1
        
    # Excessive exclamation marks
    if text.count('!') > 3:
        risk_score += 1
        
    # ALL CAPS text (common in spam)
    words = text.split()
    caps_words = sum(1 for w in words if len(w) > 3 and w.isupper())
    if caps_words > len(words) * 0.3:
        risk_score += 2
        
    return risk_score

def analyze_html_content(html):
    """Analyze HTML content for phishing indicators"""
    if not html or len(html) < 10:
        return 0, False
        
    html_lower = html.lower()
    risk_score = 0
    has_password_field = False
    
    # Check for password input fields (CRITICAL - immediate phishing indicator)
    if 'type=\'password\'' in html_lower or 'type="password"' in html_lower or 'password' in html_lower:
        risk_score += 10  # Very high score
        has_password_field = True
        
    # Check for forms
    if '<form' in html_lower:
        risk_score += 1
        
    # Check for iframes (can be used to hide content)
    if '<iframe' in html_lower:
        risk_score += 2
        
    # Suspicious form actions
    suspicious_actions = ['submit', 'login', 'signin', 'verify', 'update']
    if any(action in html_lower for action in suspicious_actions):
        risk_score += 1
        
    # Hidden inputs (can be malicious)
    if 'type="hidden"' in html_lower or "type='hidden'" in html_lower:
        risk_score += 1
        
    # JavaScript suspicious patterns
    if '<script' in html_lower:
        if 'document.location' in html_lower or 'window.location' in html_lower:
            risk_score += 2
            
    return risk_score, has_password_field

@app.get("/")
def root():
    return {
        "status": "API is running", 
        "model_loaded": model is not None,
        "features": {
            "email_analysis": ENABLE_EMAIL_ANALYSIS
        }
    }

@app.post("/predict", dependencies=[Depends(scan_rate_limiter)])
def predict(data: PredictionRequest):
    try:
        # SSRF Protection (inspect scheme and forbidden IP literals)
        if data.url:
            is_safe, ssrf_reason = validate_safe_url(data.url, skip_dns_check=True)
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

        # Multi-signal evaluation using Threat Policy (Decision 3)
        # Avoids single-signal false positive where a password input alone flags legitimate sites
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
        log_to_db("predict_v2", data.url, result, policy["risk_score"], policy["audit_reasons"], user_id=data.user_id)

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
# --- PHASE 2: AUTHENTICATION & ACCESS CONTROL ENDPOINTS (Argon2id + JWT) ---
# ============================================================================

# In-memory user fallback when MongoDB service is unreachable
_memory_users = {}

@app.post("/api/auth/register", dependencies=[Depends(auth_rate_limiter)])
def auth_register(data: RegisterRequest):
    """
    Registers a new security user with Argon2id password hashing and policy enforcement.
    """
    # 1. Validate password policy
    is_valid, msg = validate_password_policy(data.password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=msg)

    email_clean = data.email.lower().strip()

    # 2. Check if user already exists
    if users_collection is not None:
        if users_collection.find_one({"email": email_clean}):
            raise HTTPException(status_code=409, detail="Conflict Detected: User profile already exists.")
        user_count = users_collection.count_documents({})
    else:
        if email_clean in _memory_users:
            raise HTTPException(status_code=409, detail="Conflict Detected: User profile already exists.")
        user_count = len(_memory_users)

    # First registered user is automatically assigned Admin role; subsequent users are Analysts
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

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": {
            "id": user_id,
            "name": data.name.strip(),
            "email": email_clean,
            "role": role
        }
    }

@app.post("/api/auth/login", dependencies=[Depends(auth_rate_limiter)])
def auth_login(data: LoginRequest):
    """
    Authenticates a user against Argon2id hash and issues JWT access/refresh tokens.
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

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": role
        }
    }

@app.post("/api/auth/refresh")
def auth_refresh(data: RefreshRequest):
    """
    Rotates access token using a valid, unrevoked refresh token.
    """
    payload = decode_token(data.refresh_token, expected_type="refresh")
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

    return {
        "access_token": new_access_token,
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
    data: RefreshRequest = None,
    user: dict = Depends(get_current_user_optional)
):
    """
    Revokes the provided refresh token.
    """
    if user and data and data.refresh_token:
        try:
            payload = decode_token(data.refresh_token, expected_type="refresh")
            jti = payload.get("jti")
            if users_collection is not None:
                users_collection.update_one(
                    {"id": user["id"]},
                    {"$pull": {"refresh_tokens": jti}}
                )
            else:
                user["refresh_tokens"] = [t for t in user.get("refresh_tokens", []) if t != jti]
        except Exception:
            pass
    return {"success": True, "message": "Clearance session terminated."}

# --- Enhanced Secure Endpoints for React Frontend ---

@app.post("/api/fetch-url", dependencies=[Depends(scan_rate_limiter)])
def api_fetch_url(data: URLRequest):
    is_safe, reason = validate_safe_url(data.url)
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
        is_safe, reason = validate_safe_url(data.url)
        if not is_safe:
            raise HTTPException(status_code=400, detail=f"SSRF Security Violation: {reason}")
        html = fetch_live_html(data.url)
    
    snippets = extract_suspicious_snippets(html)
    return {"snippets": snippets}

@app.post("/api/fetch-dom-tree", dependencies=[Depends(scan_rate_limiter)])
def api_fetch_dom_tree(data: PredictionRequest):
    html = data.html
    if not html and data.url:
        is_safe, reason = validate_safe_url(data.url)
        if not is_safe:
            raise HTTPException(status_code=400, detail=f"SSRF Security Violation: {reason}")
        html = fetch_live_html(data.url)
    
    tree = extract_dom_tree(html)
    return {"dom_tree": tree}

@app.post("/api/analyze-url", dependencies=[Depends(scan_rate_limiter)])
def api_analyze_url(data: PredictionRequest):
    """
    Main Multi-Signal Analysis Flow:
    1. SSRF validation & HTML Fetch
    2. ML Classification & Explainability (SHAP/LIME)
    3. Multi-Signal Threat Policy Evaluation (Decision 3)
    4. Auto-Blocklist only on Confirmed Malicious criteria
    5. Audit logging in scan history
    """
    # 1. SSRF Validation
    html = data.html
    if data.url:
        needs_fetch = not html
        is_safe, reason = validate_safe_url(data.url, skip_dns_check=not needs_fetch)
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

    prediction, score, reasons = analyze_phishing(data.url, html)
    
    # --- ML Integration & Explainability ---
    ml_prediction = "Unknown"
    ml_confidence = 0.0
    explanation = {"top_features": []}
    
    if model:
        try:
            feats = extract_url_features(data.url)
            feature_order = ["url_length", "domain_length", "dot_count", "digit_count", "has_ip", "is_https", "susp_keywords"]
            input_vector = [feats[f] for f in feature_order]
            input_df = pd.DataFrame([input_vector], columns=feature_order)
            
            pred_class = model.predict(input_df)[0]
            ml_prediction = "phishing" if pred_class == 1 else "legitimate"
            probs = model.predict_proba(input_df)[0]
            ml_confidence = float(probs[1]) if pred_class == 1 else float(probs[0])
            
            if explainer_shap:
                shap_values = explainer_shap.shap_values(input_df)
                if isinstance(shap_values, list):
                    sv = shap_values[1][0]
                elif len(np.array(shap_values).shape) == 3:
                    sv = np.array(shap_values)[0, :, 1]
                else:
                    sv = np.array(shap_values)[0]

                feature_importance = zip(feature_order, sv)
                sorted_features = sorted(feature_importance, key=lambda x: abs(x[1]), reverse=True)
                explanation["top_features"] = [
                    f"{name}: {feats.get(name, 'N/A')} ({'Increases Risk' if val > 0 else 'Decreases Risk'})"
                    for name, val in sorted_features[:3]
                ]
        except Exception as e:
            print(f"ML/Explainability Error: {e}")

    # 5. Multi-Signal Threat Policy (Decision 3)
    policy = evaluate_threat_policy(
        url=data.url,
        url_heuristic_score=score,
        html_score=score,
        html_reasons=reasons,
        ml_prediction=ml_prediction,
        ml_confidence=ml_confidence,
        has_password_field=has_pwd,
        is_external_form_action=is_external_form,
        manual_blocklist_match=manual_block
    )

    final_prediction = policy["prediction"]
    final_score = policy["risk_score"]
    should_block = policy["should_block"]
    combined_reasons = list(dict.fromkeys(reasons + policy["audit_reasons"]))

    # 6. Multi-Signal Auto Blocklist System
    if should_block and blocklist_collection is not None:
        try:
            if not blocklist_collection.find_one({"url": data.url}):
                blocklist_collection.insert_one({
                    "url": data.url,
                    "risk_score": final_score,
                    "risk_level": policy["risk_level"],
                    "reasons": combined_reasons,
                    "corroborating_signals": policy["corroborating_signals"],
                    "blocked_by": "multi_signal_policy_v2",
                    "timestamp": datetime.now(timezone.utc)
                })
        except Exception as e:
            print(f"Failed to auto-block URL: {e}")

    log_to_db("url_analysis", data.url, final_prediction, final_score, combined_reasons, user_id=data.user_id)
    
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
@app.get("/api/check-blocked-url")
def check_blocked_url(url: str):
    """
    Check if a URL is in the blocklist.
    Used by the browser extension for real-time enforcement.
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

# --- Blocklist Management (Dashboard) ---
@app.get("/api/blocklist")
def get_blocklist():
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
    user: dict = Depends(require_admin if REQUIRE_AUTH else get_current_user_optional)
):
    if blocklist_collection is not None:
        result = blocklist_collection.delete_one({"url": url})
        return {"success": result.deleted_count > 0}
    return {"error": "Database unavailable"}

@app.post("/api/mark-safe")
def mark_url_safe(
    url: str,
    user: dict = Depends(require_admin if REQUIRE_AUTH else get_current_user_optional)
):
    """Admin override to mark a URL as safe by removing it from blocklist."""
    if blocklist_collection is not None:
        blocklist_collection.delete_one({"url": url})
        admin_info = user.get("email") if user else "administrator"
        log_to_db("admin_override", url, "Legitimate", 0, [f"Marked safe by {admin_info} override"])
        return {"success": True}
    return {"error": "Database unavailable"}

@app.post("/api/extract-email-signals")
def api_extract_email_signals(data: EmailRequest):
    if not ENABLE_EMAIL_ANALYSIS:
        raise HTTPException(status_code=403, detail="Email analysis feature is disabled")
    signals = extract_email_signals(data.email_text)
    return {"signals": signals}

@app.post("/api/analyze-email", dependencies=[Depends(scan_rate_limiter)])
def api_analyze_email(data: EmailRequest):
    if not ENABLE_EMAIL_ANALYSIS:
        raise HTTPException(status_code=403, detail="Email analysis feature is disabled")
    # Pass the loaded ML model for more accurate detection
    prediction, score, reasons = analyze_email_phishing(data.email_text, ml_model=email_ml_model)
    
    risk_level = (
        RiskLevel.LOW if score < 40 else
        RiskLevel.MEDIUM if score < 70 else
        RiskLevel.HIGH if score < 90 else
        RiskLevel.CONFIRMED_MALICIOUS
    )
    
    log_to_db("email_analysis", data.email_text[:500], prediction, score, reasons, user_id=data.user_id)
    return {
        "prediction": prediction,
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }

@app.get("/api/dashboard-stats")
def get_dashboard_stats(user_id: str = None):
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
        
        # Build filter query
        query = {}
        if user_id:
            query["user_id"] = user_id

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
        
        # Get 7-day activity aggregation
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        match_stage = {"timestamp": {"$gte": seven_days_ago}}
        if user_id:
            match_stage["user_id"] = user_id
            
        pipeline = [
            {"$match": match_stage},
            {"$group": {
                "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id": 1}}
        ]
        weekly_activity = list(history_collection.aggregate(pipeline))
        
        # Ensure we have data for all 7 days (even if 0)
        formatted_activity = []
        for i in range(7):
            date = (datetime.utcnow() - timedelta(days=6-i)).strftime("%Y-%m-%d")
            day_name = (datetime.utcnow() - timedelta(days=6-i)).strftime("%a")
            count = next((item['count'] for item in weekly_activity if item['_id'] == date), 0)
            formatted_activity.append({"day": day_name, "date": date, "count": count})

        # Get last 10 scans
        recent_scans_cursor = history_collection.find(query).sort("timestamp", -1).limit(10)
        recent_scans = []
        for scan in recent_scans_cursor:
            scan["_id"] = str(scan["_id"])  # Convert ObjectId to string
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

