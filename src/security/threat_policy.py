"""
Multi-Signal Threat Intelligence & Policy Engine for CyberScout.
Implements Decision 3:
- Multi-signal corroboration (ML + URL Heuristics + HTML Forensics + Threat Intelligence)
- Explicit Risk Levels: Low, Medium, High, Confirmed Malicious
- Separation of Warning vs. Blocking actions
- Trusted Domain Allowlisting
- Audit-trailed threat justification
"""

from urllib.parse import urlparse
from typing import Dict, List, Any, Tuple
import tldextract

# High-reputation verified domains that should never be auto-blocked by automated scanners
TRUSTED_DOMAINS = {
    "google.com", "accounts.google.com", "mail.google.com", "drive.google.com",
    "github.com", "gist.github.com",
    "microsoft.com", "login.microsoftonline.com", "live.com", "office.com",
    "apple.com", "icloud.com",
    "amazon.com", "aws.amazon.com",
    "linkedin.com",
    "youtube.com",
    "wikipedia.org",
    "cloudflare.com",
    "paypal.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com",
    "twitter.com", "x.com",
    "meta.com", "facebook.com", "instagram.com",
    "gov.in", "nic.in", "usa.gov", "gov.uk"
}

class RiskLevel:
    LOW = "LOW"                     # 0 - 39: Normal/Legitimate
    MEDIUM = "MEDIUM"               # 40 - 69: Suspicious (Warning)
    HIGH = "HIGH"                   # 70 - 89: High Risk (Advisory Warning, manual review)
    CONFIRMED_MALICIOUS = "CONFIRMED_MALICIOUS" # 90 - 100: Confirmed Threat (Block candidate)

class PolicyAction:
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"

def get_registered_domain(url: str) -> str:
    """Extract registered domain (e.g., 'login.google.com' -> 'google.com')."""
    try:
        ext = tldextract.extract(url)
        if ext.registered_domain:
            return ext.registered_domain.lower()
        parsed = urlparse(url)
        return (parsed.hostname or "").lower()
    except Exception:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower()

def is_domain_trusted(url: str) -> bool:
    """Check if the URL belongs to a verified trusted domain."""
    reg_domain = get_registered_domain(url)
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    
    return reg_domain in TRUSTED_DOMAINS or hostname in TRUSTED_DOMAINS

def evaluate_threat_policy(
    url: str,
    url_heuristic_score: int,
    html_score: int,
    html_reasons: List[str],
    ml_prediction: str,
    ml_confidence: float,
    has_password_field: bool = False,
    is_external_form_action: bool = False,
    manual_blocklist_match: bool = False
) -> Dict[str, Any]:
    """
    Evaluates multi-signal telemetry to produce a balanced, fair, and accurate
    threat assessment without single-signal false-positive blocking.
    """
    audit_reasons: List[str] = []
    corroborating_signals: List[str] = []
    
    trusted = is_domain_trusted(url)
    
    # 1. Evaluate Trusted Domain status
    if trusted:
        audit_reasons.append("Domain is in the Verified Trusted Allowlist (high reputation).")
        # On trusted domains, a password field is normal authentication
        if has_password_field:
            audit_reasons.append("Legitimate authentication element detected on verified domain.")
            
    # 2. Corroborate Signal A: Machine Learning Classifier
    ml_flagged = False
    if ml_prediction.lower() == "phishing" and ml_confidence >= 0.70:
        ml_flagged = True
        corroborating_signals.append(f"ML Model: Phishing pattern identified (Confidence: {ml_confidence:.2f})")
        audit_reasons.append(f"AI/ML URL Classifier classified pattern as phishing ({ml_confidence*100:.1f}% confidence).")
    elif ml_prediction.lower() == "legitimate":
        audit_reasons.append(f"AI/ML Classifier supports legitimate classification ({ml_confidence*100:.1f}% confidence).")

    # 3. Corroborate Signal B: Heuristic URL Signals
    heuristic_flagged = False
    if url_heuristic_score >= 35:
        heuristic_flagged = True
        corroborating_signals.append(f"URL Forensics: Suspicious lexical structure (Score: {url_heuristic_score})")
        audit_reasons.append("Suspicious URL structure detected (e.g. IP host, excessive masking, or deceptive subdomains).")

    # 4. Corroborate Signal C: HTML Forensics
    html_flagged = False
    if is_external_form_action:
        html_flagged = True
        corroborating_signals.append("HTML Forensics: Credential harvesting form targets external/untrusted domain")
        audit_reasons.append("CRITICAL: Form target transmits submitted data to an external third-party domain.")
    elif html_score >= 50:
        html_flagged = True
        corroborating_signals.append(f"HTML Forensics: High suspicious structural indicators (Score: {html_score})")

    # 5. Handle Password Field Nuance (Decision 3 requirement)
    if has_password_field and not trusted:
        if is_external_form_action or heuristic_flagged:
            corroborating_signals.append("Credential Input: Password field present on suspicious or external-action target")
            audit_reasons.append("Password input detected on suspicious host without verified domain authenticity.")
        else:
            audit_reasons.append("Password input field detected; standard credential form noted.")

    # 6. Corroborate Signal D: Manual/Prior Blocklist Match
    if manual_blocklist_match:
        corroborating_signals.append("Threat Intelligence: URL matched prior malicious blocklist entry")
        audit_reasons.append("Active entry present in threat intelligence blocklist database.")

    # Calculate Balanced Unified Risk Score
    # Weights: Heuristic (30%) + HTML (35%) + ML (35%)
    w_heuristic = 0.30
    w_html = 0.35
    w_ml = 0.35
    
    ml_numeric = int(ml_confidence * 100) if ml_prediction.lower() == "phishing" else int((1.0 - ml_confidence) * 20)
    
    raw_score = (url_heuristic_score * w_heuristic) + (html_score * w_html) + (ml_numeric * w_ml)
    
    # Cap or mitigate if domain is trusted
    if trusted:
        # A trusted domain cannot exceed Medium risk even with dynamic script alerts
        final_score = min(int(raw_score * 0.3), 35)
    else:
        final_score = min(int(raw_score), 100)
        
    # Manual blocklist override
    if manual_blocklist_match and not trusted:
        final_score = max(final_score, 95)

    # 7. Map to Risk Levels
    if final_score < 40:
        risk_level = RiskLevel.LOW
        action = PolicyAction.ALLOW
        prediction = "legitimate"
    elif final_score < 70:
        risk_level = RiskLevel.MEDIUM
        action = PolicyAction.WARN
        prediction = "suspicious"
    elif final_score < 90:
        risk_level = RiskLevel.HIGH
        action = PolicyAction.WARN
        prediction = "phishing"
    else:
        risk_level = RiskLevel.CONFIRMED_MALICIOUS
        action = PolicyAction.BLOCK if not trusted else PolicyAction.WARN
        prediction = "phishing"

    # 8. Strict Auto-Blocking Enforcement Rules (Decision 3)
    # Requirements:
    # 1. Must NOT be a trusted domain
    # 2. Score must be >= 90 (CONFIRMED_MALICIOUS)
    # 3. Must have at least TWO distinct corroborating signals (or verified manual blocklist)
    should_auto_block = False
    if not trusted:
        if manual_blocklist_match:
            should_auto_block = True
        elif final_score >= 90 and len(corroborating_signals) >= 2:
            should_auto_block = True
            audit_reasons.append("Auto-block enacted: Confirmed Malicious threshold reached with multi-signal corroboration.")

    return {
        "prediction": prediction,
        "risk_score": final_score,
        "risk_level": risk_level,
        "action": action,
        "should_block": should_auto_block,
        "is_trusted_domain": trusted,
        "corroborating_signals": corroborating_signals,
        "audit_reasons": audit_reasons
    }
