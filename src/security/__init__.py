"""
CyberScout Security Subsystem.
Includes:
- SSRF Guard and Safe HTTP Fetching (DNS Rebinding Protected)
- Argon2id Password Hashing and RFC 7519 JWT Auth
- Secure HTTP-Only Cookies and CSRF Protection
- Sliding Window In-Memory Rate Limiting
- Multi-Signal Threat Policy & Auto-Block Enforcement
"""

from .ssrf import validate_safe_url, safe_fetch_html, is_ip_blocked
from .auth import (
    hash_password,
    verify_password,
    validate_password_policy,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_auth_dependency,
    validate_production_security_config,
    get_jwt_secret,
    create_csrf_token,
    verify_csrf_token,
    get_cookie_configuration
)
from .rate_limiter import (
    SlidingWindowRateLimiter,
    auth_rate_limiter,
    scan_rate_limiter,
    general_rate_limiter
)
from .threat_policy import (
    RiskLevel,
    PolicyAction,
    is_domain_trusted,
    evaluate_threat_policy
)

__all__ = [
    "validate_safe_url",
    "safe_fetch_html",
    "is_ip_blocked",
    "hash_password",
    "verify_password",
    "validate_password_policy",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "get_auth_dependency",
    "validate_production_security_config",
    "get_jwt_secret",
    "create_csrf_token",
    "verify_csrf_token",
    "get_cookie_configuration",
    "SlidingWindowRateLimiter",
    "auth_rate_limiter",
    "scan_rate_limiter",
    "general_rate_limiter",
    "RiskLevel",
    "PolicyAction",
    "is_domain_trusted",
    "evaluate_threat_policy"
]
