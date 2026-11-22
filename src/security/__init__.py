"""
CyberScout Security Subsystem.
Includes:
- SSRF Guard and Safe HTTP Fetching
- Argon2id Password Hashing and RFC 7519 JWT Auth
- Sliding Window In-Memory Rate Limiting
- Multi-Signal Threat Policy & Auto-Block Enforcement
"""

from .ssrf import validate_safe_url, safe_fetch_html
from .auth import (
    hash_password,
    verify_password,
    validate_password_policy,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_auth_dependency
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
    "hash_password",
    "verify_password",
    "validate_password_policy",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "get_auth_dependency",
    "SlidingWindowRateLimiter",
    "auth_rate_limiter",
    "scan_rate_limiter",
    "general_rate_limiter",
    "RiskLevel",
    "PolicyAction",
    "is_domain_trusted",
    "evaluate_threat_policy"
]
