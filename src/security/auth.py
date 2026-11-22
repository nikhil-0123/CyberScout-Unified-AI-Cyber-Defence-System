"""
Authentication and Authorization Module for CyberScout.
Implements Argon2id password hashing, RFC 7519 compliant JWTs,
role-based access control (RBAC), secure HTTP-only cookies, and CSRF protection.
"""

import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
import jwt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Initialize Argon2id password hasher with secure parameters (RFC 9106 recommended)
# time_cost: 3 iterations, memory_cost: 64MB (65536 KiB), parallelism: 4 lanes
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)

# Known weak/placeholder secrets that must NEVER be used in production
INSECURE_SECRETS = {
    "cyberscout_production_super_secure_jwt_secret_key_minimum_32_bytes_2026",
    "replace_with_a_cryptographically_secure_random_32_plus_character_secret_e_g_openssl_rand_hex_32",
    "your_minimum_32_char_cryptographically_secure_random_key_here",
    "secret", "supersecret", "changeme", "12345678901234567890123456789012"
}

_DYNAMIC_DEV_SECRET: Optional[str] = None

def get_jwt_secret() -> str:
    """
    Retrieves and validates the JWT secret.
    In production: strictly enforces non-empty, strong (>=32 char), non-default key.
    In development: allows configured key or securely generates an in-memory session key.
    """
    global _DYNAMIC_DEV_SECRET
    env = os.getenv("ENVIRONMENT", os.getenv("NODE_ENV", "development")).lower()
    is_prod = env in ("production", "prod")
    secret = os.getenv("JWT_SECRET", "").strip()

    if is_prod:
        if not secret:
            raise RuntimeError(
                "CRITICAL SECURITY FATAL: JWT_SECRET environment variable is not configured. "
                "Production startup aborted. Set a cryptographically secure 32+ character JWT_SECRET."
            )
        if len(secret) < 32:
            raise RuntimeError(
                f"CRITICAL SECURITY FATAL: Configured JWT_SECRET is too short ({len(secret)} chars). "
                "Production requires at least 32 characters."
            )
        if secret in INSECURE_SECRETS:
            raise RuntimeError(
                "CRITICAL SECURITY FATAL: JWT_SECRET matches a known public placeholder or default value. "
                "Production requires a unique randomly generated key (e.g., via 'openssl rand -hex 32')."
            )
        return secret

    # Development mode handling
    if secret and len(secret) >= 32 and secret not in INSECURE_SECRETS:
        return secret

    if _DYNAMIC_DEV_SECRET is None:
        _DYNAMIC_DEV_SECRET = secrets.token_urlsafe(32)
        print("SECURITY NOTICE: Development environment active without explicit JWT_SECRET. Generated dynamic session key.")
    return _DYNAMIC_DEV_SECRET

def validate_production_security_config() -> None:
    """
    Validates security constraints at application startup.
    Fails startup with RuntimeError if any production security invariant is violated.
    """
    env = os.getenv("ENVIRONMENT", os.getenv("NODE_ENV", "development")).lower()
    if env in ("production", "prod"):
        # Enforce JWT_SECRET strength
        get_jwt_secret()

        # Enforce CORS configuration sanity
        cors_env = os.getenv("CORS_ORIGINS", "")
        if "*" in [o.strip() for o in cors_env.split(",")]:
            raise RuntimeError(
                "CRITICAL SECURITY FATAL: Wildcard CORS origin '*' is not allowed when credentials are enabled in production."
            )

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

security_bearer = HTTPBearer(auto_error=False)

# Common insecure passwords blacklist
DISALLOWED_PASSWORDS = {
    "password", "password123", "12345678", "123456789", "qwerty123",
    "admin123", "cyberscout", "phishguard", "welcome1", "letmein123"
}

def validate_password_policy(password: str) -> tuple[bool, str]:
    """
    Enforces strong password policy:
    - Minimum 8 characters
    - At least 1 lowercase letter
    - At least 1 uppercase letter
    - At least 1 digit
    - At least 1 special character
    - Not in known weak password blacklist
    """
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters in length."
    if len(password) > 128:
        return False, "Password exceeds maximum allowable length of 128 characters."
    if password.lower() in DISALLOWED_PASSWORDS:
        return False, "Password is too common and easily guessed. Please select a stronger password."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter (a-z)."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter (A-Z)."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one numeric digit (0-9)."
    if not re.search(r"[@$!%*?&_\-#\^~`(){}\[\]|:;,<.>/+=]", password):
        return False, "Password must contain at least one special character (e.g. !@#$%^&*)."
    return True, ""

def hash_password(plain_password: str) -> str:
    """Hash plaintext password using Argon2id."""
    return ph.hash(plain_password)

def verify_password(hashed_password: str, plain_password: str) -> bool:
    """Verify plaintext password against an Argon2id hash."""
    try:
        return ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, InvalidHashError):
        return False
    except Exception:
        return False

def create_access_token(user_id: str, email: str, role: str = "analyst") -> str:
    """Generate a short-lived JWT access token."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp())
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)

def create_refresh_token(user_id: str) -> tuple[str, str, datetime]:
    """
    Generate a cryptographic refresh token and its JWT wrapper.
    Returns: (token_str, jti, expiry_datetime)
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    jti = secrets.token_hex(16)
    payload = {
        "sub": str(user_id),
        "jti": jti,
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp())
    }
    token_str = jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)
    return token_str, jti, expire

def decode_token(token: str, expected_type: str = "access") -> Dict[str, Any]:
    """
    Decodes and validates a JWT token.
    Raises HTTPException(401) on failure.
    """
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != expected_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token type. Expected '{expected_type}' token."
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please log in again."
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication token: {str(e)}"
        )

# --- Cross-Domain Cookie & CSRF Utilities (Cloudflare Pages <-> Render API) ---

def create_csrf_token() -> str:
    """Generates a high-entropy CSRF protection token."""
    return secrets.token_urlsafe(32)

def verify_csrf_token(client_token: Optional[str], expected_token: Optional[str]) -> bool:
    """Verifies CSRF token matching using constant-time comparison."""
    if not client_token or not expected_token:
        return False
    return secrets.compare_digest(client_token, expected_token)

def get_cookie_configuration(request: Optional[Request] = None) -> Dict[str, Any]:
    """
    Calculates secure cookie parameters.
    Supports cross-domain Cloudflare Pages -> Render API via SameSite=None and Secure=True.
    Falls back to Lax / non-secure for local HTTP testing if not over HTTPS.
    """
    env = os.getenv("ENVIRONMENT", os.getenv("NODE_ENV", "development")).lower()
    is_prod = env in ("production", "prod")

    # Determine if current request or environment uses TLS/HTTPS
    is_https = is_prod or os.getenv("SECURE_COOKIES", "false").lower() == "true"
    if request:
        proto = request.headers.get("x-forwarded-proto", request.url.scheme).lower()
        if proto == "https":
            is_https = True

    if is_https:
        # Cross-site Cloudflare Pages <-> Render API requires SameSite=None + Secure=True
        return {
            "secure": True,
            "samesite": "none",
            "httponly": True,
            "path": "/api/auth",
            "max_age": REFRESH_TOKEN_EXPIRE_DAYS * 86400
        }
    else:
        # Local development on HTTP
        return {
            "secure": False,
            "samesite": "lax",
            "httponly": True,
            "path": "/api/auth",
            "max_age": REFRESH_TOKEN_EXPIRE_DAYS * 86400
        }

# Dependency Factory to resolve user from MongoDB or memory
def get_auth_dependency(users_collection, memory_users: Optional[Dict[str, Any]] = None):
    """Factory creating FastAPI dependencies bound to the active MongoDB users collection."""

    def get_current_user_optional(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)
    ) -> Optional[Dict[str, Any]]:
        if not credentials or not credentials.credentials:
            return None
        token = credentials.credentials
        try:
            payload = decode_token(token, expected_type="access")
            user_id = payload.get("sub")
            if not user_id:
                return None
            if users_collection is not None:
                user = users_collection.find_one({"id": user_id})
                return user
            if memory_users is not None:
                return next((u for u in memory_users.values() if u.get("id") == user_id), None)
            return {"id": user_id, "email": payload.get("email"), "role": payload.get("role", "analyst")}
        except Exception:
            return None

    def require_current_user(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)
    ) -> Dict[str, Any]:
        if not credentials or not credentials.credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required. Please provide a valid Bearer token.",
                headers={"WWW-Authenticate": "Bearer"}
            )
        payload = decode_token(credentials.credentials, expected_type="access")
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Malformed token: missing subject identity."
            )
        if users_collection is not None:
            user = users_collection.find_one({"id": user_id})
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User account associated with this token no longer exists."
                )
            if not user.get("is_active", True):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User account has been disabled."
                )
            return user
        if memory_users is not None:
            user = next((u for u in memory_users.values() if u.get("id") == user_id), None)
            if user:
                return user
        return {"id": user_id, "email": payload.get("email"), "role": payload.get("role", "analyst"), "is_active": True}

    def require_admin(
        user: Dict[str, Any] = Depends(require_current_user)
    ) -> Dict[str, Any]:
        if user.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Administrative privilege required for this operation."
            )
        return user

    return get_current_user_optional, require_current_user, require_admin
