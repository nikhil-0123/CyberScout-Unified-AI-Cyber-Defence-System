"""
Authentication and Authorization Module for CyberScout.
Implements Argon2id password hashing, RFC 7519 compliant JWTs,
role-based access control (RBAC), and token rotation.
"""

import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
import jwt
from fastapi import Depends, HTTPException, status
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

# JWT Configuration
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET or len(JWT_SECRET) < 32:
    # Ensure development has a persistent-per-process fallback if not set in .env
    # In production, this should always be explicitly set
    JWT_SECRET = os.getenv("JWT_SECRET", "cyberscout_production_super_secure_jwt_secret_key_minimum_32_bytes_2026")

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
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

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
    token_str = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token_str, jti, expire

def decode_token(token: str, expected_type: str = "access") -> Dict[str, Any]:
    """
    Decodes and validates a JWT token.
    Raises HTTPException(401) on failure.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
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

# Dependency Factory to resolve user from MongoDB
def get_auth_dependency(users_collection):
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
            if not user_id or users_collection is None:
                return None
            user = users_collection.find_one({"id": user_id})
            return user
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
        if not user_id or users_collection is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or database service unavailable."
            )
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
