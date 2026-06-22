"""
Nakul Authentication & Security
=================================

JWT token-based authentication, password hashing,
session management, CSRF protection, and rate limiting.
"""

import hashlib
import logging
import secrets
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple
from collections import defaultdict

from jose import JWTError, jwt
from passlib.context import CryptContext

logger = logging.getLogger("nakul.auth")

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthManager:
    """Manages authentication, tokens, and security."""

    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 60,
        rate_limit_attempts: int = 5,
        rate_limit_window_seconds: int = 300,
        ip_allowlist: list = None,
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.rate_limit_attempts = rate_limit_attempts
        self.rate_limit_window_seconds = rate_limit_window_seconds
        self.ip_allowlist = ip_allowlist or []

        # Rate limiting state: {ip: [(timestamp, success)]}
        self._login_attempts: Dict[str, list] = defaultdict(list)
        # CSRF tokens: {token: expiry_timestamp}
        self._csrf_tokens: Dict[str, float] = {}
        # Active sessions: {token_jti: expiry_timestamp}
        self._active_sessions: Dict[str, float] = {}

    # =========================================================================
    # Password Hashing
    # =========================================================================

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against a hash."""
        try:
            return pwd_context.verify(plain_password, hashed_password)
        except Exception:
            return False

    # =========================================================================
    # JWT Token Management
    # =========================================================================

    def create_access_token(
        self, username: str, expires_delta: Optional[timedelta] = None
    ) -> Tuple[str, str]:
        """
        Create a JWT access token.
        Returns (token, jti) where jti is the unique token ID.
        """
        jti = secrets.token_hex(16)
        
        now_ts = time.time()
        expire_minutes = expires_delta.total_seconds() / 60 if expires_delta else self.access_token_expire_minutes
        expire_ts = now_ts + (expire_minutes * 60)
        
        # We still need datetime for JWT standard payload
        expire_dt = datetime.utcfromtimestamp(expire_ts)

        payload = {
            "sub": username,
            "exp": expire_dt,
            "iat": datetime.utcfromtimestamp(now_ts),
            "jti": jti,
            "type": "access",
        }

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        # Track active session using raw timestamps
        self._active_sessions[jti] = expire_ts
        self._cleanup_sessions()

        logger.info(f"Access token created for user: {username}")
        return token, jti

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode a JWT token.
        Returns the payload dict or None if invalid.
        """
        try:
            payload = jwt.decode(
                token, self.secret_key, algorithms=[self.algorithm]
            )

            jti = payload.get("jti", "")
            if jti and jti not in self._active_sessions:
                logger.warning(f"Token with revoked/expired session: {jti[:8]}...")
                return None

            return payload

        except JWTError as e:
            logger.debug(f"Token verification failed: {e}")
            return None

    def revoke_token(self, jti: str) -> None:
        """Revoke a token by removing its session."""
        if jti in self._active_sessions:
            del self._active_sessions[jti]
            logger.info(f"Token revoked: {jti[:8]}...")

    def revoke_all_tokens(self) -> None:
        """Revoke all active sessions."""
        count = len(self._active_sessions)
        self._active_sessions.clear()
        logger.info(f"All {count} active sessions revoked")

    # =========================================================================
    # Rate Limiting
    # =========================================================================

    def check_rate_limit(self, ip_address: str) -> Tuple[bool, int]:
        """
        Check if an IP is rate-limited for login attempts.
        Returns (is_allowed, remaining_attempts).
        """
        now = time.time()
        window_start = now - self.rate_limit_window_seconds

        # Clean old attempts
        self._login_attempts[ip_address] = [
            (ts, success) for ts, success in self._login_attempts[ip_address]
            if ts > window_start
        ]

        # Count failed attempts in window
        failed = sum(
            1 for ts, success in self._login_attempts[ip_address]
            if not success
        )

        remaining = max(0, self.rate_limit_attempts - failed)
        return failed < self.rate_limit_attempts, remaining

    def record_login_attempt(self, ip_address: str, success: bool) -> None:
        """Record a login attempt for rate limiting."""
        self._login_attempts[ip_address].append((time.time(), success))

        if success:
            # Clear failed attempts on successful login
            self._login_attempts[ip_address] = [
                (ts, s) for ts, s in self._login_attempts[ip_address] if s
            ]

    # =========================================================================
    # CSRF Protection
    # =========================================================================

    def generate_csrf_token(self) -> str:
        """Generate a CSRF token valid for 1 hour."""
        token = secrets.token_hex(32)
        self._csrf_tokens[token] = time.time() + 3600  # 1 hour expiry
        self._cleanup_csrf()
        return token

    def validate_csrf_token(self, token: str) -> bool:
        """Validate a CSRF token."""
        if token in self._csrf_tokens:
            if self._csrf_tokens[token] > time.time():
                del self._csrf_tokens[token]  # One-time use
                return True
            else:
                del self._csrf_tokens[token]
        return False

    # =========================================================================
    # IP Allowlist
    # =========================================================================

    def check_ip_allowed(self, ip_address: str) -> bool:
        """Check if an IP is in the allowlist. Empty list = allow all."""
        if not self.ip_allowlist:
            return True
        return ip_address in self.ip_allowlist

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    def _cleanup_sessions(self) -> None:
        """Remove expired sessions."""
        now = time.time()
        expired = [
            jti for jti, exp in self._active_sessions.items() if exp < now
        ]
        for jti in expired:
            del self._active_sessions[jti]

    def _cleanup_csrf(self) -> None:
        """Remove expired CSRF tokens."""
        now = time.time()
        expired = [
            token for token, exp in self._csrf_tokens.items() if exp < now
        ]
        for token in expired:
            del self._csrf_tokens[token]


def generate_initial_password() -> Tuple[str, str]:
    """Generate a random initial admin password. Returns (plain, hash)."""
    password = secrets.token_urlsafe(16)
    password_hash = pwd_context.hash(password)
    return password, password_hash
