"""JWT token operations with enhanced security and key rotation"""

import hashlib
import secrets
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import jwt
from jwt.types import Options


class TokenBlacklist:
    """In-memory token blacklist with automatic cleanup"""

    __slots__ = ("_blacklist", "_max_size", "_cleanup_counter")

    def __init__(self, max_size: int = 10000) -> None:
        self._blacklist: dict[str, float] = {}
        self._max_size = max_size
        self._cleanup_counter = 0

    def add(self, token: str, expires_at: float) -> None:
        """Add token to blacklist"""
        self._blacklist[token] = expires_at
        self._cleanup_counter += 1

        if self._cleanup_counter >= 100:
            self._cleanup()
            self._cleanup_counter = 0

    def is_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted"""
        if token in self._blacklist:
            expires_at = self._blacklist[token]
            now = datetime.now(UTC).timestamp()

            if now < expires_at:
                return True
            else:
                del self._blacklist[token]

        return False

    def _cleanup(self) -> None:
        """Remove expired tokens"""
        now = datetime.now(UTC).timestamp()
        expired = [token for token, exp in self._blacklist.items() if exp <= now]

        for token in expired:
            del self._blacklist[token]

        if len(self._blacklist) > self._max_size:
            items = sorted(self._blacklist.items(), key=lambda x: x[1])
            to_remove = len(self._blacklist) - self._max_size
            for token, _ in items[:to_remove]:
                del self._blacklist[token]


class KeyRotation:
    """Key rotation manager for JWT signing"""

    __slots__ = ("_keys", "_current_index", "_max_keys")

    def __init__(self, initial_key: str, max_keys: int = 3) -> None:
        self._keys: deque[tuple[str, str]] = deque(maxlen=max_keys)
        self._max_keys = max_keys
        self._current_index = 0

        key_id = self._generate_key_id()
        self._keys.append((key_id, initial_key))

    def _generate_key_id(self) -> str:
        """Generate unique key ID"""
        return secrets.token_urlsafe(16)

    def get_current_key(self) -> tuple[str, str]:
        """Get current signing key and its ID"""
        return self._keys[-1]

    def get_key_by_id(self, key_id: str) -> str | None:
        """Get key by ID for verification"""
        for kid, key in self._keys:
            if kid == key_id:
                return key
        return None

    def rotate_key(self, new_key: str) -> str:
        """Rotate to new key, return new key ID"""
        key_id = self._generate_key_id()
        self._keys.append((key_id, new_key))
        return key_id

    def all_keys(self) -> list[tuple[str, str]]:
        """Get all keys for verification"""
        return list(self._keys)


class JWTManager:
    """Enhanced JWT manager with key rotation and blacklisting"""

    __slots__ = (
        "_secret_key",
        "_algorithm",
        "_public_key",
        "_access_token_expire",
        "_refresh_token_expire",
        "_key_rotation",
        "_blacklist",
        "_issuer",
        "_audience",
    )

    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        public_key: str | None = None,
        access_token_expire_minutes: int = 30,
        refresh_token_expire_days: int = 7,
        enable_key_rotation: bool = False,
        enable_blacklist: bool = True,
        issuer: str | None = None,
        audience: str | list[str] | None = None,
    ) -> None:
        if not secret_key:
            raise ValueError("Secret key is required")
        if access_token_expire_minutes <= 0:
            raise ValueError("Access token expiration must be positive")
        if refresh_token_expire_days <= 0:
            raise ValueError("Refresh token expiration must be positive")

        self._secret_key = secret_key
        self._algorithm = algorithm
        self._public_key = public_key
        self._access_token_expire = timedelta(minutes=access_token_expire_minutes)
        self._refresh_token_expire = timedelta(days=refresh_token_expire_days)
        self._issuer = issuer
        self._audience = audience

        self._key_rotation = KeyRotation(secret_key) if enable_key_rotation else None
        self._blacklist = TokenBlacklist() if enable_blacklist else None

    def encode(
        self,
        payload: dict[str, Any],
        expires_delta: timedelta | None = None,
        token_type: Literal["access", "refresh", "custom"] = "custom",
    ) -> str:
        """Encode JWT token with enhanced security"""
        if not payload:
            raise ValueError("Payload cannot be empty")

        if not self._secret_key:
            raise ValueError("Secret key is required for JWT encoding")

        try:
            to_encode = payload.copy()

            now = datetime.now(UTC)

            if expires_delta:
                if expires_delta.total_seconds() <= 0:
                    raise ValueError("Expiration delta must be positive")
                expire = now + expires_delta
            else:
                expire = now + timedelta(hours=24)

            to_encode["exp"] = int(expire.timestamp())
            to_encode["iat"] = int(now.timestamp())
            to_encode["jti"] = secrets.token_urlsafe(16)
            to_encode["type"] = token_type

            if self._issuer:
                to_encode["iss"] = self._issuer
            if self._audience:
                to_encode["aud"] = self._audience

            key_to_use = self._secret_key
            kid = None

            if self._key_rotation:
                kid, key_to_use = self._key_rotation.get_current_key()

            headers = {"kid": kid} if kid else None

            return jwt.encode(to_encode, key_to_use, algorithm=self._algorithm, headers=headers)
        except jwt.InvalidTokenError as e:
            raise ValueError(f"JWT encoding failed: {str(e)}") from e
        except Exception as e:
            raise ValueError(f"Unexpected error during JWT encoding: {str(e)}") from e

    def decode(self, token: str, verify: bool = True) -> dict[str, Any]:
        """Decode JWT token with blacklist check and key rotation support"""
        if not token:
            raise ValueError("Token cannot be empty")

        if not token.strip():
            raise ValueError("Token cannot be empty or whitespace")

        if self._blacklist and self._blacklist.is_blacklisted(token):
            raise ValueError("Token has been revoked")

        try:
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")

            key_to_use = self._public_key if self._public_key else self._secret_key

            if kid and self._key_rotation:
                rotation_key = self._key_rotation.get_key_by_id(kid)
                if rotation_key:
                    key_to_use = rotation_key

            if not key_to_use:
                raise ValueError("No key available for token verification")

            options: Options = {"verify_signature": verify}

            payload = jwt.decode(
                token,
                key_to_use,
                algorithms=[self._algorithm],
                options=options,
                issuer=self._issuer if verify else None,
                audience=self._audience if verify else None,
            )
            return dict(payload)
        except jwt.ExpiredSignatureError as exc:
            raise ValueError("Token has expired") from exc
        except jwt.InvalidIssuerError as exc:
            raise ValueError("Invalid token issuer") from exc
        except jwt.InvalidAudienceError as exc:
            raise ValueError("Invalid token audience") from exc
        except jwt.InvalidTokenError as exc:
            raise ValueError(f"Invalid token: {exc}") from exc
        except Exception as e:
            raise ValueError(f"Unexpected error during token decoding: {str(e)}") from e

    def create_access_token(self, data: dict[str, Any]) -> str:
        """Create access token"""
        return self.encode(data, self._access_token_expire, token_type="access")

    def create_refresh_token(self, data: dict[str, Any]) -> str:
        """Create refresh token"""
        return self.encode(data, self._refresh_token_expire, token_type="refresh")

    def decode_token(self, token: str, verify: bool = True) -> dict[str, Any]:
        """Decode and validate token"""
        return self.decode(token, verify=verify)

    def revoke_token(self, token: str) -> None:
        """Add token to blacklist"""
        if not self._blacklist:
            raise RuntimeError("Token blacklist is not enabled")

        try:
            payload = self.decode(token, verify=False)
            exp = payload.get("exp")

            if exp:
                self._blacklist.add(token, float(exp))
        except Exception:
            pass

    def rotate_key(self, new_key: str) -> str:
        """Rotate signing key, return new key ID"""
        if not self._key_rotation:
            raise RuntimeError("Key rotation is not enabled")

        return self._key_rotation.rotate_key(new_key)

    def get_token_fingerprint(self, token: str) -> str:
        """Generate fingerprint for token (for tracking)"""
        return hashlib.sha256(token.encode()).hexdigest()[:16]


class JWTHandler:
    """JWT encoding and decoding"""

    __slots__ = ("_secret_key", "_algorithm", "_public_key")

    def __init__(
        self, secret_key: str, algorithm: str = "HS256", public_key: str | None = None
    ) -> None:
        self._secret_key = secret_key
        self._algorithm = algorithm
        self._public_key = public_key

    def encode(self, payload: dict[str, Any], expires_delta: timedelta | None = None) -> str:
        """Encode JWT token"""
        to_encode = payload.copy()

        now = datetime.now(UTC)

        if expires_delta:
            expire = now + expires_delta
        else:
            expire = now + timedelta(hours=24)

        to_encode["exp"] = int(expire.timestamp())
        to_encode["iat"] = int(now.timestamp())
        to_encode["jti"] = secrets.token_urlsafe(16)

        return jwt.encode(to_encode, self._secret_key, algorithm=self._algorithm)

    def decode(self, token: str) -> dict[str, Any]:
        """Decode JWT token"""
        try:
            key = self._public_key if self._public_key else self._secret_key
            payload = jwt.decode(token, key, algorithms=[self._algorithm])
            return dict(payload)
        except jwt.InvalidTokenError as exc:
            raise ValueError(f"Invalid token: {exc}") from exc

    def create_access_token(
        self, subject: str, expires_delta: timedelta | None = None, **claims: Any
    ) -> str:
        """Create access token with subject"""
        payload = {"sub": subject, **claims}
        return self.encode(payload, expires_delta)

    def create_refresh_token(self, subject: str, expires_delta: timedelta | None = None) -> str:
        """Create refresh token"""
        if expires_delta is None:
            expires_delta = timedelta(days=7)

        return self.encode({"sub": subject, "type": "refresh"}, expires_delta)

    def verify_token(self, token: str) -> str | None:
        """Verify token and return subject"""
        try:
            payload = self.decode(token)
            sub = payload.get("sub")
            return str(sub) if sub is not None else None
        except ValueError:
            return None

    def verify_refresh_token(self, token: str) -> str | None:
        """Verify refresh token and return subject"""
        try:
            payload = self.decode(token)
            if payload.get("type") != "refresh":
                return None
            sub = payload.get("sub")
            return str(sub) if sub is not None else None
        except ValueError:
            return None
