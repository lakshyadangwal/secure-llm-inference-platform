"""
Commit 50: Request Signer (HMAC Verification Utility)
======================================================
HMAC-SHA256 request signing and verification utility.
Used for:
  - Verifying webhook payloads are from trusted senders
  - Signing internal service-to-service calls
  - Timestamped signatures to prevent replay attacks
  - API key hashing for secure comparison

Design:
  - No external dependencies (stdlib hmac + hashlib only)
  - Constant-time comparison to prevent timing attacks
  - Configurable replay window (default 5 minutes)
  - Nonce tracking to prevent exact replay within window
  - Multiple secret support (key rotation)
"""

import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
REPLAY_WINDOW_SECONDS = 300      # 5-minute replay protection window
MAX_NONCES            = 10000    # max tracked nonces (rolling)
SIGNATURE_HEADER      = "X-Neuro-Signature"
TIMESTAMP_HEADER      = "X-Neuro-Timestamp"
NONCE_HEADER          = "X-Neuro-Nonce"


# ── Verification result ────────────────────────────────────────────────────────

@dataclass
class VerifyResult:
    is_valid: bool
    reason: str
    age_seconds: Optional[float] = None

    @property
    def is_replay(self) -> bool:
        return "replay" in self.reason

    @property
    def is_expired(self) -> bool:
        return "expired" in self.reason


# ── Signer ─────────────────────────────────────────────────────────────────────

class RequestSigner:
    """
    HMAC-based request signing utility with replay protection.
    """

    def __init__(
        self,
        primary_secret: Optional[str] = None,
        replay_window: float = REPLAY_WINDOW_SECONDS,
    ):
        # Use a random secret if none provided (meaningful only for testing)
        self._secrets: list[bytes] = []
        self._nonces: set = set()
        self._nonce_ages: list[tuple[float, str]] = []  # (timestamp, nonce)
        self._lock = RLock()
        self._replay_window = replay_window
        self._total_signed = 0
        self._total_verified = 0
        self._total_rejected = 0

        if primary_secret:
            self.add_secret(primary_secret)
        else:
            self.add_secret(secrets.token_hex(32))

        logger.info(
            "🔐 RequestSigner initialised (window=%.0fs  secrets=%d)",
            replay_window, len(self._secrets)
        )

    def add_secret(self, secret: str) -> None:
        """Add a signing secret (supports key rotation — multiple secrets accepted)."""
        with self._lock:
            self._secrets.append(secret.encode())
        logger.info("🔐 Signing secret added (total=%d)", len(self._secrets))

    def remove_oldest_secret(self) -> bool:
        """Remove the oldest secret during key rotation."""
        with self._lock:
            if len(self._secrets) > 1:
                self._secrets.pop(0)
                return True
        return False

    # ── Signing ────────────────────────────────────────────────────────────────

    def sign(self, payload: str | bytes, timestamp: Optional[float] = None) -> dict[str, str]:
        """
        Sign a payload and return headers dict.

        Args:
            payload:   The request body or data to sign.
            timestamp: Unix timestamp (defaults to now).

        Returns:
            Dict with X-Neuro-Signature, X-Neuro-Timestamp, X-Neuro-Nonce.
        """
        if isinstance(payload, str):
            payload = payload.encode()

        ts = str(int(timestamp or time.time()))
        nonce = secrets.token_hex(8)
        message = f"{ts}.{nonce}.".encode() + payload

        with self._lock:
            secret = self._secrets[-1]  # always sign with the newest secret

        sig = hmac.new(secret, message, hashlib.sha256).hexdigest()
        self._total_signed += 1

        return {
            SIGNATURE_HEADER: f"v1={sig}",
            TIMESTAMP_HEADER: ts,
            NONCE_HEADER: nonce,
        }

    # ── Verification ───────────────────────────────────────────────────────────

    def verify(
        self,
        payload: str | bytes,
        signature_header: str,
        timestamp_header: str,
        nonce_header: str = "",
    ) -> VerifyResult:
        """
        Verify a signed request.

        Args:
            payload:           Raw request body.
            signature_header:  Value of X-Neuro-Signature header.
            timestamp_header:  Value of X-Neuro-Timestamp header.
            nonce_header:      Value of X-Neuro-Nonce header (optional).

        Returns:
            VerifyResult with is_valid and reason.
        """
        self._total_verified += 1

        if isinstance(payload, str):
            payload = payload.encode()

        # ── Timestamp check ────────────────────────────────────────────────────
        try:
            ts = int(timestamp_header)
        except (ValueError, TypeError):
            self._total_rejected += 1
            return VerifyResult(False, "invalid_timestamp_format")

        now = time.time()
        age = now - ts
        if abs(age) > self._replay_window:
            self._total_rejected += 1
            return VerifyResult(False, f"timestamp_expired_age_{age:.0f}s", age)

        # ── Nonce replay check ─────────────────────────────────────────────────
        if nonce_header:
            with self._lock:
                self._purge_old_nonces(now)
                if nonce_header in self._nonces:
                    self._total_rejected += 1
                    return VerifyResult(False, "replay_nonce_reused", age)
                self._nonces.add(nonce_header)
                self._nonce_ages.append((now, nonce_header))

        # ── Signature check ────────────────────────────────────────────────────
        nonce = nonce_header or ""
        message = f"{timestamp_header}.{nonce}.".encode() + payload

        # Check against all active secrets (key rotation support)
        expected_prefix = "v1="
        if not signature_header.startswith(expected_prefix):
            self._total_rejected += 1
            return VerifyResult(False, "invalid_signature_format", age)

        provided_sig = signature_header[len(expected_prefix):]  # type: ignore[index]

        with self._lock:
            secrets_to_try = list(self._secrets)

        for secret in reversed(secrets_to_try):   # try newest first
            expected_sig = hmac.new(secret, message, hashlib.sha256).hexdigest()
            if hmac.compare_digest(provided_sig, expected_sig):
                return VerifyResult(True, "ok", age)

        self._total_rejected += 1
        return VerifyResult(False, "signature_mismatch", age)

    def _purge_old_nonces(self, now: float) -> None:
        """Remove nonces older than the replay window. Must hold lock."""
        cutoff = now - self._replay_window
        old = [(ts, n) for ts, n in self._nonce_ages if ts < cutoff]
        for _, n in old:
            self._nonces.discard(n)
        self._nonce_ages = [(ts, n) for ts, n in self._nonce_ages if ts >= cutoff]

        # Hard cap
        if len(self._nonces) > MAX_NONCES:
            excess = len(self._nonces) - MAX_NONCES
            for _, n in self._nonce_ages[:excess]:  # type: ignore[index]
                self._nonces.discard(n)
            self._nonce_ages = self._nonce_ages[excess:]  # type: ignore[index]

    # ── API key helpers ────────────────────────────────────────────────────────

    @staticmethod
    def hash_api_key(raw_key: str) -> str:
        """One-way hash an API key for safe storage."""
        return hashlib.sha256(raw_key.encode()).hexdigest()

    @staticmethod
    def verify_api_key(raw_key: str, stored_hash: str) -> bool:
        """Constant-time comparison of an API key against its stored hash."""
        computed = hashlib.sha256(raw_key.encode()).hexdigest()
        return hmac.compare_digest(computed, stored_hash)

    @staticmethod
    def generate_api_key(prefix: str = "ns") -> str:
        """Generate a secure API key with optional prefix."""
        token = secrets.token_urlsafe(32)
        return f"{prefix}_{token}"

    # ── Stats ──────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_signed": self._total_signed,
                "total_verified": self._total_verified,
                "total_rejected": self._total_rejected,
                "active_secrets": len(self._secrets),
                "tracked_nonces": len(self._nonces),
                "rejection_rate_pct": round(  # type: ignore[call-overload]
                    self._total_rejected / max(self._total_verified, 1) * 100, 1
                ),
            }


# ── Singleton ──────────────────────────────────────────────────────────────────
request_signer = RequestSigner()
