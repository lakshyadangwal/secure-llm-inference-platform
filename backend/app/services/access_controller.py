"""
Commit 58: Access Control (RBAC)
==================================
Role-Based Access Control for the Neuro-Sentry API.
Defines roles, permissions, and a lightweight enforcement layer
that works as a FastAPI dependency or a standalone check.

Roles (hierarchical — higher includes lower):
  READONLY  — can view stats and health
  ANALYST   — can view all data, run test probes
  OPERATOR  — can manage watchlists, block/unblock IPs
  ADMIN     — full access, can manage roles and config

Permissions:
  health:read, stats:read, audit:read, diag:read,
  threat_intel:read, watchlist:read, watchlist:write,
  reputation:read, reputation:write, config:read,
  config:write, sessions:read, admin:all

API key management:
  - API keys are hashed (SHA-256) before storage
  - Each key is bound to one role
  - Keys can be revoked without restart
  - Rate of key checks is tracked (brute-force detection)
"""

import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import Optional

logger = logging.getLogger(__name__)

# ── Roles ──────────────────────────────────────────────────────────────────────

class Role(str, Enum):
    READONLY = "readonly"
    ANALYST  = "analyst"
    OPERATOR = "operator"
    ADMIN    = "admin"

    @property
    def level(self) -> int:
        _levels: dict[str, int] = {
            "readonly": 1, "analyst": 2, "operator": 3, "admin": 4,
        }
        return _levels[str(self.value)]

    def has_at_least(self, required: "Role") -> bool:
        return self.level >= required.level


# ── Permissions ────────────────────────────────────────────────────────────────

class Permission(str, Enum):
    HEALTH_READ       = "health:read"
    STATS_READ        = "stats:read"
    AUDIT_READ        = "audit:read"
    DIAG_READ         = "diag:read"
    THREAT_INTEL_READ = "threat_intel:read"
    WATCHLIST_READ    = "watchlist:read"
    WATCHLIST_WRITE   = "watchlist:write"
    REPUTATION_READ   = "reputation:read"
    REPUTATION_WRITE  = "reputation:write"
    CONFIG_READ       = "config:read"
    CONFIG_WRITE      = "config:write"
    SESSIONS_READ     = "sessions:read"
    ADMIN_ALL         = "admin:all"


# Role → Permission mapping
_ROLE_PERMS: dict[str, set[str]] = {
    Role.READONLY.value: {
        Permission.HEALTH_READ.value,
        Permission.STATS_READ.value,
    },
    Role.ANALYST.value: {
        Permission.HEALTH_READ.value,
        Permission.STATS_READ.value,
        Permission.AUDIT_READ.value,
        Permission.DIAG_READ.value,
        Permission.THREAT_INTEL_READ.value,
        Permission.WATCHLIST_READ.value,
        Permission.REPUTATION_READ.value,
        Permission.CONFIG_READ.value,
        Permission.SESSIONS_READ.value,
    },
    Role.OPERATOR.value: {
        Permission.HEALTH_READ.value,
        Permission.STATS_READ.value,
        Permission.AUDIT_READ.value,
        Permission.DIAG_READ.value,
        Permission.THREAT_INTEL_READ.value,
        Permission.WATCHLIST_READ.value,
        Permission.WATCHLIST_WRITE.value,
        Permission.REPUTATION_READ.value,
        Permission.REPUTATION_WRITE.value,
        Permission.CONFIG_READ.value,
        Permission.SESSIONS_READ.value,
    },
    Role.ADMIN.value: {
        Permission.HEALTH_READ.value,
        Permission.STATS_READ.value,
        Permission.AUDIT_READ.value,
        Permission.DIAG_READ.value,
        Permission.THREAT_INTEL_READ.value,
        Permission.WATCHLIST_READ.value,
        Permission.WATCHLIST_WRITE.value,
        Permission.REPUTATION_READ.value,
        Permission.REPUTATION_WRITE.value,
        Permission.CONFIG_READ.value,
        Permission.CONFIG_WRITE.value,
        Permission.SESSIONS_READ.value,
        Permission.ADMIN_ALL.value,
    },
}


def _role_has_permission(role: Role, perm: Permission) -> bool:
    return perm.value in _ROLE_PERMS.get(str(role.value), set())


# ── API Key record ─────────────────────────────────────────────────────────────

@dataclass
class APIKeyRecord:
    name: str                         # human label (e.g., "monitoring-dashboard")
    role: Role
    key_hash: str                     # SHA-256 hex of the raw key
    created_at: float = field(default_factory=time.time)
    last_used_at: Optional[float] = None
    use_count: int = 0
    revoked: bool = False
    revoked_at: Optional[float] = None
    ip_allowlist: list[str] = field(default_factory=list)  # empty = allow all

    @property
    def is_active(self) -> bool:
        return not self.revoked

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "role": self.role.value,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "use_count": self.use_count,
            "revoked": self.revoked,
            "ip_allowlist": self.ip_allowlist,
        }


# ── Auth result ────────────────────────────────────────────────────────────────

@dataclass
class AuthResult:
    is_authenticated: bool
    is_authorised: bool
    role: Optional[Role]
    key_name: Optional[str]
    reason: str

    @property
    def is_ok(self) -> bool:
        return self.is_authenticated and self.is_authorised

    def to_dict(self) -> dict:
        return {
            "is_authenticated": self.is_authenticated,
            "is_authorised": self.is_authorised,
            "role": self.role.value if self.role is not None else None,  # type: ignore[union-attr]
            "key_name": self.key_name,
            "reason": self.reason,
        }


# ── Access Controller ──────────────────────────────────────────────────────────

class AccessController:
    """
    Manages API keys and enforces RBAC for Neuro-Sentry endpoints.
    """

    # Monitor failed auth attempts to detect brute-force
    _BRUTE_FORCE_WINDOW  = 60.0     # seconds
    _BRUTE_FORCE_LIMIT   = 20       # max failures per IP in window

    def __init__(self) -> None:
        self._keys: dict[str, APIKeyRecord] = {}       # key_hash → record
        self._failed_auths: dict[str, list[float]] = {}  # ip → [timestamps]
        self._lock = RLock()
        self._total_auth_attempts = 0
        self._total_auth_failures = 0
        self._total_auth_successes = 0

        # Provision a default admin key on startup for testing
        self._default_admin_key: Optional[str] = None
        raw, hashed = self._generate_key_pair()
        self._default_admin_key = raw
        self._keys[hashed] = APIKeyRecord(
            name="default-admin",
            role=Role.ADMIN,
            key_hash=hashed,
        )
        logger.info("🔑 AccessController initialised (default admin key provisioned)")

    # ── Key generation ─────────────────────────────────────────────────────

    @staticmethod
    def _hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode()).hexdigest()

    @staticmethod
    def _generate_key_pair() -> tuple[str, str]:
        raw = "ns_" + secrets.token_urlsafe(32)
        hashed = hashlib.sha256(raw.encode()).hexdigest()
        return raw, hashed

    def create_key(self, name: str, role: Role, ip_allowlist: Optional[list[str]] = None) -> str:
        """
        Create a new API key with `role` and return the raw key (shown only once).
        """
        raw, hashed = self._generate_key_pair()
        record = APIKeyRecord(
            name=name,
            role=role,
            key_hash=hashed,
            ip_allowlist=ip_allowlist or [],
        )
        with self._lock:
            self._keys[hashed] = record
        logger.info("🔑 API key created — name=%s  role=%s", name, role.value)
        return raw

    def revoke_key(self, key_hash: str) -> bool:
        """Revoke a key by its hash. Returns True if found."""
        with self._lock:
            record = self._keys.get(key_hash)
            if record:
                record.revoked = True
                record.revoked_at = time.time()
                logger.info("🔑 API key revoked — name=%s", record.name)
                return True
        return False

    # ── Authentication & authorisation ─────────────────────────────────────

    def authenticate(
        self,
        raw_key: str,
        required_permission: Optional[Permission] = None,
        ip: str = "unknown",
    ) -> AuthResult:
        """
        Verify `raw_key` and optionally check for `required_permission`.

        Args:
            raw_key:              The plaintext API key from the request.
            required_permission:  The permission this endpoint requires.
            ip:                   Client IP for brute-force tracking.

        Returns:
            AuthResult with authentication and authorisation status.
        """
        self._total_auth_attempts += 1

        # Brute-force check
        if self._is_brute_force(ip):
            self._total_auth_failures += 1
            return AuthResult(False, False, None, None, "brute_force_detected")

        hashed = self._hash_key(raw_key)

        with self._lock:
            record = self._keys.get(hashed)

        if record is None:
            self._record_failure(ip)
            self._total_auth_failures += 1
            return AuthResult(False, False, None, None, "key_not_found")

        if record.revoked:
            self._record_failure(ip)
            self._total_auth_failures += 1
            return AuthResult(False, False, None, None, "key_revoked")

        if record.ip_allowlist and ip not in record.ip_allowlist:
            self._record_failure(ip)
            self._total_auth_failures += 1
            return AuthResult(False, False, record.role, record.name, "ip_not_allowed")

        # Update usage stats
        with self._lock:
            record.last_used_at = time.time()
            record.use_count += 1

        self._total_auth_successes += 1

        if required_permission is not None:
            has_perm = _role_has_permission(record.role, required_permission)
            if not has_perm:
                return AuthResult(True, False, record.role, record.name, "insufficient_permission")
            return AuthResult(True, True, record.role, record.name, "ok")

        return AuthResult(True, True, record.role, record.name, "ok")

    def _record_failure(self, ip: str) -> None:
        now = time.time()
        with self._lock:
            if ip not in self._failed_auths:
                self._failed_auths[ip] = []
            self._failed_auths[ip].append(now)
            # Trim old entries
            cutoff = now - self._BRUTE_FORCE_WINDOW
            self._failed_auths[ip] = [
                t for t in self._failed_auths[ip] if t >= cutoff
            ]

    def _is_brute_force(self, ip: str) -> bool:
        now = time.time()
        cutoff = now - self._BRUTE_FORCE_WINDOW
        with self._lock:
            failures = [t for t in self._failed_auths.get(ip, []) if t >= cutoff]
            return len(failures) >= self._BRUTE_FORCE_LIMIT

    def check_permission(self, role: Role, permission: Permission) -> bool:
        return _role_has_permission(role, permission)

    def list_keys(self) -> list[dict]:
        with self._lock:
            return [r.to_dict() for r in self._keys.values()]

    def get_default_admin_key(self) -> Optional[str]:
        """Return the auto-generated admin key (for development only)."""
        return self._default_admin_key

    def get_stats(self) -> dict:
        with self._lock:
            active_keys = sum(1 for r in self._keys.values() if r.is_active)
            revoked_keys = sum(1 for r in self._keys.values() if r.revoked)
        return {
            "total_keys": len(self._keys),
            "active_keys": active_keys,
            "revoked_keys": revoked_keys,
            "total_auth_attempts": self._total_auth_attempts,
            "total_auth_failures": self._total_auth_failures,
            "total_auth_successes": self._total_auth_successes,
        }


# ── Singleton ──────────────────────────────────────────────────────────────────
access_controller = AccessController()
