#!/usr/bin/env python3
"""
tests/mock_vault.py — In-memory mock vault for testing and feature dev.

Mirrors the real server layer exactly but:
  - No disk I/O
  - No real crypto (AES still runs, FrodoKEM skipped)
  - No Ollama needed (intent parser stubbed)
  - Fully deterministic

Use this to build features before wiring to the real store.
"""

import hashlib
import json
import secrets
from datetime import datetime, timezone, timedelta
from fnmatch import fnmatch
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Mock Crypto — AES-256-GCM still runs, KEK is just a fixed test key
# ---------------------------------------------------------------------------

class MockCrypto:
    """Encrypt/decrypt with a fixed test key. Never use in prod."""

    TEST_KEY = b"\xde\xad\xbe\xef" * 8  # 32 bytes

    @staticmethod
    def encrypt(plaintext: bytes, path: str) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = b"\x00" * 12  # Fixed nonce for determinism in tests
        ct    = AESGCM(MockCrypto.TEST_KEY).encrypt(nonce, plaintext, path.encode())
        return nonce + ct

    @staticmethod
    def decrypt(data: bytes, path: str) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce, ct = data[:12], data[12:]
        return AESGCM(MockCrypto.TEST_KEY).decrypt(nonce, ct, path.encode())

    @staticmethod
    def content_hash(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Mock Store — in-memory .vault/ object store
# ---------------------------------------------------------------------------

class MockStore:
    """
    In-memory implementation of VaultStore.
    Same interface — drop-in for tests.
    """

    def __init__(self, default_env: str = "prod"):
        self._objects: Dict[str, bytes]           = {}   # hash → encrypted bytes
        self._refs:    Dict[str, Dict[str, str]]  = {}   # env/ns/key → hash
        self._env:     str                        = default_env
        self._envs:    List[str]                  = [default_env]

    # -- env --

    def current_env(self) -> str:
        return self._env

    def checkout(self, env: str) -> None:
        if env not in self._envs:
            self._envs.append(env)
        self._env = env

    def list_envs(self) -> List[str]:
        return list(self._envs)

    def is_initialised(self) -> bool:
        return True

    # -- CRUD --

    def set(self, path: str, value: bytes, env: Optional[str] = None) -> str:
        env = env or self._env
        full = f"{env}/{path}"
        enc  = MockCrypto.encrypt(value, full)
        h    = MockCrypto.content_hash(enc)
        self._objects[h] = enc
        self._refs[full]  = h
        return h

    def get(self, path: str, env: Optional[str] = None) -> bytes:
        env  = env or self._env
        full = f"{env}/{path}"
        h    = self._refs.get(full)
        if h is None:
            raise KeyError(f"Secret '{full}' not found.")
        return MockCrypto.decrypt(self._objects[h], full)

    def delete(self, path: str, env: Optional[str] = None) -> bool:
        env  = env or self._env
        full = f"{env}/{path}"
        if full not in self._refs:
            return False
        del self._refs[full]
        return True

    def exists(self, path: str, env: Optional[str] = None) -> bool:
        env  = env or self._env
        return f"{env}/{path}" in self._refs

    def list(self, namespace: str, env: Optional[str] = None) -> List[str]:
        env    = env or self._env
        prefix = f"{env}/{namespace}/"
        return [
            k[len(prefix):]
            for k in self._refs
            if k.startswith(prefix)
        ]

    def merge(self, src_env: str, dst_env: str) -> int:
        count = 0
        src_prefix = f"{src_env}/"
        for full, h in list(self._refs.items()):
            if full.startswith(src_prefix):
                dst_key = f"{dst_env}/" + full[len(src_prefix):]
                self._refs[dst_key] = h
                count += 1
        if dst_env not in self._envs:
            self._envs.append(dst_env)
        return count

    # -- helpers for tests --

    def dump(self) -> Dict:
        return {"env": self._env, "refs": dict(self._refs)}

    def seed(self, namespace: str, secrets_dict: Dict[str, str], env: Optional[str] = None) -> None:
        """Convenience: bulk-insert secrets for test setup."""
        for key, value in secrets_dict.items():
            self.set(f"{namespace}/{key}", value.encode(), env=env)


# ---------------------------------------------------------------------------
# Mock Audit Log — in-memory JSONL
# ---------------------------------------------------------------------------

class MockAuditLog:
    """In-memory audit log. Verifiable chain works exactly like real one."""

    GENESIS_HASH = "0" * 64

    def __init__(self):
        self._entries: List[Dict] = []

    def append(
        self,
        actor:    str,
        action:   str,
        target:   str,
        result:   str,
        metadata: Optional[Dict] = None,
    ) -> str:
        prev_hash = self._last_hash()
        body = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor":     actor,
            "action":    action,
            "target":    target,
            "result":    result,
            "prev_hash": prev_hash,
        }
        if metadata:
            body["metadata"] = metadata

        body_str   = json.dumps(body, sort_keys=True, separators=(",", ":"))
        entry_hash = hashlib.sha256((prev_hash + body_str).encode()).hexdigest()
        body["hash"] = entry_hash
        self._entries.append(body)
        return entry_hash

    def tail(self, n: int = 50) -> List[Dict]:
        return self._entries[-n:]

    def query(
        self,
        namespace:  Optional[str] = None,
        actor:      Optional[str] = None,
        action:     Optional[str] = None,
        since_iso:  Optional[str] = None,
        limit:      int = 200,
    ) -> List[Dict]:
        entries = list(self._entries)
        if since_iso:
            entries = [e for e in entries if e["timestamp"] >= since_iso]
        if namespace:
            entries = [e for e in entries if e["target"].startswith(namespace)]
        if actor:
            entries = [e for e in entries if e["actor"] == actor]
        if action:
            entries = [e for e in entries if e["action"] == action]
        return list(reversed(entries))[:limit]

    def verify_chain(self) -> bool:
        prev_hash = self.GENESIS_HASH
        for entry in self._entries:
            stored = entry.get("hash")
            copy   = {k: v for k, v in entry.items() if k != "hash"}
            body_str  = json.dumps(copy, sort_keys=True, separators=(",", ":"))
            expected  = hashlib.sha256((prev_hash + body_str).encode()).hexdigest()
            if expected != stored:
                return False
            prev_hash = stored
        return True

    def detect_anomalies(self, since_iso=None, namespace=None) -> List[Dict]:
        from collections import Counter
        entries   = self.query(namespace=namespace, since_iso=since_iso, limit=1000)
        anomalies = []

        for e in entries:
            if e["result"] == "denied":
                anomalies.append({**e, "anomaly": "access_denied"})

        for e in entries:
            hour = int(e["timestamp"][11:13])
            if e["action"] == "secret_read" and 0 <= hour < 6:
                anomalies.append({**e, "anomaly": "off_hours_read"})

        counts: Counter = Counter(
            e["actor"] for e in entries if e["action"] == "secret_read"
        )
        for actor, count in counts.items():
            if count > 20:
                anomalies.append({"anomaly": "high_volume_reads", "actor": actor, "count": count})

        return anomalies

    def _last_hash(self) -> str:
        return self._entries[-1]["hash"] if self._entries else self.GENESIS_HASH

    def all(self) -> List[Dict]:
        return list(self._entries)


# ---------------------------------------------------------------------------
# Mock Auth — in-memory token store
# ---------------------------------------------------------------------------

class MockAuthStore:
    """In-memory token store. Same interface as AuthStore."""

    def __init__(self):
        self._tokens: Dict[str, Dict] = {}

    def create(
        self,
        scopes: List[str],
        ttl:    Optional[str] = None,
        label:  Optional[str] = None,
    ) -> str:
        raw      = "tk_" + secrets.token_urlsafe(16)
        token_id = hashlib.sha256(raw.encode()).hexdigest()

        expires = None
        if ttl:
            from server.auth import _parse_ttl
            expires = (datetime.now(timezone.utc) + _parse_ttl(ttl)).isoformat()

        self._tokens[token_id] = {
            "id":      token_id,
            "label":   label or token_id[:12],
            "scopes":  scopes,
            "created": datetime.now(timezone.utc).isoformat(),
            "expires": expires,
            "revoked": False,
        }
        return raw

    def revoke(self, raw_or_id: str) -> bool:
        tid = (
            hashlib.sha256(raw_or_id.encode()).hexdigest()
            if raw_or_id.startswith("tk_")
            else raw_or_id
        )
        if tid not in self._tokens:
            return False
        self._tokens[tid]["revoked"] = True
        return True

    def list(self) -> List[Dict]:
        return [
            {**t, "active": self._is_active(t)}
            for t in self._tokens.values()
        ]

    def validate(self, raw: str, path: str, action: str) -> Dict:
        from server.auth import TokenNotFoundError, TokenExpiredError, ScopeViolationError
        tid    = hashlib.sha256(raw.encode()).hexdigest()
        record = self._tokens.get(tid)
        if not record:
            raise TokenNotFoundError("Invalid token.")
        if record["revoked"]:
            raise TokenExpiredError("Token revoked.")
        if not self._is_active(record):
            raise TokenExpiredError("Token expired.")
        if not any(fnmatch(path, s) for s in record["scopes"]):
            raise ScopeViolationError(f"Not scoped for '{path}'.")
        return record

    def validate_admin(self, raw: str) -> Dict:
        from server.auth import TokenNotFoundError, TokenExpiredError, ScopeViolationError
        tid    = hashlib.sha256(raw.encode()).hexdigest()
        record = self._tokens.get(tid)
        if not record:
            raise TokenNotFoundError("Invalid token.")
        if record["revoked"] or not self._is_active(record):
            raise TokenExpiredError("Token expired/revoked.")
        if "*" not in record["scopes"]:
            raise ScopeViolationError("Admin scope required.")
        return record

    @staticmethod
    def _is_active(record: Dict) -> bool:
        if record.get("revoked"):
            return False
        expires = record.get("expires")
        if not expires:
            return True
        return datetime.now(timezone.utc) < datetime.fromisoformat(expires)


# ---------------------------------------------------------------------------
# Mock Intent Parser — no Ollama needed
# ---------------------------------------------------------------------------

class MockIntentParser:
    """
    Stubbed intent parser for testing executor logic.
    Returns a pre-baked ParsedIntent without hitting Ollama.
    """

    @staticmethod
    def parse(
        intent:    str,
        args:      Optional[Dict] = None,
        confidence: float = 0.95,
        risk:      str = "low",
    ) -> Dict:
        from intent.prompts import CONFIRM_REQUIRED, IntentType
        intent_enum = IntentType(intent)
        requires_confirm = (
            intent_enum in CONFIRM_REQUIRED
            or risk == "high"
            or confidence < 0.7
        )
        return {
            "intent":          intent,
            "confidence":      confidence,
            "risk":            risk,
            "args":            args or {},
            "requires_confirm": requires_confirm,
            "summary":         f"[mock] {intent} with args {args}",
        }


# ---------------------------------------------------------------------------
# Vault fixture — pre-wired mock for tests
# ---------------------------------------------------------------------------

@dataclass
class VaultFixture:
    """
    Fully wired mock vault for tests and feature development.

    Usage:
        v = VaultFixture.fresh()
        v.store.set("myapp/db_pass", b"secret")
        v.audit.append("tk_test", "secret_read", "myapp/db_pass", "success")
        assert v.audit.verify_chain()
    """
    store:  MockStore      = field(default_factory=MockStore)
    audit:  MockAuditLog   = field(default_factory=MockAuditLog)
    auth:   MockAuthStore  = field(default_factory=MockAuthStore)
    parser: MockIntentParser = field(default_factory=MockIntentParser)

    # Pre-created tokens
    admin_token: str = ""
    user_token:  str = ""

    @classmethod
    def fresh(cls, seed_secrets: bool = True) -> "VaultFixture":
        """
        Create a fresh fixture with:
          - prod + staging environments
          - admin token (scope=*)
          - user token (scope=myapp/*)
          - seeded secrets if requested
        """
        v = cls()

        v.admin_token = v.auth.create(scopes=["*"],       label="admin")
        v.user_token  = v.auth.create(scopes=["myapp/*"], label="user",  ttl="24h")

        v.store.checkout("prod")
        v.store.checkout("staging")
        v.store.checkout("prod")  # back to prod as default

        if seed_secrets:
            v.store.seed("myapp", {
                "db_password":  "super-secret-db-pass",
                "api_key":      "sk-test-abc123",
                "stripe_key":   "sk_live_xyz789",
            }, env="prod")

            v.store.seed("myapp", {
                "db_password":  "staging-db-pass",
                "api_key":      "sk-staging-abc123",
            }, env="staging")

        return v
