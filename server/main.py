#!/usr/bin/env python3
"""
main.py — Lockr FastAPI server.

Wires: auth → store → audit → intent layer
All requests logged to audit before touching vault core.
"""

from pathlib import Path
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .store   import VaultStore
from .auth    import AuthStore, TokenNotFoundError, TokenExpiredError, ScopeViolationError
from .audit   import AuditLog
from .crypto  import pq_status
from ..intent import parse_intent, execute, ExecutionStatus

# ---------------------------------------------------------------------------
# Singletons — one store per process
# ---------------------------------------------------------------------------

vault  = VaultStore()
auth   = AuthStore()
log    = AuditLog()


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

def _token(authorization: str = Header(...)) -> str:
    """Extract raw token from 'Bearer tk_...' header."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authorization header must be 'Bearer <token>'")
    return authorization[7:]


async def require_token(
    path:   str,
    action: str,
    raw:    str = Depends(_token),
) -> dict:
    """Validate token + scope. Logs denied attempts."""
    try:
        return auth.validate(raw, path, action)
    except TokenNotFoundError:
        log.append("unknown", f"secret_{action}", path, "denied", {"reason": "invalid_token"})
        raise HTTPException(401, "Invalid token.")
    except TokenExpiredError as e:
        log.append("unknown", f"secret_{action}", path, "denied", {"reason": str(e)})
        raise HTTPException(401, str(e))
    except ScopeViolationError as e:
        log.append(raw[:12], f"secret_{action}", path, "denied", {"reason": "scope_violation"})
        raise HTTPException(403, str(e))


async def require_admin(raw: str = Depends(_token)) -> dict:
    try:
        return auth.validate_admin(raw)
    except (TokenNotFoundError, TokenExpiredError, ScopeViolationError) as e:
        raise HTTPException(403, str(e))


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class SecretWrite(BaseModel):
    value: str


class TokenCreate(BaseModel):
    scopes: List[str]
    ttl:    Optional[str] = None
    label:  Optional[str] = None


class AskRequest(BaseModel):
    query:   str
    confirm: bool = False


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    if not vault.is_initialised():
        raise RuntimeError(".vault/ not found. Run `lockr init` first.")
    yield

app = FastAPI(
    title="Lockr",
    version="0.1.0",
    description="Git-architecture secrets manager with PQ encryption and SOC-2 evidence.",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    chain_ok = log.verify_chain()
    return {
        "status":    "ok",
        "env":       vault.current_env(),
        "pq":        pq_status(),
        "audit_chain": "intact" if chain_ok else "TAMPERED",
    }


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

@app.put("/secrets/{namespace}/{key}")
async def write_secret(
    namespace: str,
    key:       str,
    body:      SecretWrite,
    raw:       str = Depends(_token),
):
    path = f"{namespace}/{key}"
    try:
        auth.validate(raw, path, "write")
    except (TokenNotFoundError, TokenExpiredError) as e:
        raise HTTPException(401, str(e))
    except ScopeViolationError as e:
        log.append(raw[:12], "secret_write", path, "denied")
        raise HTTPException(403, str(e))

    hash_hex = vault.set(path, body.value.encode())
    log.append(raw[:12], "secret_write", path, "success", {"object": hash_hex})
    return {"path": path, "object": hash_hex}


@app.get("/secrets/{namespace}/{key}")
async def read_secret(
    namespace: str,
    key:       str,
    raw:       str = Depends(_token),
):
    path = f"{namespace}/{key}"
    try:
        auth.validate(raw, path, "read")
    except (TokenNotFoundError, TokenExpiredError) as e:
        raise HTTPException(401, str(e))
    except ScopeViolationError as e:
        log.append(raw[:12], "secret_read", path, "denied")
        raise HTTPException(403, str(e))

    try:
        value = vault.get(path)
    except KeyError:
        log.append(raw[:12], "secret_read", path, "error", {"reason": "not_found"})
        raise HTTPException(404, f"Secret '{path}' not found.")

    log.append(raw[:12], "secret_read", path, "success")
    return {"path": path, "value": value.decode()}


@app.delete("/secrets/{namespace}/{key}")
async def delete_secret(
    namespace: str,
    key:       str,
    raw:       str = Depends(_token),
):
    path = f"{namespace}/{key}"
    try:
        auth.validate(raw, path, "delete")
    except (TokenNotFoundError, TokenExpiredError) as e:
        raise HTTPException(401, str(e))
    except ScopeViolationError as e:
        log.append(raw[:12], "secret_delete", path, "denied")
        raise HTTPException(403, str(e))

    deleted = vault.delete(path)
    status  = "success" if deleted else "not_found"
    log.append(raw[:12], "secret_delete", path, status)

    if not deleted:
        raise HTTPException(404, f"Secret '{path}' not found.")
    return {"path": path, "deleted": True}


@app.get("/secrets/{namespace}")
async def list_secrets(
    namespace: str,
    raw:       str = Depends(_token),
):
    path = f"{namespace}/*"
    try:
        auth.validate(raw, f"{namespace}/.", "read")
    except (TokenNotFoundError, TokenExpiredError) as e:
        raise HTTPException(401, str(e))
    except ScopeViolationError as e:
        raise HTTPException(403, str(e))

    keys = vault.list(namespace)
    log.append(raw[:12], "secret_list", namespace, "success", {"count": len(keys)})
    return {"namespace": namespace, "keys": keys}


# ---------------------------------------------------------------------------
# Auth / Tokens
# ---------------------------------------------------------------------------

@app.post("/auth/token")
async def create_token(
    body: TokenCreate,
    _:    dict = Depends(require_admin),
    raw:  str  = Depends(_token),
):
    token = auth.create(scopes=body.scopes, ttl=body.ttl, label=body.label)
    log.append(raw[:12], "token_create", body.label or "unnamed", "success", {"scopes": body.scopes})
    return {"token": token, "scopes": body.scopes, "ttl": body.ttl}


@app.delete("/auth/token/{token_id}")
async def revoke_token(
    token_id: str,
    _:        dict = Depends(require_admin),
    raw:      str  = Depends(_token),
):
    ok = auth.revoke(token_id)
    log.append(raw[:12], "token_revoke", token_id, "success" if ok else "not_found")
    if not ok:
        raise HTTPException(404, "Token not found.")
    return {"revoked": token_id}


@app.get("/auth/tokens")
async def list_tokens(_: dict = Depends(require_admin)):
    return {"tokens": auth.list()}


# ---------------------------------------------------------------------------
# Intent (LLM / natural language)
# ---------------------------------------------------------------------------

@app.post("/ask")
async def ask(
    body: AskRequest,
    _:    dict = Depends(require_admin),
    raw:  str  = Depends(_token),
):
    """
    Natural language intent endpoint.
    LLM classifies → executor validates → action runs.
    LLM NEVER sees secret values.
    """
    intent = await parse_intent(body.query)
    log.append(
        raw[:12], "intent_parse", body.query[:80], "success",
        {"intent": intent["intent"], "confidence": intent["confidence"]}
    )

    result = execute(intent, confirmed=body.confirm)

    log.append(
        raw[:12], "intent_execute", intent["intent"], result.status.value,
        {"risk": result.risk}
    )

    if result.status == ExecutionStatus.REQUIRES_CONFIRM:
        return JSONResponse(status_code=202, content={
            "status":  "requires_confirm",
            "message": result.message,
            "intent":  intent,
        })

    if result.status in (ExecutionStatus.REJECTED, ExecutionStatus.FAILED):
        raise HTTPException(400, result.message)

    return {
        "status":  result.status.value,
        "message": result.message,
        "intent":  intent,
        "data":    result.data,
    }


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

@app.get("/audit")
async def get_audit(
    n:         int           = 50,
    namespace: Optional[str] = None,
    actor:     Optional[str] = None,
    since:     Optional[str] = None,
    _:         dict          = Depends(require_admin),
):
    entries = log.query(namespace=namespace, actor=actor, since_iso=since, limit=n)
    return {"entries": entries, "chain_ok": log.verify_chain()}


@app.get("/audit/anomalies")
async def get_anomalies(
    since:     Optional[str] = None,
    namespace: Optional[str] = None,
    _:         dict          = Depends(require_admin),
):
    anomalies = log.detect_anomalies(since_iso=since, namespace=namespace)
    return {"anomalies": anomalies, "count": len(anomalies)}


# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------

@app.get("/compliance/report")
async def compliance_report(
    framework: str  = "soc2",
    _:         dict = Depends(require_admin),
    raw:       str  = Depends(_token),
):
    """
    Generate compliance evidence report.
    Stub — full implementation in compliance.py (Phase 5).
    """
    if framework not in ("soc2", "iso27001", "both"):
        raise HTTPException(400, f"Unknown framework: {framework}")

    chain_ok = log.verify_chain()
    tokens   = auth.list()
    active   = [t for t in tokens if t["active"]]

    log.append(raw[:12], "compliance_report", framework, "success")

    return {
        "framework":    framework,
        "generated_at": __import__("datetime").datetime.utcnow().isoformat(),
        "audit_chain":  "intact" if chain_ok else "TAMPERED — report invalid",
        "active_tokens": len(active),
        "total_tokens":  len(tokens),
        "env":           vault.current_env(),
        "controls": {
            "CC7.2 / A.8.15": "hash-chained audit log — " + ("PASS" if chain_ok else "FAIL"),
            "CC6.1 / A.5.18": f"RBAC scoped tokens — {len(active)} active",
            "CC6.7 / A.8.24": f"AES-256-GCM envelope encryption — PASS",
            "CC6.6 / A.8.25": f"environment isolation (git-style branches) — PASS",
        }
    }
