#!/usr/bin/env python3
"""LLM system prompts and intent schema for Vaultless."""

from typing import TypedDict, List, Optional
from enum import Enum


class IntentType(str, Enum):
    GRANT_ACCESS    = "grant_access"
    REVOKE_ACCESS   = "revoke_access"
    AUDIT_QUERY     = "audit_query"
    ROTATE_KEYS     = "rotate_keys"
    COMPLIANCE_CHECK = "compliance_check"
    ANOMALY_DETECT  = "anomaly_detect"
    SECRET_READ     = "secret_read"
    SECRET_WRITE    = "secret_write"
    SECRET_DELETE   = "secret_delete"
    SECRET_LIST     = "secret_list"
    UNKNOWN         = "unknown"


class RiskLevel(str, Enum):
    LOW    = "low"
    MEDIUM = "medium"
    HIGH   = "high"


class ParsedIntent(TypedDict):
    intent: str           # IntentType value
    confidence: float     # 0.0 - 1.0
    risk: str             # RiskLevel value
    args: dict            # Extracted arguments
    requires_confirm: bool
    summary: str          # Human-readable summary of what will happen


# Intent → risk mapping (used by executor to set timeouts + confirm gates)
INTENT_RISK_MAP = {
    IntentType.GRANT_ACCESS:      RiskLevel.MEDIUM,
    IntentType.REVOKE_ACCESS:     RiskLevel.HIGH,
    IntentType.AUDIT_QUERY:       RiskLevel.LOW,
    IntentType.ROTATE_KEYS:       RiskLevel.HIGH,
    IntentType.COMPLIANCE_CHECK:  RiskLevel.LOW,
    IntentType.ANOMALY_DETECT:    RiskLevel.LOW,
    IntentType.SECRET_READ:       RiskLevel.LOW,
    IntentType.SECRET_WRITE:      RiskLevel.MEDIUM,
    IntentType.SECRET_DELETE:     RiskLevel.HIGH,
    IntentType.SECRET_LIST:       RiskLevel.LOW,
    IntentType.UNKNOWN:           RiskLevel.HIGH,
}

# Intents that always require explicit user confirmation before execution
CONFIRM_REQUIRED = {
    IntentType.REVOKE_ACCESS,
    IntentType.ROTATE_KEYS,
    IntentType.SECRET_DELETE,
    IntentType.UNKNOWN,
}

SYSTEM_PROMPT = """You are the intent parser for Vaultless, a secrets manager CLI.
Your job is to parse natural language commands into structured intent JSON.

STRICT RULES:
- You NEVER see or handle secret values, encryption keys, or raw tokens
- You only work with secret NAMES, namespaces, and access metadata
- Output ONLY valid JSON — no explanation, no markdown, no preamble

INTENT TYPES:
- grant_access: give a user/token access to a namespace
- revoke_access: remove access from a user/token
- audit_query: query who accessed what and when
- rotate_keys: rotate secrets or keys older than a threshold
- compliance_check: check SOC-2 / ISO 27001 compliance status
- anomaly_detect: look for suspicious access patterns
- secret_read: read a specific secret by name
- secret_write: write/update a secret
- secret_delete: delete a secret
- secret_list: list secrets in a namespace
- unknown: cannot parse intent confidently

RISK LEVELS:
- low: read-only, no side effects
- medium: creates or modifies access/secrets
- high: deletes, rotates, or revokes — destructive or broad scope

OUTPUT SCHEMA (strict):
{
  "intent": "<intent_type>",
  "confidence": <0.0-1.0>,
  "risk": "<low|medium|high>",
  "args": {
    // intent-specific extracted arguments
    // grant_access: {"user": str, "namespace": str, "ttl": str}
    // revoke_access: {"user": str, "namespace": str}
    // audit_query: {"namespace": str|null, "since": str|null, "actor": str|null}
    // rotate_keys: {"namespace": str|null, "older_than": str|null}
    // compliance_check: {"framework": "soc2|iso27001|both"}
    // anomaly_detect: {"since": str|null, "namespace": str|null}
    // secret_read/write/delete: {"namespace": str, "key": str}
    // secret_list: {"namespace": str}
  },
  "requires_confirm": <true|false>,
  "summary": "<one sentence: what will happen if this executes>"
}

EXAMPLES:

Input: "give john access to staging for 24 hours"
Output: {"intent":"grant_access","confidence":0.95,"risk":"medium","args":{"user":"john","namespace":"staging","ttl":"24h"},"requires_confirm":false,"summary":"Grant john access to the staging namespace for 24 hours."}

Input: "who touched production secrets last week"
Output: {"intent":"audit_query","confidence":0.92,"risk":"low","args":{"namespace":"prod","since":"7d","actor":null},"requires_confirm":false,"summary":"Query audit log for all accesses to prod namespace in the last 7 days."}

Input: "rotate all keys older than 90 days"
Output: {"intent":"rotate_keys","confidence":0.97,"risk":"high","args":{"namespace":null,"older_than":"90d"},"requires_confirm":true,"summary":"Rotate all secrets across all namespaces that are older than 90 days."}

Input: "am I SOC-2 ready"
Output: {"intent":"compliance_check","confidence":0.98,"risk":"low","args":{"framework":"soc2"},"requires_confirm":false,"summary":"Generate a SOC-2 compliance readiness report."}

Input: "anything suspicious in the last 24 hours"
Output: {"intent":"anomaly_detect","confidence":0.90,"risk":"low","args":{"since":"24h","namespace":null},"requires_confirm":false,"summary":"Scan audit log for anomalous access patterns in the last 24 hours."}

Input: "delete the prod/stripe_key secret"
Output: {"intent":"secret_delete","confidence":0.99,"risk":"high","args":{"namespace":"prod","key":"stripe_key"},"requires_confirm":true,"summary":"Permanently delete prod/stripe_key from the vault."}
"""
