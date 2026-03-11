#!/usr/bin/env python3
"""Intent parser — LLM classification via inference.py (pure stdlib, no httpx)."""

import json
import urllib.request
import urllib.error
from typing import Optional

from .prompts import (
    ParsedIntent,
    IntentType,
    COMMAND_CATALOG,
    SYSTEM_PROMPT,
)

OLLAMA_URL   = "http://localhost:11434/api/chat"
OLLAMA_MODEL = "qwen2.5-coder:7b"
TIMEOUT_S    = 60


# ---------------------------------------------------------------------------
# Ollama call — mirrors inference.py exactly
# ---------------------------------------------------------------------------

def _call_model(user_input: str) -> str:
    """
    Hit local Ollama. Pure stdlib — no httpx, no async.
    Raises RuntimeError if Ollama is unreachable.
    """
    payload = {
        "model":  OLLAMA_MODEL,
        "stream": False,
        "options": {"temperature": 0.0},  # classifier — deterministic
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_input},
        ],
    }

    req = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
        data = json.loads(resp.read().decode())
        return data["message"]["content"].strip()


def is_ollama_running() -> bool:
    """Quick health check before any model call."""
    try:
        urllib.request.urlopen("http://localhost:11434", timeout=3)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Fallback — keyword matching when Ollama is down
# ---------------------------------------------------------------------------

def _fallback_intent(user_input: str) -> ParsedIntent:
    """
    Keyword fallback — vault stays operable even with no LLM.
    """
    text = user_input.lower()

    if any(w in text for w in ["give", "grant", "access", "allow"]):
        intent = IntentType.GRANT_ACCESS
    elif any(w in text for w in ["revoke", "remove access", "deny"]):
        intent = IntentType.REVOKE_ACCESS
    elif any(w in text for w in ["who", "touched", "accessed", "audit", "log"]):
        intent = IntentType.AUDIT_QUERY
    elif any(w in text for w in ["rotate", "rotation"]):
        intent = IntentType.ROTATE_KEYS
    elif any(w in text for w in ["soc", "iso", "compliance", "ready"]):
        intent = IntentType.COMPLIANCE_CHECK
    elif any(w in text for w in ["suspicious", "anomaly", "unusual", "weird"]):
        intent = IntentType.ANOMALY_DETECT
    elif any(w in text for w in ["delete", "remove", "drop"]):
        intent = IntentType.SECRET_DELETE
    elif any(w in text for w in ["set", "write", "update", "store"]):
        intent = IntentType.SECRET_WRITE
    elif any(w in text for w in ["get", "read", "show", "fetch", "what is"]):
        intent = IntentType.SECRET_READ
    elif any(w in text for w in ["list", "ls", "all keys", "all secrets"]):
        intent = IntentType.SECRET_LIST
    else:
        intent = IntentType.UNKNOWN

    command = COMMAND_CATALOG.get(intent, "")

    return ParsedIntent(
        intent=intent.value,
        command=command,
        args={},
        summary=f"[fallback] Detected intent: {intent.value}. Use specific CLI command for best results.",
    )


# ---------------------------------------------------------------------------
# Validate + repair LLM output — never trust it raw
# ---------------------------------------------------------------------------

def _validate_and_repair(raw: dict, user_input: str) -> ParsedIntent:
    valid_intents = {i.value for i in IntentType}

    intent_str = raw.get("intent", IntentType.UNKNOWN.value)
    if intent_str not in valid_intents:
        intent_str = IntentType.UNKNOWN.value

    intent = IntentType(intent_str)
    command = raw.get("command", COMMAND_CATALOG.get(intent, ""))

    return ParsedIntent(
        intent=intent.value,
        command=command,
        args=raw.get("args", {}),
        summary=raw.get("summary", f"Execute {intent.value} based on: '{user_input}'"),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_intent_sync(user_input: str) -> ParsedIntent:
    """
    Parse natural language into a structured vault intent.
    Sync — no async needed since we use stdlib urllib.

    Falls back to keyword matching if Ollama is down.
    Always returns a valid ParsedIntent, never raises.
    """
    try:
        content = _call_model(user_input)

        # Strip markdown fences if model wrapped output
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
            content = content.strip()

        raw = json.loads(content)
        return _validate_and_repair(raw, user_input)

    except urllib.error.URLError:
        return _fallback_intent(user_input)

    except (json.JSONDecodeError, KeyError):
        return _fallback_intent(user_input)

    except Exception:
        return _fallback_intent(user_input)


async def parse_intent(user_input: str) -> ParsedIntent:
    """Async alias for main.py — just calls sync (urllib is blocking anyway)."""
    return parse_intent_sync(user_input)
