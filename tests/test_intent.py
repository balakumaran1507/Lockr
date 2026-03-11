#!/usr/bin/env python3
"""Tests for intent parser + executor — no Ollama needed."""

import pytest
from unittest.mock import patch
from tests.mock_vault import MockIntentParser
from intent.executor import execute, ExecutionStatus
from intent.prompts import IntentType


class TestIntentParser:

    def test_keyword_fallback_grant_access(self):
        from intent.parser import _fallback_intent
        result = _fallback_intent("give john access to staging")
        assert result["intent"] == IntentType.GRANT_ACCESS.value
        assert result["confidence"] == 0.4

    def test_keyword_fallback_audit_query(self):
        from intent.parser import _fallback_intent
        result = _fallback_intent("who touched production last week")
        assert result["intent"] == IntentType.AUDIT_QUERY.value

    def test_keyword_fallback_rotate(self):
        from intent.parser import _fallback_intent
        result = _fallback_intent("rotate all keys older than 90 days")
        assert result["intent"] == IntentType.ROTATE_KEYS.value

    def test_keyword_fallback_compliance(self):
        from intent.parser import _fallback_intent
        result = _fallback_intent("am I SOC-2 ready")
        assert result["intent"] == IntentType.COMPLIANCE_CHECK.value

    def test_keyword_fallback_anomaly(self):
        from intent.parser import _fallback_intent
        result = _fallback_intent("anything suspicious in the last 24 hours")
        assert result["intent"] == IntentType.ANOMALY_DETECT.value

    def test_keyword_fallback_delete(self):
        from intent.parser import _fallback_intent
        result = _fallback_intent("delete the prod/stripe_key")
        assert result["intent"] == IntentType.SECRET_DELETE.value
        assert result["requires_confirm"] is True  # high risk

    def test_keyword_fallback_unknown(self):
        from intent.parser import _fallback_intent
        result = _fallback_intent("reticulate the splines")
        assert result["intent"] == IntentType.UNKNOWN.value
        assert result["requires_confirm"] is True

    def test_validate_and_repair_bad_intent(self):
        from intent.parser import _validate_and_repair
        raw    = {"intent": "destroy_everything", "confidence": 0.99, "risk": "low", "args": {}}
        result = _validate_and_repair(raw, "test")
        assert result["intent"] == IntentType.UNKNOWN.value

    def test_validate_floors_risk(self):
        from intent.parser import _validate_and_repair
        # secret_delete is HIGH risk in catalog — LLM declaring "low" should be floored
        raw    = {"intent": "secret_delete", "confidence": 0.9, "risk": "low", "args": {}}
        result = _validate_and_repair(raw, "test")
        assert result["risk"] == "high"

    def test_validate_low_confidence_sets_confirm(self):
        from intent.parser import _validate_and_repair
        raw    = {"intent": "secret_read", "confidence": 0.4, "risk": "low", "args": {}}
        result = _validate_and_repair(raw, "test")
        assert result["requires_confirm"] is True

    def test_mock_parser_helper(self):
        intent = MockIntentParser.parse("audit_query", args={"namespace": "prod"})
        assert intent["intent"] == "audit_query"
        assert intent["args"]["namespace"] == "prod"
        assert intent["requires_confirm"] is False

    def test_ollama_down_returns_fallback(self):
        """Simulate Ollama being unreachable — should always return a valid intent."""
        from intent.parser import parse_intent_sync
        import urllib.error

        with patch("intent.parser.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
            result = parse_intent_sync("give john access to staging")

        assert result["intent"] == IntentType.GRANT_ACCESS.value
        assert result["confidence"] == 0.4  # fallback confidence


class TestIntentExecutor:

    def test_audit_query_executes(self):
        intent = MockIntentParser.parse("audit_query", args={"namespace": "prod", "since": "7d"})
        result = execute(intent, confirmed=False)
        assert result.status == ExecutionStatus.SUCCESS

    def test_compliance_check_executes(self):
        intent = MockIntentParser.parse("compliance_check", args={"framework": "soc2"})
        result = execute(intent, confirmed=False)
        assert result.status == ExecutionStatus.SUCCESS

    def test_secret_list_executes(self):
        intent = MockIntentParser.parse("secret_list", args={"namespace": "myapp"})
        result = execute(intent, confirmed=False)
        assert result.status == ExecutionStatus.SUCCESS

    def test_high_risk_requires_confirm(self):
        intent = MockIntentParser.parse(
            "secret_delete",
            args={"namespace": "prod", "key": "stripe_key"},
            risk="high",
        )
        result = execute(intent, confirmed=False)
        assert result.status == ExecutionStatus.REQUIRES_CONFIRM

    def test_high_risk_passes_with_confirm(self):
        intent = MockIntentParser.parse(
            "secret_delete",
            args={"namespace": "prod", "key": "stripe_key"},
            risk="high",
        )
        result = execute(intent, confirmed=True)
        assert result.status == ExecutionStatus.SUCCESS

    def test_unknown_intent_always_rejected(self):
        intent = MockIntentParser.parse("unknown", args={})
        result = execute(intent, confirmed=True)
        assert result.status == ExecutionStatus.REJECTED

    def test_missing_args_rejected(self):
        intent = MockIntentParser.parse(
            "grant_access",
            args={"user": "john"},  # missing namespace
            risk="medium",
        )
        result = execute(intent, confirmed=True)
        assert result.status == ExecutionStatus.REJECTED

    def test_namespace_traversal_rejected(self):
        intent = MockIntentParser.parse(
            "secret_read",
            args={"namespace": "../etc", "key": "passwd"},
            risk="low",
        )
        result = execute(intent, confirmed=True)
        assert result.status == ExecutionStatus.REJECTED

    def test_low_confidence_fallback(self):
        intent = MockIntentParser.parse(
            "secret_read",
            args={"namespace": "myapp", "key": "db"},
            confidence=0.3,
            risk="low",
        )
        result = execute(intent, confirmed=False)
        assert result.status in (ExecutionStatus.FALLBACK, ExecutionStatus.REQUIRES_CONFIRM)

    def test_rotate_keys_requires_confirm(self):
        intent = MockIntentParser.parse(
            "rotate_keys",
            args={"older_than": "90d"},
            risk="high",
        )
        result = execute(intent, confirmed=False)
        assert result.status == ExecutionStatus.REQUIRES_CONFIRM

    def test_grant_access_executes(self):
        intent = MockIntentParser.parse(
            "grant_access",
            args={"user": "john", "namespace": "staging", "ttl": "24h"},
            risk="medium",
        )
        result = execute(intent, confirmed=False)
        assert result.status == ExecutionStatus.SUCCESS
        assert "john" in result.message
