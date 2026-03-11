#!/usr/bin/env python3
"""Tests for MockAuditLog — hash-chained tamper-evident log."""

import pytest
from tests.mock_vault import MockAuditLog


class TestAuditLog:

    def test_append_and_tail(self):
        log = MockAuditLog()
        log.append("tk_admin", "secret_read", "myapp/db", "success")
        log.append("tk_admin", "secret_write", "myapp/api", "success")
        entries = log.tail(10)
        assert len(entries) == 2
        assert entries[0]["action"] == "secret_read"

    def test_chain_intact_after_appends(self):
        log = MockAuditLog()
        for i in range(10):
            log.append("tk_test", "secret_read", f"myapp/key{i}", "success")
        assert log.verify_chain() is True

    def test_chain_broken_after_tamper(self):
        log = MockAuditLog()
        log.append("tk_admin", "secret_read", "myapp/db", "success")
        log.append("tk_admin", "secret_write", "myapp/api", "success")

        # Tamper with first entry
        log._entries[0]["actor"] = "tk_evil"

        assert log.verify_chain() is False

    def test_empty_log_chain_valid(self):
        log = MockAuditLog()
        assert log.verify_chain() is True

    def test_genesis_hash_sentinel(self):
        log = MockAuditLog()
        log.append("tk_admin", "secret_read", "myapp/db", "success")
        assert log._entries[0]["prev_hash"] == "0" * 64

    def test_query_by_namespace(self):
        log = MockAuditLog()
        log.append("tk_a", "secret_read", "myapp/db",    "success")
        log.append("tk_a", "secret_read", "otherapp/key", "success")
        results = log.query(namespace="myapp")
        assert all(e["target"].startswith("myapp") for e in results)
        assert len(results) == 1

    def test_query_by_actor(self):
        log = MockAuditLog()
        log.append("tk_alice", "secret_read",  "myapp/a", "success")
        log.append("tk_bob",   "secret_write", "myapp/b", "success")
        results = log.query(actor="tk_alice")
        assert len(results) == 1
        assert results[0]["actor"] == "tk_alice"

    def test_query_by_action(self):
        log = MockAuditLog()
        log.append("tk_a", "secret_read",   "myapp/a", "success")
        log.append("tk_a", "secret_write",  "myapp/b", "success")
        log.append("tk_a", "token_create",  "admin",   "success")
        results = log.query(action="secret_read")
        assert len(results) == 1

    def test_query_returns_newest_first(self):
        log = MockAuditLog()
        log.append("tk_a", "secret_read", "myapp/a", "success")
        log.append("tk_a", "secret_read", "myapp/b", "success")
        results = log.query()
        assert results[0]["target"] == "myapp/b"

    def test_anomaly_denied(self):
        log = MockAuditLog()
        log.append("tk_bad", "secret_read", "myapp/db", "denied")
        anomalies = log.detect_anomalies()
        assert any(a["anomaly"] == "access_denied" for a in anomalies)

    def test_anomaly_high_volume(self):
        log = MockAuditLog()
        for i in range(25):
            log.append("tk_scraper", "secret_read", f"myapp/key{i}", "success")
        anomalies = log.detect_anomalies()
        assert any(
            a["anomaly"] == "high_volume_reads" and a["actor"] == "tk_scraper"
            for a in anomalies
        )

    def test_metadata_stored(self):
        log = MockAuditLog()
        log.append("tk_a", "secret_read", "myapp/db", "success", {"env": "prod"})
        assert log.all()[0]["metadata"]["env"] == "prod"

    def test_chain_still_valid_with_metadata(self):
        log = MockAuditLog()
        log.append("tk_a", "secret_read", "myapp/db", "success", {"foo": "bar"})
        log.append("tk_a", "secret_write", "myapp/api", "success")
        assert log.verify_chain() is True
