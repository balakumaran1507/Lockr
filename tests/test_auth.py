#!/usr/bin/env python3
"""Tests for MockAuthStore — token lifecycle and scope enforcement."""

import pytest
from tests.mock_vault import MockAuthStore
from server.auth import TokenNotFoundError, TokenExpiredError, ScopeViolationError


class TestAuthStore:

    def test_create_returns_token(self):
        auth = MockAuthStore()
        token = auth.create(scopes=["myapp/*"])
        assert token.startswith("tk_")

    def test_validate_valid_token(self):
        auth  = MockAuthStore()
        token = auth.create(scopes=["myapp/*"])
        record = auth.validate(token, "myapp/db_password", "read")
        assert record["label"] is not None

    def test_validate_invalid_token_raises(self):
        auth = MockAuthStore()
        with pytest.raises(TokenNotFoundError):
            auth.validate("tk_garbage", "myapp/db", "read")

    def test_validate_wrong_scope_raises(self):
        auth  = MockAuthStore()
        token = auth.create(scopes=["staging/*"])
        with pytest.raises(ScopeViolationError):
            auth.validate(token, "prod/db_password", "read")

    def test_revoke_blocks_access(self):
        auth  = MockAuthStore()
        token = auth.create(scopes=["myapp/*"])
        auth.revoke(token)
        with pytest.raises(TokenExpiredError):
            auth.validate(token, "myapp/db", "read")

    def test_revoke_missing_returns_false(self):
        auth = MockAuthStore()
        assert auth.revoke("tk_ghost") is False

    def test_ttl_expired_blocks_access(self):
        import time
        from unittest.mock import patch
        from datetime import datetime, timezone, timedelta

        auth  = MockAuthStore()
        token = auth.create(scopes=["myapp/*"], ttl="1s")

        # Manually expire by patching datetime
        tid = list(auth._tokens.keys())[0]
        auth._tokens[tid]["expires"] = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        ).isoformat()

        with pytest.raises(TokenExpiredError):
            auth.validate(token, "myapp/db", "read")

    def test_admin_scope_required(self):
        auth  = MockAuthStore()
        token = auth.create(scopes=["myapp/*"])
        with pytest.raises(ScopeViolationError):
            auth.validate_admin(token)

    def test_admin_validate_passes_with_star_scope(self):
        auth  = MockAuthStore()
        token = auth.create(scopes=["*"])
        record = auth.validate_admin(token)
        assert "*" in record["scopes"]

    def test_list_tokens(self):
        auth = MockAuthStore()
        auth.create(scopes=["myapp/*"], label="alice")
        auth.create(scopes=["staging/*"], label="bob")
        tokens = auth.list()
        labels = [t["label"] for t in tokens]
        assert "alice" in labels
        assert "bob" in labels

    def test_glob_scope_matching(self):
        auth  = MockAuthStore()
        token = auth.create(scopes=["myapp/api_*"])
        # Should match
        auth.validate(token, "myapp/api_key", "read")
        # Should not match
        with pytest.raises(ScopeViolationError):
            auth.validate(token, "myapp/db_password", "read")

    def test_never_expires_token(self):
        auth  = MockAuthStore()
        token = auth.create(scopes=["*"])  # no ttl
        record = auth.validate_admin(token)
        assert record["expires"] is None
