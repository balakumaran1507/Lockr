#!/usr/bin/env python3
"""Tests for MockStore — git-style content-addressable object store."""

import pytest
from tests.mock_vault import MockStore, VaultFixture


class TestMockStore:

    def test_set_and_get(self):
        s = MockStore()
        s.set("myapp/db_password", b"s3cr3t")
        assert s.get("myapp/db_password") == b"s3cr3t"

    def test_get_missing_raises(self):
        s = MockStore()
        with pytest.raises(KeyError):
            s.get("myapp/nonexistent")

    def test_delete(self):
        s = MockStore()
        s.set("myapp/key", b"val")
        assert s.delete("myapp/key") is True
        with pytest.raises(KeyError):
            s.get("myapp/key")

    def test_delete_missing_returns_false(self):
        s = MockStore()
        assert s.delete("myapp/ghost") is False

    def test_list_namespace(self):
        s = MockStore()
        s.set("myapp/a", b"1")
        s.set("myapp/b", b"2")
        s.set("otherapp/c", b"3")
        keys = s.list("myapp")
        assert sorted(keys) == ["a", "b"]

    def test_overwrite(self):
        s = MockStore()
        s.set("myapp/key", b"old")
        s.set("myapp/key", b"new")
        assert s.get("myapp/key") == b"new"

    def test_env_isolation(self):
        s = MockStore()
        s.set("myapp/key", b"prod-val", env="prod")
        s.set("myapp/key", b"staging-val", env="staging")
        assert s.get("myapp/key", env="prod")    == b"prod-val"
        assert s.get("myapp/key", env="staging") == b"staging-val"

    def test_checkout_switches_env(self):
        s = MockStore()
        s.set("myapp/key", b"prod-val", env="prod")
        s.checkout("staging")
        assert s.current_env() == "staging"
        with pytest.raises(KeyError):
            s.get("myapp/key")  # not in staging

    def test_merge_copies_refs(self):
        s = MockStore()
        s.set("myapp/db", b"prod-db", env="prod")
        s.set("myapp/api", b"prod-api", env="prod")
        count = s.merge("prod", "staging")
        assert count == 2
        # Merge copies ref pointers — objects are AAD-bound to original env path.
        # Real store.merge() does the same: it's a pointer copy (like git).
        # Decryption under staging env would need re-encryption with staging AAD.
        assert s.exists("myapp/db", env="staging")
        assert s.exists("myapp/api", env="staging")

    def test_content_addressable_dedup(self):
        s = MockStore()
        h1 = s.set("myapp/a", b"same")
        h2 = s.set("myapp/b", b"same")
        # Same plaintext + different path = different AAD = different ciphertext = different hash
        # (AAD is bound to path in MockCrypto)
        assert h1 != h2  # paths differ so AAD differs

    def test_exists(self):
        s = MockStore()
        s.set("myapp/key", b"val")
        assert s.exists("myapp/key") is True
        assert s.exists("myapp/ghost") is False

    def test_seed_helper(self):
        s = MockStore()
        s.seed("myapp", {"db": "pass", "api": "key"})
        assert s.get("myapp/db") == b"pass"
        assert s.get("myapp/api") == b"key"

    def test_invalid_path_raises(self):
        from server.store import VaultStore
        with pytest.raises(ValueError):
            VaultStore._split_path("nodot")

    def test_fixture_fresh(self):
        v = VaultFixture.fresh()
        assert v.store.get("myapp/db_password", env="prod") == b"super-secret-db-pass"
        assert v.store.get("myapp/db_password", env="staging") == b"staging-db-pass"
        assert v.admin_token.startswith("tk_")
        assert v.user_token.startswith("tk_")
