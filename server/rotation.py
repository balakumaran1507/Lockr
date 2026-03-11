#!/usr/bin/env python3
"""
Key rotation manager with versioning support.

Allows rotating secrets while keeping old versions for:
- Rollback during deployment issues
- Gradual migration (blue/green deployments)
- Audit trail of all historical values
"""

import json
import secrets
import string
from pathlib import Path
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict


@dataclass
class SecretVersion:
    """A single version of a secret."""
    version: int
    value_hash: str  # SHA-256 of the encrypted value (for audit)
    created_at: str
    created_by: str  # Token or user that created it
    rotation_reason: str  # "manual", "scheduled", "policy", "emergency"
    active: bool  # Only one version is active at a time


@dataclass
class RotationPolicy:
    """Rotation policy for a secret or namespace."""
    enabled: bool
    max_age_days: int  # Rotate after this many days
    keep_versions: int  # How many old versions to keep
    auto_rotate: bool  # Automatically rotate when max_age reached
    notify_before_days: int  # Warn before rotation


class RotationManager:
    """Manages secret rotation with versioning."""

    def __init__(self, vault_root: Path = Path(".vault")):
        self.vault_root = vault_root
        self.versions_dir = vault_root / "versions"
        self.policies_dir = vault_root / "rotation_policies"
        self.versions_dir.mkdir(parents=True, exist_ok=True)
        self.policies_dir.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------------------
    # Version Management
    # -------------------------------------------------------------------------

    def get_version_file(self, secret_path: str) -> Path:
        """Get the version metadata file for a secret."""
        # secret_path like "prod/db_password"
        safe_path = secret_path.replace("/", "_")
        return self.versions_dir / f"{safe_path}.json"

    def get_versions(self, secret_path: str) -> List[SecretVersion]:
        """Get all versions of a secret."""
        version_file = self.get_version_file(secret_path)
        if not version_file.exists():
            return []

        data = json.loads(version_file.read_text())
        return [SecretVersion(**v) for v in data.get("versions", [])]

    def save_versions(self, secret_path: str, versions: List[SecretVersion]):
        """Save version metadata."""
        version_file = self.get_version_file(secret_path)
        data = {
            "secret_path": secret_path,
            "versions": [asdict(v) for v in versions]
        }
        version_file.write_text(json.dumps(data, indent=2))

    def get_active_version(self, secret_path: str) -> Optional[SecretVersion]:
        """Get the currently active version."""
        versions = self.get_versions(secret_path)
        active = [v for v in versions if v.active]
        return active[0] if active else None

    def record_version(
        self,
        secret_path: str,
        value_hash: str,
        created_by: str,
        rotation_reason: str = "manual"
    ) -> SecretVersion:
        """
        Record a new version of a secret.
        Automatically deactivates the previous active version.
        """
        versions = self.get_versions(secret_path)

        # Deactivate all previous versions
        for v in versions:
            v.active = False

        # Create new version
        new_version_num = max([v.version for v in versions], default=0) + 1
        new_version = SecretVersion(
            version=new_version_num,
            value_hash=value_hash,
            created_at=datetime.utcnow().isoformat() + "Z",
            created_by=created_by,
            rotation_reason=rotation_reason,
            active=True
        )

        versions.append(new_version)
        self.save_versions(secret_path, versions)

        return new_version

    def rollback_to_version(self, secret_path: str, version_num: int) -> bool:
        """
        Rollback to a previous version by making it active.
        Returns True if successful.
        """
        versions = self.get_versions(secret_path)

        # Find the target version
        target = None
        for v in versions:
            if v.version == version_num:
                target = v
                v.active = True
            else:
                v.active = False

        if target:
            self.save_versions(secret_path, versions)
            return True

        return False

    def cleanup_old_versions(self, secret_path: str, keep_count: int):
        """
        Remove old versions, keeping only the most recent ones.
        Always keeps the active version.
        """
        versions = self.get_versions(secret_path)

        # Sort by version number (newest first)
        versions_sorted = sorted(versions, key=lambda v: v.version, reverse=True)

        # Keep: active version + most recent versions
        active_version = self.get_active_version(secret_path)
        to_keep = []

        if active_version:
            to_keep.append(active_version)

        # Add most recent versions (up to keep_count)
        for v in versions_sorted:
            if len(to_keep) >= keep_count:
                break
            if v not in to_keep:
                to_keep.append(v)

        self.save_versions(secret_path, to_keep)

    # -------------------------------------------------------------------------
    # Rotation Policies
    # -------------------------------------------------------------------------

    def get_policy_file(self, namespace: str) -> Path:
        """Get the policy file for a namespace."""
        return self.policies_dir / f"{namespace}.json"

    def set_policy(self, namespace: str, policy: RotationPolicy):
        """Set rotation policy for a namespace."""
        policy_file = self.get_policy_file(namespace)
        policy_file.write_text(json.dumps(asdict(policy), indent=2))

    def get_policy(self, namespace: str) -> Optional[RotationPolicy]:
        """Get rotation policy for a namespace."""
        policy_file = self.get_policy_file(namespace)
        if not policy_file.exists():
            return None

        data = json.loads(policy_file.read_text())
        return RotationPolicy(**data)

    def needs_rotation(self, secret_path: str) -> bool:
        """Check if a secret needs rotation based on policy."""
        namespace = secret_path.split("/")[0]
        policy = self.get_policy(namespace)

        if not policy or not policy.enabled:
            return False

        active_version = self.get_active_version(secret_path)
        if not active_version:
            return False

        created_at = datetime.fromisoformat(active_version.created_at.replace("Z", ""))
        age_days = (datetime.utcnow() - created_at).days

        return age_days >= policy.max_age_days

    def get_rotation_candidates(self, namespace: str) -> List[str]:
        """
        Get all secrets in a namespace that need rotation.
        Returns list of secret paths.
        """
        # This would integrate with VaultStore to list all secrets
        # For MVP, we'll return a simple implementation
        candidates = []

        # Scan version files for this namespace
        for version_file in self.versions_dir.glob(f"{namespace}_*.json"):
            data = json.loads(version_file.read_text())
            secret_path = data.get("secret_path")

            if secret_path and self.needs_rotation(secret_path):
                candidates.append(secret_path)

        return candidates

    # -------------------------------------------------------------------------
    # Rotation Operations
    # -------------------------------------------------------------------------

    def rotate_secret(
        self,
        secret_path: str,
        new_value: bytes,
        created_by: str,
        reason: str = "manual"
    ) -> SecretVersion:
        """
        Rotate a secret to a new value.

        Steps:
        1. Store new encrypted value
        2. Record new version
        3. Cleanup old versions per policy
        4. Log rotation event

        Args:
            secret_path: Path like "prod/db_password"
            new_value: New secret value (will be encrypted)
            created_by: User/token performing rotation
            reason: Rotation reason ("manual", "scheduled", "policy", "emergency")

        Returns:
            The new SecretVersion
        """
        from server.store import VaultStore
        from server.audit import AuditLog
        import hashlib

        # 1. Store new value using VaultStore
        store = VaultStore()
        namespace, key = secret_path.split("/", 1)
        value_hash = store.set(secret_path, new_value)

        # 2. Record version
        new_version = self.record_version(
            secret_path=secret_path,
            value_hash=value_hash,
            created_by=created_by,
            rotation_reason=reason
        )

        # 3. Cleanup old versions
        namespace = secret_path.split("/")[0]
        policy = self.get_policy(namespace)
        if policy:
            self.cleanup_old_versions(secret_path, policy.keep_versions)

        # 4. Log rotation
        audit = AuditLog()
        audit.append(
            actor=created_by,
            action="secret_rotate",
            target=secret_path,
            result="success"
        )

        return new_version

    def generate_random_value(self, length: int = 32, charset: str = "all") -> bytes:
        """
        Generate a random secret value for rotation.

        Args:
            length: Length of generated secret
            charset: "all", "alphanumeric", "hex", "base64"

        Returns:
            Random bytes
        """
        if charset == "alphanumeric":
            chars = string.ascii_letters + string.digits
            value = ''.join(secrets.choice(chars) for _ in range(length))
        elif charset == "hex":
            value = secrets.token_hex(length // 2)
        elif charset == "base64":
            value = secrets.token_urlsafe(length)
        else:  # "all"
            chars = string.ascii_letters + string.digits + string.punctuation
            value = ''.join(secrets.choice(chars) for _ in range(length))

        return value.encode()

    def auto_rotate_secret(
        self,
        secret_path: str,
        created_by: str = "system",
        generate: bool = True,
        length: int = 32
    ) -> SecretVersion:
        """
        Automatically rotate a secret with a generated value.

        Args:
            secret_path: Secret to rotate
            created_by: Actor performing rotation
            generate: If True, generate random value. If False, user must provide.
            length: Length of generated secret

        Returns:
            New SecretVersion
        """
        if generate:
            new_value = self.generate_random_value(length=length)
        else:
            raise ValueError("Auto-rotation requires generate=True or provide new_value to rotate_secret()")

        return self.rotate_secret(
            secret_path=secret_path,
            new_value=new_value,
            created_by=created_by,
            reason="scheduled"
        )

    # -------------------------------------------------------------------------
    # Reporting
    # -------------------------------------------------------------------------

    def get_rotation_status(self, namespace: str) -> Dict[str, Any]:
        """Get rotation status for a namespace."""
        policy = self.get_policy(namespace)
        candidates = self.get_rotation_candidates(namespace)

        # Get all secrets in namespace
        all_secrets = []
        for version_file in self.versions_dir.glob(f"{namespace}_*.json"):
            data = json.loads(version_file.read_text())
            secret_path = data.get("secret_path")
            if secret_path:
                all_secrets.append(secret_path)

        return {
            "namespace": namespace,
            "policy": asdict(policy) if policy else None,
            "total_secrets": len(all_secrets),
            "needs_rotation": len(candidates),
            "rotation_candidates": candidates,
            "compliance": len(candidates) == 0 if policy and policy.enabled else None
        }

    def get_secret_history(self, secret_path: str) -> Dict[str, Any]:
        """Get complete history of a secret with all versions."""
        versions = self.get_versions(secret_path)
        active_version = self.get_active_version(secret_path)

        return {
            "secret_path": secret_path,
            "total_versions": len(versions),
            "active_version": active_version.version if active_version else None,
            "versions": [asdict(v) for v in versions],
            "oldest": versions[0].created_at if versions else None,
            "newest": versions[-1].created_at if versions else None
        }
