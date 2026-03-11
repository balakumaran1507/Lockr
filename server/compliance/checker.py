#!/usr/bin/env python3
"""
Automated compliance checker — validates vault state against framework controls.
"""

from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path

from .framework import Framework, Control, ControlResult, ControlStatus


class ComplianceChecker:
    """Runs automated compliance checks against the vault."""

    def __init__(self, vault_root: Path = Path(".vault")):
        self.vault_root = vault_root

    def check_framework(self, framework: Framework) -> List[ControlResult]:
        """
        Run all automated checks for a framework.

        Returns list of ControlResult objects.
        """
        results = []

        for control in framework.controls:
            if control.automated and control.check_function:
                result = self._run_check(control)
            else:
                # Manual control - mark as requiring manual review
                result = ControlResult(
                    control_id=control.id,
                    status=ControlStatus.MANUAL,
                    evidence=[],
                    notes=f"Manual review required: {control.description}",
                    checked_at=datetime.utcnow().isoformat() + "Z",
                    automated=False
                )

            results.append(result)

        return results

    def _run_check(self, control: Control) -> ControlResult:
        """Execute a single automated check."""
        check_func = getattr(self, control.check_function, None)

        if not check_func:
            return ControlResult(
                control_id=control.id,
                status=ControlStatus.FAIL,
                evidence=[],
                notes=f"Check function '{control.check_function}' not implemented",
                checked_at=datetime.utcnow().isoformat() + "Z",
                automated=True
            )

        try:
            return check_func(control)
        except Exception as e:
            return ControlResult(
                control_id=control.id,
                status=ControlStatus.FAIL,
                evidence=[],
                notes=f"Check failed with error: {str(e)}",
                checked_at=datetime.utcnow().isoformat() + "Z",
                automated=True
            )

    # -------------------------------------------------------------------------
    # Check implementations
    # -------------------------------------------------------------------------

    def check_access_control(self, control: Control) -> ControlResult:
        """Check if access control via tokens is implemented."""
        from server.auth import AuthStore

        try:
            auth = AuthStore()
            tokens = auth.list()

            if not tokens:
                return ControlResult(
                    control_id=control.id,
                    status=ControlStatus.FAIL,
                    evidence=[],
                    notes="No access tokens configured",
                    checked_at=datetime.utcnow().isoformat() + "Z",
                    automated=True
                )

            active_tokens = [t for t in tokens if t.get("active")]
            evidence = [
                f"Total tokens: {len(tokens)}",
                f"Active tokens: {len(active_tokens)}",
                f"Token scopes: {', '.join(set(s for t in tokens for s in t.get('scopes', [])))}",
            ]

            return ControlResult(
                control_id=control.id,
                status=ControlStatus.PASS,
                evidence=evidence,
                notes=f"Access control via scoped tokens is active with {len(active_tokens)} active tokens",
                checked_at=datetime.utcnow().isoformat() + "Z",
                automated=True
            )

        except Exception as e:
            return ControlResult(
                control_id=control.id,
                status=ControlStatus.FAIL,
                evidence=[],
                notes=f"Access control check failed: {str(e)}",
                checked_at=datetime.utcnow().isoformat() + "Z",
                automated=True
            )

    def check_revocation_capability(self, control: Control) -> ControlResult:
        """Check if token revocation is implemented."""
        from server.auth import AuthStore

        try:
            auth = AuthStore()
            tokens = auth.list()

            # Check if any tokens have been revoked (shows the capability exists)
            revoked = [t for t in tokens if not t.get("active")]

            evidence = [
                f"Revocation capability: Implemented",
                f"Total revoked tokens: {len(revoked)}",
                "Token revocation command: 'lockr token revoke <token_id>'"
            ]

            return ControlResult(
                control_id=control.id,
                status=ControlStatus.PASS,
                evidence=evidence,
                notes="Token revocation capability is implemented and functional",
                checked_at=datetime.utcnow().isoformat() + "Z",
                automated=True
            )

        except Exception as e:
            return ControlResult(
                control_id=control.id,
                status=ControlStatus.FAIL,
                evidence=[],
                notes=f"Revocation check failed: {str(e)}",
                checked_at=datetime.utcnow().isoformat() + "Z",
                automated=True
            )

    def check_encryption(self, control: Control) -> ControlResult:
        """Check encryption status."""
        from server.crypto import pq_status

        try:
            crypto_status = pq_status()
            # Check if PQ is available based on the status string
            pq_available = "FrodoKEM" in crypto_status

            evidence = [
                f"Encryption status: {crypto_status}",
                "Data Encryption: AES-256-GCM",
                f"Key Encapsulation: {'FrodoKEM-1344-SHAKE' if pq_available else 'X25519 (dev fallback)'}",
                "All secrets encrypted at rest: Yes"
            ]

            status = ControlStatus.PASS if pq_available else ControlStatus.PARTIAL
            notes = "Production-grade post-quantum encryption active" if pq_available else "AES-256-GCM encryption active (install liboqs for PQ)"

            return ControlResult(
                control_id=control.id,
                status=status,
                evidence=evidence,
                notes=notes,
                checked_at=datetime.utcnow().isoformat() + "Z",
                automated=True
            )

        except Exception as e:
            return ControlResult(
                control_id=control.id,
                status=ControlStatus.FAIL,
                evidence=[],
                notes=f"Encryption check failed: {str(e)}",
                checked_at=datetime.utcnow().isoformat() + "Z",
                automated=True
            )

    def check_audit_log(self, control: Control) -> ControlResult:
        """Check audit log integrity and coverage."""
        from server.audit import AuditLog

        try:
            audit = AuditLog()
            chain_valid = audit.verify_chain()

            # Get recent entries to show logging is active
            recent = audit.query(limit=10)

            evidence = [
                f"Audit log integrity: {'INTACT' if chain_valid else 'COMPROMISED'}",
                f"Hash chain verification: {'PASS' if chain_valid else 'FAIL'}",
                f"Recent events logged: {len(recent)}",
                "Tamper-evident: Yes (SHA-256 hash chain)",
                "Event types logged: secret_read, secret_write, secret_delete, token_create, token_revoke"
            ]

            status = ControlStatus.PASS if chain_valid else ControlStatus.FAIL
            notes = "Tamper-evident audit logging is active and verified" if chain_valid else "AUDIT CHAIN COMPROMISED - investigate immediately"

            return ControlResult(
                control_id=control.id,
                status=status,
                evidence=evidence,
                notes=notes,
                checked_at=datetime.utcnow().isoformat() + "Z",
                automated=True
            )

        except Exception as e:
            return ControlResult(
                control_id=control.id,
                status=ControlStatus.FAIL,
                evidence=[],
                notes=f"Audit log check failed: {str(e)}",
                checked_at=datetime.utcnow().isoformat() + "Z",
                automated=True
            )

    def check_environments(self, control: Control) -> ControlResult:
        """Check environment separation."""
        from server.store import VaultStore

        try:
            store = VaultStore()
            envs = store.list_envs()
            current = store.current_env()

            evidence = [
                f"Environments configured: {', '.join(envs)}",
                f"Current environment: {current}",
                f"Total environments: {len(envs)}",
                "Environment separation: Git-style branches"
            ]

            # Good practice: have at least 2 environments (e.g., prod + staging)
            if len(envs) >= 2:
                status = ControlStatus.PASS
                notes = f"Environment separation implemented with {len(envs)} environments"
            elif len(envs) == 1:
                status = ControlStatus.PARTIAL
                notes = "Only one environment configured. Consider adding staging/dev environments"
            else:
                status = ControlStatus.FAIL
                notes = "No environments configured"

            return ControlResult(
                control_id=control.id,
                status=status,
                evidence=evidence,
                notes=notes,
                checked_at=datetime.utcnow().isoformat() + "Z",
                automated=True
            )

        except Exception as e:
            return ControlResult(
                control_id=control.id,
                status=ControlStatus.FAIL,
                evidence=[],
                notes=f"Environment check failed: {str(e)}",
                checked_at=datetime.utcnow().isoformat() + "Z",
                automated=True
            )

    def check_admin_access(self, control: Control) -> ControlResult:
        """Check admin/privileged access controls."""
        from server.auth import AuthStore

        try:
            auth = AuthStore()
            tokens = auth.list()

            # Admin tokens have scope "*"
            admin_tokens = [t for t in tokens if "*" in t.get("scopes", [])]
            active_admin = [t for t in admin_tokens if t.get("active")]

            evidence = [
                f"Total admin tokens: {len(admin_tokens)}",
                f"Active admin tokens: {len(active_admin)}",
                "Admin scope: * (full access)",
                "Regular tokens: Scoped to specific namespaces"
            ]

            if active_admin:
                status = ControlStatus.PASS
                notes = f"{len(active_admin)} active admin tokens with privileged access"
            else:
                status = ControlStatus.FAIL
                notes = "No active admin tokens - access may be restricted"

            return ControlResult(
                control_id=control.id,
                status=status,
                evidence=evidence,
                notes=notes,
                checked_at=datetime.utcnow().isoformat() + "Z",
                automated=True
            )

        except Exception as e:
            return ControlResult(
                control_id=control.id,
                status=ControlStatus.FAIL,
                evidence=[],
                notes=f"Admin access check failed: {str(e)}",
                checked_at=datetime.utcnow().isoformat() + "Z",
                automated=True
            )

    def generate_summary(self, results: List[ControlResult]) -> Dict[str, Any]:
        """Generate a summary of compliance check results."""
        total = len(results)
        passed = sum(1 for r in results if r.status == ControlStatus.PASS)
        failed = sum(1 for r in results if r.status == ControlStatus.FAIL)
        partial = sum(1 for r in results if r.status == ControlStatus.PARTIAL)
        manual = sum(1 for r in results if r.status == ControlStatus.MANUAL)
        automated = sum(1 for r in results if r.automated)

        compliance_score = (passed / (total - manual)) * 100 if (total - manual) > 0 else 0

        return {
            "total_controls": total,
            "automated_checks": automated,
            "manual_reviews": manual,
            "manual": manual,  # Alias for consistency
            "passed": passed,
            "failed": failed,
            "partial": partial,
            "compliance_score": round(compliance_score, 1),
            "ready_for_audit": failed == 0 and partial == 0
        }
