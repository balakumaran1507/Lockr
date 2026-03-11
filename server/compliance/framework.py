#!/usr/bin/env python3
"""
Compliance framework manager — SOC2, ISO 27001, and custom frameworks.

Allows companies to:
  1. Use built-in SOC2/ISO27001 templates
  2. Upload custom framework requirements
  3. Auto-check compliance against vault state
  4. Generate evidence reports
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum


class ControlStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_APPLICABLE = "n/a"
    MANUAL = "manual"


@dataclass
class Control:
    """A single compliance control requirement."""
    id: str
    title: str
    description: str
    automated: bool  # Can Lockr check this automatically?
    check_function: Optional[str] = None  # Name of Python function to run
    evidence_required: List[str] = None  # What evidence is needed
    category: str = "general"

    def __post_init__(self):
        if self.evidence_required is None:
            self.evidence_required = []


@dataclass
class ControlResult:
    """Result of checking a single control."""
    control_id: str
    status: ControlStatus
    evidence: List[str]
    notes: str
    checked_at: str
    automated: bool


@dataclass
class Framework:
    """A compliance framework (SOC2, ISO27001, or custom)."""
    name: str
    version: str
    controls: List[Control]
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class FrameworkStore:
    """Manages compliance frameworks and check results."""

    def __init__(self, vault_root: Path = Path(".vault")):
        self.vault_root = vault_root
        self.frameworks_dir = vault_root / "frameworks"
        self.results_dir = vault_root / "compliance_results"
        self.frameworks_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)

        # Initialize built-in frameworks
        self._init_builtin_frameworks()

    def _init_builtin_frameworks(self):
        """Create SOC2 and ISO27001 templates if they don't exist."""
        soc2_path = self.frameworks_dir / "soc2_default.json"
        iso27001_path = self.frameworks_dir / "iso27001_default.json"

        if not soc2_path.exists():
            self._create_soc2_framework()

        if not iso27001_path.exists():
            self._create_iso27001_framework()

    def _create_soc2_framework(self):
        """Create SOC2 Trust Services Criteria framework."""
        controls = [
            Control(
                id="CC6.1",
                title="Logical Access - Identity Management",
                description="Who has access to production secrets?",
                automated=True,
                check_function="check_access_control",
                evidence_required=["token_list", "audit_log"],
                category="security"
            ),
            Control(
                id="CC6.2",
                title="Logical Access - Access Revocation",
                description="Can you revoke access when needed?",
                automated=True,
                check_function="check_revocation_capability",
                evidence_required=["revoked_tokens"],
                category="security"
            ),
            Control(
                id="CC6.7",
                title="Encryption at Rest",
                description="Are secrets encrypted when stored?",
                automated=True,
                check_function="check_encryption",
                evidence_required=["crypto_status"],
                category="security"
            ),
            Control(
                id="CC7.2",
                title="Audit Logging and Monitoring",
                description="Are all access events logged?",
                automated=True,
                check_function="check_audit_log",
                evidence_required=["audit_chain_verification"],
                category="monitoring"
            ),
            Control(
                id="CC6.3",
                title="Access Review",
                description="Regular reviews of who has access",
                automated=False,
                evidence_required=["manual_review_records"],
                category="security"
            ),
            Control(
                id="CC6.6",
                title="Environment Separation",
                description="Production separated from dev/test?",
                automated=True,
                check_function="check_environments",
                evidence_required=["environment_list"],
                category="configuration"
            ),
            Control(
                id="A1.2",
                title="Disaster Recovery",
                description="Backup and recovery procedures",
                automated=False,
                evidence_required=["backup_policy", "recovery_test"],
                category="availability"
            ),
        ]

        framework = Framework(
            name="SOC2",
            version="2017",
            controls=controls,
            metadata={
                "description": "SOC 2 Trust Services Criteria",
                "applicable_trust_principles": ["Security", "Availability", "Confidentiality"]
            }
        )

        self.save_framework(framework)

    def _create_iso27001_framework(self):
        """Create ISO 27001:2022 framework."""
        controls = [
            Control(
                id="A.5.18",
                title="Access Rights",
                description="Access to secrets is controlled via tokens",
                automated=True,
                check_function="check_access_control",
                evidence_required=["token_list", "scope_enforcement"],
                category="access_control"
            ),
            Control(
                id="A.8.15",
                title="Logging",
                description="Security event logging",
                automated=True,
                check_function="check_audit_log",
                evidence_required=["audit_log", "log_integrity"],
                category="monitoring"
            ),
            Control(
                id="A.8.24",
                title="Cryptographic Controls",
                description="Use of encryption for data protection",
                automated=True,
                check_function="check_encryption",
                evidence_required=["encryption_algorithms", "key_management"],
                category="cryptography"
            ),
            Control(
                id="A.8.25",
                title="Secure Development Lifecycle",
                description="Security in system development",
                automated=False,
                evidence_required=["development_policy", "code_review"],
                category="development"
            ),
            Control(
                id="A.8.2",
                title="Privileged Access Rights",
                description="Admin access is controlled",
                automated=True,
                check_function="check_admin_access",
                evidence_required=["admin_token_list"],
                category="access_control"
            ),
            Control(
                id="A.17.1",
                title="Information Backup",
                description="Backup procedures",
                automated=False,
                evidence_required=["backup_procedure", "backup_tests"],
                category="availability"
            ),
        ]

        framework = Framework(
            name="ISO27001",
            version="2022",
            controls=controls,
            metadata={
                "description": "ISO/IEC 27001:2022 Information Security Controls",
                "certification_body": "To be determined"
            }
        )

        self.save_framework(framework)

    def save_framework(self, framework: Framework):
        """Save a framework to disk."""
        filename = f"{framework.name.lower().replace(' ', '_')}_default.json"
        path = self.frameworks_dir / filename

        data = {
            "name": framework.name,
            "version": framework.version,
            "controls": [asdict(c) for c in framework.controls],
            "metadata": framework.metadata
        }

        path.write_text(json.dumps(data, indent=2))

    def load_framework(self, name: str) -> Optional[Framework]:
        """Load a framework by name."""
        filename = f"{name.lower().replace(' ', '_')}_default.json"
        path = self.frameworks_dir / filename

        if not path.exists():
            # Try loading as custom framework
            custom_path = self.frameworks_dir / f"{name}.json"
            if custom_path.exists():
                path = custom_path
            else:
                return None

        data = json.loads(path.read_text())
        controls = [Control(**c) for c in data["controls"]]

        return Framework(
            name=data["name"],
            version=data["version"],
            controls=controls,
            metadata=data.get("metadata", {})
        )

    def list_frameworks(self) -> List[str]:
        """List all available frameworks."""
        frameworks = []
        for path in self.frameworks_dir.glob("*.json"):
            frameworks.append(path.stem.replace("_default", "").upper())
        return sorted(frameworks)

    def upload_custom_framework(self, name: str, controls_data: List[Dict]) -> Framework:
        """
        Upload a custom compliance framework.

        Args:
            name: Framework name
            controls_data: List of control dictionaries with keys:
                - id: Control ID
                - title: Control title
                - description: What the control checks
                - automated: Whether Lockr can auto-check (default: False)
                - category: Control category (optional)

        Returns:
            The created Framework object
        """
        controls = []
        for c in controls_data:
            control = Control(
                id=c["id"],
                title=c["title"],
                description=c["description"],
                automated=c.get("automated", False),
                check_function=c.get("check_function"),
                evidence_required=c.get("evidence_required", []),
                category=c.get("category", "general")
            )
            controls.append(control)

        framework = Framework(
            name=name,
            version=c.get("version", "1.0"),
            controls=controls,
            metadata=c.get("metadata", {})
        )

        # Save as custom framework
        filename = f"{name.lower().replace(' ', '_')}.json"
        path = self.frameworks_dir / filename

        data = {
            "name": framework.name,
            "version": framework.version,
            "controls": [asdict(c) for c in framework.controls],
            "metadata": framework.metadata
        }

        path.write_text(json.dumps(data, indent=2))
        return framework

    def save_results(self, framework_name: str, results: List[ControlResult]):
        """Save compliance check results."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{framework_name.lower()}_{timestamp}.json"
        path = self.results_dir / filename

        data = {
            "framework": framework_name,
            "timestamp": timestamp,
            "results": [asdict(r) for r in results]
        }

        path.write_text(json.dumps(data, indent=2))

        # Also save as "latest"
        latest_path = self.results_dir / f"{framework_name.lower()}_latest.json"
        latest_path.write_text(json.dumps(data, indent=2))

    def get_latest_results(self, framework_name: str) -> Optional[List[ControlResult]]:
        """Get the latest compliance check results for a framework."""
        latest_path = self.results_dir / f"{framework_name.lower()}_latest.json"

        if not latest_path.exists():
            return None

        data = json.loads(latest_path.read_text())
        return [ControlResult(**r) for r in data["results"]]
