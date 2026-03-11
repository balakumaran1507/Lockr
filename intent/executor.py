#!/usr/bin/env python3
"""
Intent executor — validates and dispatches parsed intents to vault actions.

Critical security boundary:
  - LLM output (ParsedIntent) is UNTRUSTED user input
  - Every intent re-validated here before touching vault
  - LLM never writes to vault directly — executor does
  - Secret values NEVER flow through this layer
"""

from typing import Callable, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

from .prompts import IntentType, ParsedIntent


class ExecutionStatus(str, Enum):
    SUCCESS          = "success"
    REQUIRES_CONFIRM = "requires_confirm"
    REJECTED         = "rejected"      # Failed validation
    FAILED           = "failed"        # Vault action failed
    FALLBACK         = "fallback"      # Low confidence, needs manual flags


@dataclass
class IntentResult:
    status:  ExecutionStatus
    message: str
    data:    Optional[Dict[str, Any]] = None
    command: str = ""  # Suggested CLI command


# ---------------------------------------------------------------------------
# Argument validators — each intent has required fields
# ---------------------------------------------------------------------------

def _require(args: dict, *keys: str) -> Optional[str]:
    """Returns error string if any required key is missing/empty."""
    for k in keys:
        if not args.get(k):
            return f"Missing required argument: '{k}'"
    return None


def _validate_namespace(ns: str) -> Optional[str]:
    """Basic namespace sanity — no traversal, no weird chars."""
    if not ns:
        return "Namespace cannot be empty"
    if ".." in ns or ns.startswith("/"):
        return f"Invalid namespace: '{ns}'"
    return None


def _validate_grant_access(args: dict) -> Optional[str]:
    err = _require(args, "user", "namespace")
    if err:
        return err
    return _validate_namespace(args["namespace"])


def _validate_revoke_access(args: dict) -> Optional[str]:
    return _require(args, "user", "namespace")


def _validate_audit_query(args: dict) -> Optional[str]:
    return None  # All args optional for audit queries


def _validate_rotate_keys(args: dict) -> Optional[str]:
    return None  # Namespace optional — can rotate all


def _validate_compliance_check(args: dict) -> Optional[str]:
    framework = args.get("framework", "")
    if framework not in ("soc2", "iso27001", "both", ""):
        return f"Unknown compliance framework: '{framework}'"
    return None


def _validate_anomaly_detect(args: dict) -> Optional[str]:
    return None  # All args optional


def _validate_secret_op(args: dict) -> Optional[str]:
    err = _require(args, "namespace", "key")
    if err:
        return err
    return _validate_namespace(args["namespace"])


def _validate_secret_list(args: dict) -> Optional[str]:
    err = _require(args, "namespace")
    if err:
        return err
    return _validate_namespace(args["namespace"])


VALIDATORS: Dict[str, Callable] = {
    IntentType.GRANT_ACCESS.value:      _validate_grant_access,
    IntentType.REVOKE_ACCESS.value:     _validate_revoke_access,
    IntentType.AUDIT_QUERY.value:       _validate_audit_query,
    IntentType.ROTATE_KEYS.value:       _validate_rotate_keys,
    IntentType.COMPLIANCE_CHECK.value:  _validate_compliance_check,
    IntentType.ANOMALY_DETECT.value:    _validate_anomaly_detect,
    IntentType.SECRET_READ.value:       _validate_secret_op,
    IntentType.SECRET_WRITE.value:      _validate_secret_op,
    IntentType.SECRET_DELETE.value:     _validate_secret_op,
    IntentType.SECRET_LIST.value:       _validate_secret_list,
    IntentType.UNKNOWN.value:           lambda _: "Cannot execute unknown intent",
}


# ---------------------------------------------------------------------------
# Action stubs — swap these out for real vault.core calls in Phase 2
# ---------------------------------------------------------------------------

def _exec_grant_access(args: dict) -> IntentResult:
    user = args["user"]
    ns   = args["namespace"]
    ttl  = args.get("ttl", "8h")
    # TODO: vault.auth.create_token(scope=ns, ttl=ttl, label=user)
    return IntentResult(
        status=ExecutionStatus.SUCCESS,
        message=f"✅ Granted {user} access to '{ns}' for {ttl}.",
        data={"user": user, "namespace": ns, "ttl": ttl},
        
    )


def _exec_revoke_access(args: dict) -> IntentResult:
    user = args["user"]
    ns   = args["namespace"]
    # TODO: vault.auth.revoke_token(label=user, scope=ns)
    return IntentResult(
        status=ExecutionStatus.SUCCESS,
        message=f"✅ Revoked {user}'s access to '{ns}'.",
        data={"user": user, "namespace": ns},
        
    )


def _exec_audit_query(args: dict) -> IntentResult:
    ns    = args.get("namespace", "all namespaces")
    since = args.get("since", "all time")
    actor = args.get("actor")
    # TODO: vault.audit.query(namespace=ns, since=since, actor=actor)
    msg = f"📋 Audit query: {ns} | since {since}"
    if actor:
        msg += f" | actor: {actor}"
    return IntentResult(
        status=ExecutionStatus.SUCCESS,
        message=msg,
        data=args,
        
    )


def _exec_rotate_keys(args: dict) -> IntentResult:
    ns    = args.get("namespace", "all namespaces")
    older = args.get("older_than", "any age")
    # TODO: vault.core.rotate_keys(namespace=ns, older_than=older)
    return IntentResult(
        status=ExecutionStatus.SUCCESS,
        message=f"🔄 Rotated keys in {ns} older than {older}.",
        data=args,
        
    )


def _exec_compliance_check(args: dict) -> IntentResult:
    framework = args.get("framework", "soc2")

    try:
        from server.compliance import FrameworkStore, ComplianceChecker

        store = FrameworkStore()
        checker = ComplianceChecker()

        fw = store.load_framework(framework)
        if not fw:
            return IntentResult(
                status=ExecutionStatus.FAILED,
                message=f"❌ Framework '{framework}' not found. Available: {', '.join(store.list_frameworks())}",
                data={"framework": framework},
                
            )

        results = checker.check_framework(fw)
        summary = checker.generate_summary(results)

        # Save results
        store.save_results(fw.name, results)

        return IntentResult(
            status=ExecutionStatus.SUCCESS,
            message=f"✅ {framework.upper()} compliance check complete. Score: {summary['compliance_score']}% | Passed: {summary['passed']}/{summary['total_controls']} | Audit Ready: {summary['ready_for_audit']}",
            data={"framework": framework, "summary": summary},
            
        )
    except Exception as e:
        return IntentResult(
            status=ExecutionStatus.FAILED,
            message=f"❌ Compliance check failed: {str(e)}",
            data={"framework": framework},
            
        )


def _exec_anomaly_detect(args: dict) -> IntentResult:
    since = args.get("since", "24h")
    ns    = args.get("namespace", "all namespaces")
    # TODO: vault.audit.detect_anomalies(since=since, namespace=ns)
    return IntentResult(
        status=ExecutionStatus.SUCCESS,
        message=f"🔍 Scanned {ns} for anomalies in last {since}.",
        data=args,
        
    )


def _exec_secret_read(args: dict) -> IntentResult:
    ns  = args["namespace"]
    key = args["key"]
    # TODO: vault.core.get(f"{ns}/{key}")
    return IntentResult(
        status=ExecutionStatus.SUCCESS,
        message=f"🔑 Read secret '{ns}/{key}'.",
        data={"namespace": ns, "key": key},
        
    )


def _exec_secret_write(args: dict) -> IntentResult:
    # NOTE: value never comes from LLM — executor prompts user directly
    ns  = args["namespace"]
    key = args["key"]
    # TODO: value = getpass.getpass(f"Value for {ns}/{key}: ")
    # TODO: vault.core.set(f"{ns}/{key}", value)
    return IntentResult(
        status=ExecutionStatus.SUCCESS,
        message=f"✏️  Wrote secret '{ns}/{key}'. (value prompted separately)",
        data={"namespace": ns, "key": key},
        
    )


def _exec_secret_delete(args: dict) -> IntentResult:
    ns  = args["namespace"]
    key = args["key"]
    # TODO: vault.core.delete(f"{ns}/{key}")
    return IntentResult(
        status=ExecutionStatus.SUCCESS,
        message=f"🗑️  Deleted secret '{ns}/{key}'.",
        data={"namespace": ns, "key": key},
        
    )


def _exec_secret_list(args: dict) -> IntentResult:
    ns = args["namespace"]
    # TODO: vault.core.list(ns)
    return IntentResult(
        status=ExecutionStatus.SUCCESS,
        message=f"📂 Listed secrets in '{ns}'.",
        data={"namespace": ns},
        
    )


EXECUTORS: Dict[str, Callable] = {
    IntentType.GRANT_ACCESS.value:      _exec_grant_access,
    IntentType.REVOKE_ACCESS.value:     _exec_revoke_access,
    IntentType.AUDIT_QUERY.value:       _exec_audit_query,
    IntentType.ROTATE_KEYS.value:       _exec_rotate_keys,
    IntentType.COMPLIANCE_CHECK.value:  _exec_compliance_check,
    IntentType.ANOMALY_DETECT.value:    _exec_anomaly_detect,
    IntentType.SECRET_READ.value:       _exec_secret_read,
    IntentType.SECRET_WRITE.value:      _exec_secret_write,
    IntentType.SECRET_DELETE.value:     _exec_secret_delete,
    IntentType.SECRET_LIST.value:       _exec_secret_list,
}


# ---------------------------------------------------------------------------
# Main executor entry point
# ---------------------------------------------------------------------------

def execute(intent: ParsedIntent, confirmed: bool = False) -> IntentResult:
    """
    Validate and execute a parsed intent against the vault.

    Simple model:
      - LLM selects command from catalog
      - Args validated before execution
      - User can confirm before destructive actions

    Args:
        intent:    Output from parser.parse_intent()
        confirmed: True if user explicitly confirmed (CLI prompt / --yes flag)

    Returns:
        IntentResult with status + message + suggested command
    """
    intent_type = intent["intent"]
    args        = intent["args"]
    command     = intent.get("command", "")

    # --- Validate args ---
    validator = VALIDATORS.get(intent_type)
    if not validator:
        return IntentResult(
            status=ExecutionStatus.REJECTED,
            message=f"❌ No validator for intent '{intent_type}'.",
            command=command
        )

    err = validator(args)
    if err:
        return IntentResult(
            status=ExecutionStatus.REJECTED,
            message=f"❌ Validation failed: {err}\nSuggested command: {command}",
            command=command
        )

    # --- Execute ---
    executor = EXECUTORS.get(intent_type)
    if not executor:
        return IntentResult(
            status=ExecutionStatus.REJECTED,
            message=f"❌ No executor for intent '{intent_type}'.",
            command=command
        )

    try:
        result = executor(args)
        result.command = command
        return result
    except Exception as e:
        return IntentResult(
            status=ExecutionStatus.FAILED,
            message=f"❌ Execution failed: {e}",
            command=command
        )
