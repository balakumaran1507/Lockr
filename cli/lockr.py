#!/usr/bin/env python3
"""
cli/lockr.py — Lockr CLI

Usage:
  lockr init
  lockr set myapp/db_password
  lockr get myapp/db_password
  lockr delete myapp/db_password
  lockr list myapp/
  lockr checkout prod
  lockr merge staging prod
  lockr token create --scope "myapp/*" --ttl 24h
  lockr token revoke tk_abc123
  lockr token list
  lockr ask "give john access to staging for 24 hours"
  lockr run --namespace myapp -- python app.py
  lockr compliance report --framework soc2
  lockr audit tail
  lockr audit verify
  lockr scan
  lockr guard install
  lockr guard uninstall
"""

import os
import re
import sys
import getpass
import subprocess
from pathlib import Path
from typing import Optional, List, Tuple

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

# Lazy-import server layer so CLI works even if FastAPI not installed
def _store():
    from server.store import VaultStore
    return VaultStore()

def _auth():
    from server.auth import AuthStore
    return AuthStore()

def _audit():
    from server.audit import AuditLog
    return AuditLog()

def _crypto():
    from server import generate_keypair, encode_master_key, pq_status
    return generate_keypair, encode_master_key, pq_status

console = Console()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_init():
    if not Path(".vault").exists():
        console.print("[red]✗[/red] Not a vault directory. Run [bold]lockr init[/bold] first.")
        sys.exit(1)


def _confirm_action(message: str) -> bool:
    return click.confirm(f"⚠️  {message}", default=False)


def _print_intent(intent: dict):
    console.print(Panel(
        f"[bold]Intent:[/bold]    {intent['intent']}\n"
        f"[bold]Command:[/bold]   [cyan]{intent.get('command', 'N/A')}[/cyan]\n"
        f"[bold]Summary:[/bold]   {intent['summary']}\n"
        f"[bold]Args:[/bold]      {intent['args']}",
        title="🧠 Command Selected",
        border_style="cyan",
    ))


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option("0.1.0", prog_name="lockr")
def cli():
    """Lockr — git-architecture secrets manager with PQ encryption."""
    pass


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--env", default="prod", show_default=True, help="Default environment name.")
def init(env: str):
    """Initialise a new vault in the current directory."""
    from server.store import VaultStore
    from server.auth import AuthStore
    from server.crypto import generate_keypair, encode_master_key, pq_status

    store = VaultStore()

    try:
        store.init(default_env=env)
    except FileExistsError:
        console.print("[yellow]⚠[/yellow]  .vault/ already exists.")
        sys.exit(1)

    # Reuse VAULT_MASTER_KEY if already set, otherwise generate a new keypair
    if os.environ.get("VAULT_MASTER_KEY"):
        master_key = os.environ["VAULT_MASTER_KEY"]
    else:
        pk, sk = generate_keypair()
        master_key = encode_master_key(pk, sk)

    # Create bootstrap admin token
    auth  = AuthStore()
    token = auth.create(scopes=["*"], label="admin-bootstrap")

    console.print(Panel(
        f"[bold green]✓ Vault initialised[/bold green] (env: [cyan]{env}[/cyan])\n\n"
        f"[bold]{pq_status()}[/bold]\n\n"
        f"[yellow]Add to your shell environment:[/yellow]\n"
        f"  export VAULT_MASTER_KEY={master_key}\n\n"
        f"[yellow]Admin token (save this — shown once):[/yellow]\n"
        f"  [bold cyan]{token}[/bold cyan]\n\n"
        f"[dim]Commit .vault/ to git (objects are encrypted).\n"
        f"Never commit VAULT_MASTER_KEY.[/dim]",
        title="🔐 Lockr",
        border_style="green",
    ))


# ---------------------------------------------------------------------------
# set
# ---------------------------------------------------------------------------

@cli.command("set")
@click.argument("path")
@click.argument("value", required=False)
@click.option("--env", default=None, help="Target environment (default: HEAD).")
def set_secret(path: str, value: Optional[str], env: Optional[str]):
    """Write a secret. Value prompted if not provided."""
    _require_init()

    if not value:
        value = getpass.getpass(f"Value for {path}: ")

    store = _store()
    hash_hex = store.set(path, value.encode(), env=env)

    active_env = env or store.current_env()
    console.print(
        f"[green]✓[/green] [bold]{active_env}/{path}[/bold] → [dim]{hash_hex[:12]}...[/dim]"
    )


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------

@cli.command("get")
@click.argument("path")
@click.option("--env", default=None, help="Source environment (default: HEAD).")
@click.option("--raw", is_flag=True, help="Print value only (pipeable).")
def get_secret(path: str, env: Optional[str], raw: bool):
    """Read a secret."""
    _require_init()

    store = _store()
    try:
        value = store.get(path, env=env)
    except KeyError:
        active_env = env or store.current_env()
        console.print(f"[red]✗[/red] Secret [bold]{active_env}/{path}[/bold] not found.")
        sys.exit(1)

    if raw:
        # Pipeable — no decoration
        click.echo(value.decode(), nl=False)
    else:
        active_env = env or store.current_env()
        console.print(
            f"[bold]{active_env}/{path}[/bold]\n{value.decode()}"
        )


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------

@cli.command("delete")
@click.argument("path")
@click.option("--env", default=None)
@click.option("--yes", is_flag=True, help="Skip confirmation.")
def delete_secret(path: str, env: Optional[str], yes: bool):
    """Delete a secret ref (object preserved — git-style)."""
    _require_init()

    store = _store()
    active_env = env or store.current_env()

    if not yes:
        if not _confirm_action(f"Delete {active_env}/{path}?"):
            console.print("[dim]Aborted.[/dim]")
            return

    deleted = store.delete(path, env=env)
    if deleted:
        console.print(f"[green]✓[/green] Deleted [bold]{active_env}/{path}[/bold]")
    else:
        console.print(f"[red]✗[/red] Secret [bold]{active_env}/{path}[/bold] not found.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

@cli.command("list")
@click.argument("namespace")
@click.option("--env", default=None)
def list_secrets(namespace: str, env: Optional[str]):
    """List all keys in a namespace."""
    _require_init()

    store = _store()
    keys  = store.list(namespace.rstrip("/"), env=env)
    active_env = env or store.current_env()

    if not keys:
        console.print(f"[dim]No secrets in {active_env}/{namespace}[/dim]")
        return

    table = Table(title=f"{active_env}/{namespace.rstrip('/')}/", show_header=False)
    table.add_column("key", style="cyan")
    for k in sorted(keys):
        table.add_row(k)
    console.print(table)


# ---------------------------------------------------------------------------
# checkout / merge
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("env")
def checkout(env: str):
    """Switch active environment."""
    _require_init()
    _store().checkout(env)
    console.print(f"[green]✓[/green] Switched to [bold]{env}[/bold]")


@cli.command()
@click.argument("src")
@click.argument("dst")
@click.option("--yes", is_flag=True)
def merge(src: str, dst: str, yes: bool):
    """Promote all secrets from SRC → DST environment."""
    _require_init()

    if not yes:
        if not _confirm_action(f"Merge all secrets from '{src}' into '{dst}'?"):
            console.print("[dim]Aborted.[/dim]")
            return

    count = _store().merge(src, dst)
    console.print(f"[green]✓[/green] Merged [bold]{count}[/bold] secrets from {src} → {dst}")


# ---------------------------------------------------------------------------
# token
# ---------------------------------------------------------------------------

@cli.group()
def token():
    """Manage access tokens."""
    pass


@token.command("create")
@click.option("--scope", "scopes", multiple=True, required=True, help="Namespace glob e.g. 'myapp/*'")
@click.option("--ttl", default=None, help="e.g. 24h, 7d, 30m")
@click.option("--label", default=None, help="Human-readable label.")
def token_create(scopes, ttl, label):
    """Create a new scoped token."""
    _require_init()

    raw = _auth().create(scopes=list(scopes), ttl=ttl, label=label)
    console.print(Panel(
        f"[bold cyan]{raw}[/bold cyan]\n\n"
        f"Scopes: {', '.join(scopes)}\n"
        f"TTL:    {ttl or 'never expires'}\n\n"
        f"[dim]Shown once. Store securely.[/dim]",
        title="🔑 Token Created",
        border_style="cyan",
    ))


@token.command("revoke")
@click.argument("token_id")
@click.option("--yes", is_flag=True)
def token_revoke(token_id, yes):
    """Revoke a token."""
    _require_init()

    if not yes:
        if not _confirm_action(f"Revoke token {token_id}?"):
            console.print("[dim]Aborted.[/dim]")
            return

    ok = _auth().revoke(token_id)
    if ok:
        console.print(f"[green]✓[/green] Token revoked.")
    else:
        console.print(f"[red]✗[/red] Token not found.")
        sys.exit(1)


@token.command("list")
def token_list():
    """List all tokens."""
    _require_init()

    tokens = _auth().list()
    if not tokens:
        console.print("[dim]No tokens.[/dim]")
        return

    table = Table(title="Tokens", show_lines=True)
    table.add_column("Label",   style="cyan")
    table.add_column("Scopes",  style="white")
    table.add_column("Expires", style="yellow")
    table.add_column("Status",  style="green")

    for t in tokens:
        status = "[green]active[/green]" if t["active"] else "[red]expired/revoked[/red]"
        table.add_row(
            t["label"],
            ", ".join(t["scopes"]),
            t["expires"] or "never",
            status,
        )
    console.print(table)


# ---------------------------------------------------------------------------
# ask — LLM intent
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("query")
@click.option("--yes", is_flag=True, help="Auto-confirm high-risk actions.")
def ask(query: str, yes: bool):
    """
    Natural language vault control.

    Examples:
      lockr ask "give john access to staging for 24 hours"
      lockr ask "who touched production last week"
      lockr ask "rotate all keys older than 90 days"
      lockr ask "am I SOC-2 ready"
    """
    _require_init()

    from intent.parser import parse_intent_sync
    from intent.executor import execute, ExecutionStatus

    with console.status("[bold]Thinking...[/bold]"):
        intent = parse_intent_sync(query)

    _print_intent(intent)

    result = execute(intent, confirmed=yes)

    status_icon = {
        "success":          "[green]✓[/green]",
        "requires_confirm": "[yellow]⚠[/yellow]",
        "rejected":         "[red]✗[/red]",
        "failed":           "[red]✗[/red]",
        "fallback":         "[yellow]?[/yellow]",
    }.get(result.status.value, "•")

    console.print(f"\n{status_icon} {result.message}")

    if result.command:
        console.print(f"[dim]Run manually: {result.command}[/dim]")

    if result.status in ("rejected", "failed"):
        sys.exit(1)


# ---------------------------------------------------------------------------
# run — inject secrets as env vars
# ---------------------------------------------------------------------------

@cli.command(context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.option("--namespace", required=True, help="Namespace to inject e.g. 'myapp'")
@click.option("--env", default=None, help="Environment (default: HEAD).")
@click.argument("command", nargs=-1, type=click.UNPROCESSED)
def run(namespace: str, env: Optional[str], command):
    """
    Run a command with secrets injected as environment variables.

    Secret names are uppercased and prefixed with the namespace.

      lockr run --namespace myapp -- python app.py

    myapp/db_password → MYAPP_DB_PASSWORD=<value>
    """
    _require_init()

    if not command:
        console.print("[red]✗[/red] No command specified. Usage: lockr run --namespace X -- cmd")
        sys.exit(1)

    store  = _store()
    keys   = store.list(namespace, env=env)
    active = env or store.current_env()

    injected = {}
    errors   = []

    for key in keys:
        try:
            value = store.get(f"{namespace}/{key}", env=env)
            # Convert myapp/db_password → MYAPP_DB_PASSWORD
            var_name = f"{namespace}_{key}".upper().replace("/", "_").replace("-", "_")
            injected[var_name] = value.decode()
        except Exception as e:
            errors.append(f"{namespace}/{key}: {e}")

    if errors:
        for err in errors:
            console.print(f"[yellow]⚠[/yellow] Could not load: {err}")

    env_vars = {**os.environ, **injected}

    console.print(
        f"[dim]Injecting {len(injected)} secrets from {active}/{namespace} → {list(injected.keys())}[/dim]"
    )

    result = subprocess.run(list(command), env=env_vars)
    sys.exit(result.returncode)


# ---------------------------------------------------------------------------
# compliance
# ---------------------------------------------------------------------------

@cli.group()
def compliance():
    """Compliance framework management and reporting."""
    pass


@compliance.command("check")
@click.option("--framework", default="soc2", help="Framework to check (soc2, iso27001, or custom name)")
@click.option("--save", is_flag=True, help="Save results for audit trail")
def compliance_check(framework: str, save: bool):
    """Run automated compliance checks against a framework."""
    _require_init()

    from server.compliance import FrameworkStore, ComplianceChecker

    store = FrameworkStore()
    checker = ComplianceChecker()

    # Load framework
    fw = store.load_framework(framework)
    if not fw:
        console.print(f"[red]✗[/red] Framework '{framework}' not found.")
        console.print(f"Available: {', '.join(store.list_frameworks())}")
        sys.exit(1)

    console.print(f"\n[bold]Running compliance checks for {fw.name} {fw.version}...[/bold]\n")

    # Run checks
    results = checker.check_framework(fw)
    summary = checker.generate_summary(results)

    # Save if requested
    if save:
        store.save_results(fw.name, results)
        console.print(f"[dim]Results saved to .vault/compliance_results/[/dim]\n")

    # Display results
    table = Table(title=f"{fw.name} Compliance Report", show_lines=True)
    table.add_column("Control", style="cyan", no_wrap=True)
    table.add_column("Status", style="white", no_wrap=True)
    table.add_column("Notes", style="white")

    for result in results:
        status_color = {
            "pass": "green",
            "fail": "red",
            "partial": "yellow",
            "manual": "blue",
            "n/a": "dim"
        }.get(result.status, "white")

        status_icon = {
            "pass": "✓",
            "fail": "✗",
            "partial": "⚠",
            "manual": "👤",
            "n/a": "—"
        }.get(result.status, "?")

        table.add_row(
            result.control_id,
            f"[{status_color}]{status_icon} {result.status.upper()}[/{status_color}]",
            result.notes
        )

    console.print(table)

    # Summary
    score_color = "green" if summary["compliance_score"] >= 80 else "yellow" if summary["compliance_score"] >= 60 else "red"

    console.print(f"\n[bold]Summary[/bold]")
    console.print(f"  Compliance Score: [{score_color}]{summary['compliance_score']}%[/{score_color}]")
    console.print(f"  Passed: [green]{summary['passed']}[/green] | Failed: [red]{summary['failed']}[/red] | Partial: [yellow]{summary['partial']}[/yellow] | Manual: [blue]{summary['manual']}[/blue]")
    console.print(f"  Audit Ready: [{'green' if summary['ready_for_audit'] else 'red'}]{summary['ready_for_audit']}[/{'green' if summary['ready_for_audit'] else 'red'}]")


@compliance.command("report")
@click.option("--framework", default="soc2", help="Framework name")
@click.option("--output", default=None, help="Output file path (default: print to terminal).")
@click.option("--format", default="text", type=click.Choice(["text", "json"]), help="Report format")
def compliance_report(framework: str, output: Optional[str], format: str):
    """Generate detailed compliance report with evidence."""
    _require_init()

    from server.compliance import FrameworkStore, ComplianceChecker
    import json

    store = FrameworkStore()
    checker = ComplianceChecker()

    fw = store.load_framework(framework)
    if not fw:
        console.print(f"[red]✗[/red] Framework '{framework}' not found.")
        sys.exit(1)

    results = checker.check_framework(fw)
    summary = checker.generate_summary(results)

    if format == "json":
        report_data = {
            "framework": fw.name,
            "version": fw.version,
            "generated_at": __import__('datetime').datetime.utcnow().isoformat() + "Z",
            "summary": summary,
            "controls": [
                {
                    "id": r.control_id,
                    "status": r.status,
                    "automated": r.automated,
                    "notes": r.notes,
                    "evidence": r.evidence,
                    "checked_at": r.checked_at
                }
                for r in results
            ]
        }
        report = json.dumps(report_data, indent=2)
    else:
        lines = [
            f"LOCKR COMPLIANCE REPORT",
            f"Framework: {fw.name} {fw.version}",
            f"Generated: {__import__('datetime').datetime.utcnow().isoformat()}Z",
            f"Compliance Score: {summary['compliance_score']}%",
            f"Audit Ready: {summary['ready_for_audit']}",
            "",
            "CONTROL RESULTS",
            "═" * 80,
        ]

        for result in results:
            status_icon = {"pass": "✓", "fail": "✗", "partial": "⚠", "manual": "👤"}.get(result.status, "?")
            lines.append(f"\n{result.control_id} — {status_icon} {result.status.upper()}")
            lines.append(f"  {result.notes}")
            if result.evidence:
                lines.append(f"  Evidence:")
                for ev in result.evidence:
                    lines.append(f"    • {ev}")

        lines.append("\n" + "═" * 80)
        lines.append(f"SUMMARY: {summary['passed']} passed | {summary['failed']} failed | {summary['manual']} manual")

        report = "\n".join(lines)

    if output:
        Path(output).write_text(report)
        console.print(f"[green]✓[/green] Report written to [bold]{output}[/bold]")
    else:
        console.print(report)


@compliance.command("upload")
@click.argument("name")
@click.argument("file", type=click.Path(exists=True))
def compliance_upload(name: str, file: str):
    """Upload a custom compliance framework from JSON file."""
    _require_init()

    from server.compliance import FrameworkStore
    import json

    with open(file, 'r') as f:
        data = json.load(f)

    if "controls" not in data:
        console.print("[red]✗[/red] Invalid framework file. Must have 'controls' array.")
        sys.exit(1)

    store = FrameworkStore()
    framework = store.upload_custom_framework(name, data["controls"])

    console.print(f"[green]✓[/green] Uploaded framework '{framework.name}' with {len(framework.controls)} controls")
    console.print(f"[dim]Run 'lockr compliance check --framework {name}' to test it[/dim]")


@compliance.command("list")
def compliance_list():
    """List all available compliance frameworks."""
    _require_init()

    from server.compliance import FrameworkStore

    store = FrameworkStore()
    frameworks = store.list_frameworks()

    if not frameworks:
        console.print("[dim]No frameworks available.[/dim]")
        return

    table = Table(title="Available Compliance Frameworks")
    table.add_column("Framework", style="cyan")

    for fw_name in frameworks:
        fw = store.load_framework(fw_name)
        table.add_row(f"{fw_name} ({len(fw.controls) if fw else '?'} controls)")

    console.print(table)


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

@cli.group()
def audit():
    """Audit log commands."""
    pass


@audit.command("tail")
@click.option("--n", default=20, show_default=True)
@click.option("--namespace", default=None)
def audit_tail(n: int, namespace: Optional[str]):
    """Tail the audit log."""
    _require_init()

    entries = _audit().query(namespace=namespace, limit=n)
    if not entries:
        console.print("[dim]No audit entries.[/dim]")
        return

    table = Table(title="Audit Log", show_lines=True)
    table.add_column("Time",   style="dim",    no_wrap=True)
    table.add_column("Actor",  style="cyan",   no_wrap=True)
    table.add_column("Action", style="yellow", no_wrap=True)
    table.add_column("Target", style="white")
    table.add_column("Result", style="green",  no_wrap=True)

    for e in entries:
        result_style = "green" if e["result"] == "success" else "red"
        table.add_row(
            e["timestamp"][11:19],
            e["actor"][:14],
            e["action"],
            e["target"],
            f"[{result_style}]{e['result']}[/{result_style}]",
        )
    console.print(table)


@audit.command("verify")
def audit_verify():
    """Verify audit log chain integrity."""
    _require_init()

    with console.status("Verifying chain..."):
        ok = _audit().verify_chain()

    if ok:
        console.print("[green]✓[/green] Audit chain intact.")
    else:
        console.print("[red]✗[/red] Audit chain TAMPERED — evidence invalid.")
        sys.exit(1)


@audit.command("anomalies")
@click.option("--since", default=None, help="ISO-8601 timestamp or duration e.g. '24h'")
@click.option("--namespace", default=None)
def audit_anomalies(since: Optional[str], namespace: Optional[str]):
    """Scan for suspicious access patterns."""
    _require_init()

    anomalies = _audit().detect_anomalies(since_iso=since, namespace=namespace)

    if not anomalies:
        console.print("[green]✓[/green] No anomalies detected.")
        return

    console.print(f"[red]⚠[/red] {len(anomalies)} anomalies detected:\n")
    for a in anomalies:
        console.print(
            f"  [red]{a.get('anomaly')}[/red] — "
            f"actor: {a.get('actor', '?')} | "
            f"target: {a.get('target', '?')} | "
            f"time: {a.get('timestamp', '?')}"
        )


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@cli.command()
def status():
    """Show vault status."""
    _require_init()

    from server.crypto import pq_status as _pq_status

    store    = _store()
    log      = _audit()
    chain_ok = log.verify_chain()
    envs     = store.list_envs()
    current  = store.current_env()

    console.print(Panel(
        f"[bold]Environment:[/bold] [cyan]{current}[/cyan]  "
        f"(all: {', '.join(envs)})\n"
        f"[bold]Crypto:[/bold]      {_pq_status()}\n"
        f"[bold]Audit chain:[/bold] {'[green]intact[/green]' if chain_ok else '[red]TAMPERED[/red]'}",
        title="🔐 Lockr Status",
    ))


# ---------------------------------------------------------------------------
# rotate — key rotation
# ---------------------------------------------------------------------------

@cli.group()
def rotate():
    """Secret rotation and versioning."""
    pass


@rotate.command("secret")
@click.argument("path")
@click.option("--generate", is_flag=True, help="Auto-generate new random value")
@click.option("--length", default=32, help="Length of generated value")
@click.option("--reason", default="manual", help="Rotation reason (manual/scheduled/emergency)")
def rotate_secret(path: str, generate: bool, length: int, reason: str):
    """Rotate a secret to a new version."""
    _require_init()

    from server.rotation import RotationManager
    import getpass

    rotation_mgr = RotationManager()

    if generate:
        # Auto-generate new value
        new_value = rotation_mgr.generate_random_value(length=length)
        console.print(f"[dim]Generated new random value ({length} characters)[/dim]")
    else:
        # Prompt for new value
        new_value = getpass.getpass(f"New value for {path}: ").encode()

    # Perform rotation
    new_version = rotation_mgr.rotate_secret(
        secret_path=path,
        new_value=new_value,
        created_by="cli-user",  # TODO: get from auth context
        reason=reason
    )

    console.print(f"[green]✓[/green] Rotated [bold]{path}[/bold] to version {new_version.version}")
    console.print(f"[dim]Reason: {reason} | Created: {new_version.created_at}[/dim]")

    if generate:
        console.print(f"\n[yellow]⚠ New value (save this):[/yellow]\n{new_value.decode()}")


@rotate.command("policy")
@click.argument("namespace")
@click.option("--max-age", default=90, help="Max age in days before rotation required")
@click.option("--keep-versions", default=5, help="Number of old versions to keep")
@click.option("--auto/--no-auto", default=False, help="Enable automatic rotation")
@click.option("--notify-days", default=7, help="Days before rotation to notify")
def rotate_policy(namespace: str, max_age: int, keep_versions: int, auto: bool, notify_days: int):
    """Set rotation policy for a namespace."""
    _require_init()

    from server.rotation import RotationManager, RotationPolicy

    policy = RotationPolicy(
        enabled=True,
        max_age_days=max_age,
        keep_versions=keep_versions,
        auto_rotate=auto,
        notify_before_days=notify_days
    )

    rotation_mgr = RotationManager()
    rotation_mgr.set_policy(namespace, policy)

    console.print(f"[green]✓[/green] Set rotation policy for [bold]{namespace}[/bold]")
    console.print(f"  Max age: {max_age} days")
    console.print(f"  Keep versions: {keep_versions}")
    console.print(f"  Auto-rotate: {'enabled' if auto else 'disabled'}")
    console.print(f"  Notify before: {notify_days} days")


@rotate.command("status")
@click.argument("namespace")
def rotate_status(namespace: str):
    """Check rotation status for a namespace."""
    _require_init()

    from server.rotation import RotationManager

    rotation_mgr = RotationManager()
    status = rotation_mgr.get_rotation_status(namespace)

    if not status["policy"]:
        console.print(f"[yellow]⚠[/yellow] No rotation policy set for [bold]{namespace}[/bold]")
        console.print(f"[dim]Set one with: lockr rotate policy {namespace}[/dim]")
        return

    console.print(f"\n[bold]Rotation Status: {namespace}[/bold]\n")
    console.print(f"  Total secrets: {status['total_secrets']}")
    console.print(f"  Need rotation: {status['needs_rotation']}")

    if status['compliance'] is not None:
        compliance_status = "[green]✓ COMPLIANT[/green]" if status['compliance'] else "[red]✗ NON-COMPLIANT[/red]"
        console.print(f"  Compliance: {compliance_status}")

    if status['rotation_candidates']:
        console.print(f"\n[yellow]Secrets needing rotation:[/yellow]")
        for secret in status['rotation_candidates']:
            console.print(f"  • {secret}")


@rotate.command("history")
@click.argument("path")
def rotate_history(path: str):
    """Show version history for a secret."""
    _require_init()

    from server.rotation import RotationManager

    rotation_mgr = RotationManager()
    history = rotation_mgr.get_secret_history(path)

    if history['total_versions'] == 0:
        console.print(f"[yellow]⚠[/yellow] No version history for [bold]{path}[/bold]")
        console.print(f"[dim]Secret may not exist or versioning not enabled[/dim]")
        return

    console.print(f"\n[bold]Version History: {path}[/bold]\n")
    console.print(f"  Total versions: {history['total_versions']}")
    console.print(f"  Active version: v{history['active_version']}")
    console.print(f"  Oldest: {history['oldest']}")
    console.print(f"  Newest: {history['newest']}\n")

    table = Table(title="Versions", show_lines=True)
    table.add_column("Version", style="cyan", no_wrap=True)
    table.add_column("Created", style="white")
    table.add_column("By", style="yellow")
    table.add_column("Reason", style="white")
    table.add_column("Status", style="green")

    for v in history['versions']:
        status = "[green]● ACTIVE[/green]" if v['active'] else "[dim]○ inactive[/dim]"
        table.add_row(
            f"v{v['version']}",
            v['created_at'][:19],
            v['created_by'][:20],
            v['rotation_reason'],
            status
        )

    console.print(table)


@rotate.command("rollback")
@click.argument("path")
@click.argument("version", type=int)
@click.option("--yes", is_flag=True, help="Skip confirmation")
def rotate_rollback(path: str, version: int, yes: bool):
    """Rollback a secret to a previous version."""
    _require_init()

    from server.rotation import RotationManager

    if not yes:
        if not _confirm_action(f"Rollback {path} to version {version}?"):
            console.print("[dim]Aborted.[/dim]")
            return

    rotation_mgr = RotationManager()
    success = rotation_mgr.rollback_to_version(path, version)

    if success:
        console.print(f"[green]✓[/green] Rolled back [bold]{path}[/bold] to version {version}")
        console.print(f"[dim]The old value is now active[/dim]")
    else:
        console.print(f"[red]✗[/red] Version {version} not found for {path}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# scan / guard  — detect plaintext secrets before they hit git
# ---------------------------------------------------------------------------

# File names/patterns that are likely to hold raw credentials
_SENSITIVE_FILENAME_PATTERNS = [
    r"config\.env$",
    r"\.env$",
    r"\.env\.",
    r"secrets?\.",
    r"credentials?\.",
    r"api[_-]?keys?\.",
    r"private[_-]?key",
    r"\.pem$",
    r"\.key$",
    r"\.p12$",
    r"\.pfx$",
    r"id_rsa",
    r"id_ed25519",
    r"id_ecdsa",
    r"auth\.json$",
    r"token\.json$",
    r"service[_-]?account",
]

# Content patterns that look like hardcoded credentials
_SECRET_CONTENT_PATTERNS = [
    (r"[A-Za-z_]*API[_-]?KEY\s*=\s*['\"]?[A-Za-z0-9/+_\-]{16,}", "API key assignment"),
    (r"[A-Za-z_]*SECRET\s*=\s*['\"]?[A-Za-z0-9/+_\-]{16,}", "SECRET assignment"),
    (r"[A-Za-z_]*TOKEN\s*=\s*['\"]?[A-Za-z0-9/+_\-]{16,}", "TOKEN assignment"),
    (r"[A-Za-z_]*PASSWORD\s*=\s*['\"]?[A-Za-z0-9/+_\-]{8,}", "PASSWORD assignment"),
    (r"[A-Za-z_]*MASTER[_-]?KEY\s*=\s*['\"]?[A-Za-z0-9/+_\-]{16,}", "MASTER_KEY assignment"),
    (r"[A-Za-z_]*PRIVATE[_-]?KEY\s*=\s*['\"]?[A-Za-z0-9/+_\-]{16,}", "PRIVATE_KEY assignment"),
    (r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "PEM private key"),
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI API key"),
    (r"AIza[A-Za-z0-9_\-]{35}", "Google API key"),
    (r"AKIA[A-Za-z0-9]{16}", "AWS access key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub personal token"),
    (r"xox[baprs]-[A-Za-z0-9\-]+", "Slack token"),
]

# Directories to skip entirely
_SKIP_DIRS = {".git", ".vault", "__pycache__", "node_modules", ".venv", "venv", ".tox"}

# Binary-ish extensions to skip content scanning
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".zip", ".tar", ".gz", ".bz2", ".xz",
    ".exe", ".so", ".dylib", ".dll", ".pyc",
    ".pdf", ".bin",
}


def _scan_directory(root: Path) -> Tuple[List[dict], List[dict]]:
    """
    Walk *root* and return (filename_hits, content_hits).

    filename_hits: [{"file": str, "pattern": str}]
    content_hits:  [{"file": str, "line": int, "kind": str, "snippet": str}]
    """
    filename_hits: List[dict] = []
    content_hits: List[dict] = []

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip dirs in-place so os.walk doesn't descend into them
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

        for fname in filenames:
            rel = Path(dirpath) / fname
            rel_str = str(rel.relative_to(root))

            # --- filename check ---
            for pat in _SENSITIVE_FILENAME_PATTERNS:
                if re.search(pat, fname, re.IGNORECASE):
                    filename_hits.append({"file": rel_str, "pattern": pat})
                    break  # one hit per file is enough

            # --- content check ---
            if rel.suffix.lower() in _SKIP_EXTENSIONS:
                continue
            try:
                text = rel.read_text(errors="replace")
            except OSError:
                continue

            for lineno, line in enumerate(text.splitlines(), start=1):
                for pat, kind in _SECRET_CONTENT_PATTERNS:
                    m = re.search(pat, line)
                    if m:
                        snippet = line.strip()[:80]
                        content_hits.append({
                            "file": rel_str,
                            "line": lineno,
                            "kind": kind,
                            "snippet": snippet,
                        })
                        break  # one hit per line

    return filename_hits, content_hits


@cli.command("scan")
@click.option("--path", "scan_path", default=".", show_default=True,
              help="Directory to scan (default: current directory).")
@click.option("--exit-code", is_flag=True,
              help="Exit with code 1 if any issues are found (useful in CI).")
def scan(scan_path: str, exit_code: bool):
    """Scan for plaintext API keys and sensitive files before committing to git."""
    root = Path(scan_path).resolve()
    if not root.is_dir():
        console.print(f"[red]✗[/red] Not a directory: {scan_path}")
        sys.exit(1)

    console.print(f"[dim]Scanning {root} …[/dim]")
    fn_hits, ct_hits = _scan_directory(root)

    if not fn_hits and not ct_hits:
        console.print("[green]✓[/green] No exposed secrets or sensitive files detected.")
        return

    # ---- filename hits ----
    if fn_hits:
        table = Table(title="⚠  Sensitive files detected", show_lines=True,
                      border_style="yellow")
        table.add_column("File", style="bold yellow")
        table.add_column("Matched pattern", style="dim")
        for h in fn_hits:
            table.add_row(h["file"], h["pattern"])
        console.print(table)

    # ---- content hits ----
    if ct_hits:
        table = Table(title="🔑  Possible hardcoded secrets", show_lines=True,
                      border_style="red")
        table.add_column("File", style="bold red")
        table.add_column("Line", style="cyan", no_wrap=True)
        table.add_column("Type", style="yellow")
        table.add_column("Snippet", style="dim")
        for h in ct_hits:
            table.add_row(h["file"], str(h["line"]), h["kind"], h["snippet"])
        console.print(table)

    console.print()
    console.print("[bold yellow]Recommendations:[/bold yellow]")
    console.print("  • Store secrets with [bold]lockr set <path>[/bold] instead of plain files.")
    console.print("  • Add sensitive filenames to [bold].gitignore[/bold].")
    console.print("  • Rotate any keys that may already be in git history.")

    if exit_code:
        sys.exit(1)


# ---- guard group ----

@cli.group("guard")
def guard():
    """Install / remove a git pre-commit hook that runs lockr scan."""
    pass


_HOOK_MARKER = "# lockr-guard"


def _hook_script(lockr_bin: str) -> str:
    return f"""\
{_HOOK_MARKER}
# Auto-installed by lockr guard install — DO NOT EDIT THIS BLOCK
if [ "${{LOCKR_SKIP}}" = "1" ]; then
    echo "[lockr guard] LOCKR_SKIP=1 — skipping secret scan."
else
    "{lockr_bin}" scan --exit-code || {{
        echo ""
        echo "Commit blocked by lockr guard. Use 'LOCKR_SKIP=1 git commit' to override."
        exit 1
    }}
fi
# end lockr-guard
"""


def _find_git_root(start: Path) -> Optional[Path]:
    current = start.resolve()
    for parent in [current, *current.parents]:
        if (parent / ".git").exists():
            return parent
    return None


@guard.command("install")
def guard_install():
    """Install lockr scan as a git pre-commit hook in this repository."""
    git_root = _find_git_root(Path("."))
    if git_root is None:
        console.print("[red]✗[/red] Not inside a git repository.")
        sys.exit(1)

    lockr_bin = sys.executable.replace("python", "lockr")
    # Prefer the actual lockr entry-point next to the current Python binary
    bin_dir = Path(sys.executable).parent
    candidate = bin_dir / "lockr"
    if candidate.exists():
        lockr_bin = str(candidate)
    else:
        import shutil
        lockr_bin = shutil.which("lockr") or "lockr"

    hook_path = git_root / ".git" / "hooks" / "pre-commit"
    script = _hook_script(lockr_bin)

    if hook_path.exists():
        existing = hook_path.read_text()
        if _HOOK_MARKER in existing:
            console.print("[yellow]⚠[/yellow]  lockr guard is already installed.")
            return
        with hook_path.open("a") as fh:
            fh.write("\n" + script)
        console.print(f"[green]✓[/green] Appended lockr guard to existing hook: {hook_path}")
    else:
        hook_path.write_text("#!/bin/bash\n" + script)
        hook_path.chmod(0o755)
        console.print(f"[green]✓[/green] Created pre-commit hook: {hook_path}")

    console.print("[dim]Set LOCKR_SKIP=1 to bypass the scan for a single commit.[/dim]")


@guard.command("uninstall")
def guard_uninstall():
    """Remove the lockr scan block from the pre-commit hook."""
    git_root = _find_git_root(Path("."))
    if git_root is None:
        console.print("[red]✗[/red] Not inside a git repository.")
        sys.exit(1)

    hook_path = git_root / ".git" / "hooks" / "pre-commit"
    if not hook_path.exists():
        console.print("[dim]No pre-commit hook found — nothing to do.[/dim]")
        return

    existing = hook_path.read_text()
    if _HOOK_MARKER not in existing:
        console.print("[dim]lockr guard is not installed in this hook — nothing to do.[/dim]")
        return

    # Strip everything between _HOOK_MARKER lines
    cleaned = re.sub(
        r"\n?# lockr-guard.*?# end lockr-guard\n?",
        "",
        existing,
        flags=re.DOTALL,
    ).strip()

    if cleaned in ("", "#!/bin/bash"):
        hook_path.unlink()
        console.print(f"[green]✓[/green] Removed empty hook file: {hook_path}")
    else:
        hook_path.write_text(cleaned + "\n")
        console.print(f"[green]✓[/green] Removed lockr guard block from: {hook_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
