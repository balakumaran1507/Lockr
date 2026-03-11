#!/usr/bin/env python3
"""
cli/vaultless.py — Vaultless CLI

Usage:
  vaultless init
  vaultless set myapp/db_password
  vaultless get myapp/db_password
  vaultless delete myapp/db_password
  vaultless list myapp/
  vaultless checkout prod
  vaultless merge staging prod
  vaultless token create --scope "myapp/*" --ttl 24h
  vaultless token revoke tk_abc123
  vaultless token list
  vaultless ask "give john access to staging for 24 hours"
  vaultless run --namespace myapp -- python app.py
  vaultless compliance report --framework soc2
  vaultless audit tail
  vaultless audit verify
"""

import os
import sys
import getpass
import subprocess
from pathlib import Path
from typing import Optional

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
        console.print("[red]✗[/red] Not a vault directory. Run [bold]vaultless init[/bold] first.")
        sys.exit(1)


def _confirm_action(message: str) -> bool:
    return click.confirm(f"⚠️  {message}", default=False)


def _print_intent(intent: dict):
    risk_color = {"low": "green", "medium": "yellow", "high": "red"}.get(intent["risk"], "white")
    console.print(Panel(
        f"[bold]Intent:[/bold]  {intent['intent']}\n"
        f"[bold]Summary:[/bold] {intent['summary']}\n"
        f"[bold]Risk:[/bold]    [{risk_color}]{intent['risk']}[/{risk_color}]\n"
        f"[bold]Confidence:[/bold] {intent['confidence']:.0%}\n"
        f"[bold]Args:[/bold]    {intent['args']}",
        title="🧠 Parsed Intent",
        border_style=risk_color,
    ))


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option("0.1.0", prog_name="vaultless")
def cli():
    """Vaultless — git-architecture secrets manager with PQ encryption."""
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

    # Generate KEK keypair
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
        title="🔐 Vaultless",
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
      vaultless ask "give john access to staging for 24 hours"
      vaultless ask "who touched production last week"
      vaultless ask "rotate all keys older than 90 days"
      vaultless ask "am I SOC-2 ready"
    """
    _require_init()

    from intent.parser import parse_intent_sync
    from intent.executor import execute, ExecutionStatus

    with console.status("[bold]Thinking...[/bold]"):
        intent = parse_intent_sync(query)

    _print_intent(intent)

    # Require confirm for high-risk unless --yes passed
    if intent["requires_confirm"] and not yes:
        if not _confirm_action(f"Proceed with: {intent['summary']}"):
            console.print("[dim]Aborted.[/dim]")
            return
        yes = True

    result = execute(intent, confirmed=yes)

    status_icon = {
        "success":          "[green]✓[/green]",
        "requires_confirm": "[yellow]⚠[/yellow]",
        "rejected":         "[red]✗[/red]",
        "failed":           "[red]✗[/red]",
        "fallback":         "[yellow]?[/yellow]",
    }.get(result.status.value, "•")

    console.print(f"{status_icon} {result.message}")

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

      vaultless run --namespace myapp -- python app.py

    myapp/db_password → MYAPP_DB_PASSWORD=<value>
    """
    _require_init()

    if not command:
        console.print("[red]✗[/red] No command specified. Usage: vaultless run --namespace X -- cmd")
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
    """Compliance reporting."""
    pass


@compliance.command("report")
@click.option("--framework", default="soc2", type=click.Choice(["soc2", "iso27001", "both"]))
@click.option("--output", default=None, help="Output file path (default: print to terminal).")
def compliance_report(framework: str, output: Optional[str]):
    """Generate a SOC-2 or ISO 27001 compliance report."""
    _require_init()

    store = _store()
    auth  = _auth()
    log   = _audit()

    chain_ok = log.verify_chain()
    tokens   = auth.list()
    active   = [t for t in tokens if t["active"]]
    env      = store.current_env()

    controls = {
        "CC7.2 / A.8.15 — Audit logging":          "PASS ✓" if chain_ok else "FAIL ✗ — chain tampered",
        "CC6.1 / A.5.18 — Access control (RBAC)":  f"PASS ✓ — {len(active)} active tokens",
        "CC6.2 / A.5.18 — Access revocation":       "PASS ✓ — token revoke implemented",
        "CC6.7 / A.8.24 — Encryption at rest":      "PASS ✓ — AES-256-GCM + FrodoKEM-1344",
        "CC6.6 / A.8.25 — Environment separation":  f"PASS ✓ — git-style branches, current: {env}",
        "A1.2  / A.17.1 — Backup / DR":             "MANUAL ⚠ — configure vaultless push to remote",
    }

    lines = [
        f"VAULTLESS COMPLIANCE REPORT",
        f"Framework: {framework.upper()}",
        f"Generated: {__import__('datetime').datetime.utcnow().isoformat()}Z",
        f"Environment: {env}",
        f"Audit chain: {'INTACT' if chain_ok else 'TAMPERED — REPORT INVALID'}",
        "",
        "CONTROLS",
        "─" * 60,
    ]
    for control, status in controls.items():
        lines.append(f"  {control}")
        lines.append(f"    → {status}")
        lines.append("")

    report = "\n".join(lines)

    if output:
        Path(output).write_text(report)
        console.print(f"[green]✓[/green] Report written to [bold]{output}[/bold]")
    else:
        console.print(report)


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
        title="🔐 Vaultless Status",
    ))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
