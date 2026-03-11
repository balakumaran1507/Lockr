#!/bin/bash
# demo.sh — Lockr live feature walkthrough
#
# Usage:
#   bash demo.sh           # runs straight through (CI-friendly)
#   bash demo.sh --pause   # pauses between sections (for live demos)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOCKR="$SCRIPT_DIR/.venv/bin/lockr"
PYEXEC="$SCRIPT_DIR/.venv/bin/python"
DEMO_DIR="/tmp/lockr-demo"
PAUSE_MODE=0

[[ "${1:-}" == "--pause" ]] && PAUSE_MODE=1

# ── colours ─────────────────────────────────────────────────────────────────
CYAN='\033[0;36m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
RED='\033[0;31m';  BOLD='\033[1m';      DIM='\033[2m';  NC='\033[0m'

# ── helpers ──────────────────────────────────────────────────────────────────

banner() {
  echo -e "\n${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${CYAN}${BOLD}  $1${NC}"
  echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

run() {
  echo -e "${DIM}\$ $*${NC}"
  eval "$@"
  echo ""
}

pause() {
  if [[ $PAUSE_MODE -eq 1 ]]; then
    echo -e "${YELLOW}  ↵  press Enter to continue...${NC}"
    read -r < /dev/tty || true
  fi
}

# ── pre-flight ───────────────────────────────────────────────────────────────

if [[ ! -f "$LOCKR" ]]; then
  echo -e "${RED}✗ .venv not found.${NC}"
  echo "  Run:  python -m venv .venv && .venv/bin/pip install -e ."
  exit 1
fi

rm -rf "$DEMO_DIR" && mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR" && git init -q

# Generate master key ONCE — lockr init will reuse it if VAULT_MASTER_KEY is set
export VAULT_MASTER_KEY
VAULT_MASTER_KEY=$($PYEXEC -c "
import sys; sys.path.insert(0, '$SCRIPT_DIR')
from server.crypto import generate_keypair, encode_master_key
pk, sk = generate_keypair()
print(encode_master_key(pk, sk))
")

echo -e "\n${BOLD}🔐  Lockr — Live Demo${NC}"
echo -e "${DIM}    Working directory : $DEMO_DIR${NC}"
echo -e "${DIM}    lockr binary      : $LOCKR${NC}"

# ============================================================================
banner "1 · init — create an encrypted vault"
# ============================================================================

cat <<'EOF'
  lockr init creates .vault/ — mirroring git's .git/ layout:

    .vault/objects/   AES-256-GCM encrypted blobs, named by SHA-256 hash
    .vault/refs/      per-environment key pointers  (like git branches)
    .vault/HEAD       active environment name
    .vault/audit.log  tamper-evident hash-chained log
    .vault/tokens/    RBAC token records
EOF
echo ""

run "$LOCKR init"
run "ls .vault/"

pause

# ============================================================================
banner "2 · set / get — store and retrieve secrets"
# ============================================================================

cat <<'EOF'
  Secrets are AES-256-GCM encrypted on write.
  The master key never touches disk — only lives in VAULT_MASTER_KEY.
EOF
echo ""

run "$LOCKR set myapp/db_password 'prod-db-pass-S3cur3!'"
run "$LOCKR set myapp/api_key     'sk-prod-abc123xyz789'"
run "$LOCKR set myapp/stripe_key  'sk_live_XXXXXXXXXXXX'"

echo -e "${DIM}  Decorated read:${NC}"
run "$LOCKR get myapp/db_password"

echo -e "${DIM}  --raw flag (pipeable, no decoration):${NC}"
run "$LOCKR get myapp/api_key --raw"

pause

# ============================================================================
banner "3 · list — browse a namespace"
# ============================================================================

run "$LOCKR list myapp/"

pause

# ============================================================================
banner "4 · checkout / merge — git-style environments"
# ============================================================================

cat <<'EOF'
  Environments are isolated branches.
  The same key can hold different values in prod vs staging.
EOF
echo ""

run "$LOCKR checkout staging"
run "$LOCKR set myapp/db_password 'staging-db-DIFFERENT'"

echo -e "${DIM}  staging value:${NC}"
run "$LOCKR get myapp/db_password"

run "$LOCKR checkout prod"
echo -e "${DIM}  prod value (untouched):${NC}"
run "$LOCKR get myapp/db_password"

echo -e "${DIM}  Promote staging → prod (lockr merge):${NC}"
run "$LOCKR merge staging prod --yes"

pause

# ============================================================================
banner "5 · status — vault health at a glance"
# ============================================================================

run "$LOCKR status"

pause

# ============================================================================
banner "6 · token — scoped access control"
# ============================================================================

cat <<'EOF'
  Tokens use glob-pattern scopes + optional TTLs.
  A token with scope "myapp/*" cannot read "payments/*".
EOF
echo ""

run "$LOCKR token create --scope 'myapp/*'    --ttl 24h --label john-dev"
run "$LOCKR token create --scope 'myapp/api*' --ttl 1h  --label ci-pipeline"
run "$LOCKR token list"

pause

# ============================================================================
banner "7 · run — zero-code-change secret injection"
# ============================================================================

cat <<'EOF'
  Secrets are injected as env vars at runtime — your app never
  reads files or calls an API directly.

    myapp/db_password  →  MYAPP_DB_PASSWORD
    myapp/api_key      →  MYAPP_API_KEY
    myapp/stripe_key   →  MYAPP_STRIPE_KEY
EOF
echo ""

run "$LOCKR run --namespace myapp -- env | grep MYAPP"

pause

# ============================================================================
banner "8 · audit — tamper-evident hash-chained log"
# ============================================================================

cat <<'EOF'
  Every read/write/delete is logged.  Each entry SHA-256-hashes the
  previous one — altering any entry breaks the entire chain.
  Maps to:  SOC-2 CC7.2   ISO 27001 A.8.15
EOF
echo ""

run "$LOCKR audit tail --n 8"
run "$LOCKR audit verify"

pause

# ============================================================================
banner "9 · rotate — versioned secret rotation"
# ============================================================================

run "$LOCKR rotate secret myapp/db_password --generate"
run "$LOCKR rotate history myapp/db_password"
run "$LOCKR rotate status myapp/"

pause

# ============================================================================
banner "10 · compliance — SOC-2 / ISO 27001 evidence"
# ============================================================================

cat <<'EOF'
  "The only secrets manager with SOC-2 evidence pre-built."
  Run a check, then generate a full report for auditors.
EOF
echo ""

run "$LOCKR compliance check  --framework soc2"
run "$LOCKR compliance report --framework soc2"

pause

# ============================================================================
banner "11 · scan — detect plaintext secrets before git push"
# ============================================================================

cat <<'EOF'
  lockr scan walks the project and flags:
    • Sensitive filenames  (config.env, .env, *.pem, id_rsa …)
    • Hardcoded credentials (API_KEY=, TOKEN=, AWS/GitHub/Slack keys …)
EOF
echo ""

# Plant realistic "leaked" files
cat > ./config.env <<'ENVEOF'
VAULT_MASTER_KEY=AAAA_THIS_SHOULD_NOT_BE_HERE
STRIPE_SECRET_KEY=sk_live_XXXXXXXXXXXX
DB_PASSWORD=super-secret-123
ENVEOF

cat > ./app_config.py <<'PYEOF'
# Oops — someone hardcoded creds
OPENAI_API_KEY = "sk-proj-abc123xyz789longapikey"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN   = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456ab"
PYEOF

echo -e "${DIM}  Planted: config.env  app_config.py${NC}\n"

run "$LOCKR scan"

pause

# ============================================================================
banner "12 · guard — block git commits that contain secrets"
# ============================================================================

cat <<'EOF'
  lockr guard install injects a pre-commit hook.
  Any commit staged with secrets is blocked automatically.
  Override for one commit:  LOCKR_SKIP=1 git commit …
EOF
echo ""

run "$LOCKR guard install"
echo -e "${DIM}  Attempting: git add config.env && git commit …${NC}\n"

git add config.env 2>/dev/null || true
if git -c user.email="demo@lockr" -c user.name="Demo" \
       commit -m "add config" 2>&1; then
  echo -e "${RED}  commit should have been blocked — check hook${NC}"
else
  echo -e "${GREEN}  ✓ Commit blocked. Secrets protected.${NC}"
fi

echo ""
run "$LOCKR guard uninstall"

pause

# ============================================================================
echo -e "\n${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  All features demonstrated successfully.${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
echo -e "  Vault at  : ${BOLD}$DEMO_DIR/.vault/${NC}"
echo -e "  Full help : ${BOLD}lockr --help${NC}"
echo ""
