# Vaultless — Project Context
> Share this file with any AI model to get full context on the project.

---

## What We're Building

**Vaultless** — A git-architecture-inspired secrets manager with an LLM intent layer and built-in ISO 27001 / SOC-2 compliance reporting.

**One-line pitch:**
> "The only secrets manager that comes with your SOC-2 evidence pre-built."

---

## Current Build State

MVP is built. All core layers are implemented and wired together.

```
.
├── cli/
│   ├── __init__.py
│   └── vaultless.py        ✅ Click CLI — full command surface
├── intent/
│   ├── __init__.py
│   ├── executor.py         ✅ Validated intent dispatch
│   ├── parser.py           ✅ Ollama/qwen LLM classifier + keyword fallback
│   └── prompts.py          ✅ Intent schema, system prompt, risk map
├── server/
│   ├── __init__.py
│   ├── audit.py            ✅ Hash-chained tamper-evident log
│   ├── auth.py             ✅ Token CRUD + fnmatch scope enforcement
│   ├── crypto.py           ✅ FrodoKEM-1344 PQ KEK + AES-256-GCM DEK
│   ├── main.py             ✅ FastAPI — all endpoints wired
│   └── store.py            ✅ Git-style .vault/ content-addressable store
└── setup.py                ✅ pip install -e . → vaultless binary
```

**Install:**
```bash
pip install -e .          # installs vaultless binary
pip install -e ".[pq]"   # + FrodoKEM (requires: yay -S liboqs)
vaultless --help
```

---

## The Problem

HashiCorp Vault is the industry standard but:
- Insanely complex to self-host (Raft consensus, unsealing ceremony)
- Steep learning curve, needs a dedicated platform engineer
- Overkill for 80% of use cases

Existing lightweight alternatives (SOPS, git-secret, git-crypt) are:
- Tied to GPG (terrible UX)
- No REST API
- No team story
- No compliance angle

**The gap:** Self-hosted + simple + cloud-agnostic + compliance-ready. Nobody owns this cleanly.

---

## Core Architecture

### The `.git` Mental Model
Vaultless stores secrets exactly like git stores objects — content-addressable, hash-referenced, branchable.

```
.vault/
  objects/
    a1/b2c3d4...    ← AES-256-GCM encrypted blob, named by SHA-256 of ciphertext
  refs/
    heads/
      prod/
        myapp/db_password   ← hash pointer file
      staging/
        myapp/db_password   ← different hash = different value
  HEAD                      ← current environment ("prod")
  audit.log                 ← hash-chained, tamper-evident JSONL
  vault.toml                ← config (KEK algorithm, default env)
  tokens/                   ← hashed token records (JSON)
```

### Crypto Stack
```
DEK : AES-256-GCM          per-secret data encryption key
KEK : FrodoKEM-1344-SHAKE  post-quantum key encapsulation (NIST Level 5)
      ↳ fallback: X25519 if liboqs .so not present (dev only)

Flow:
  encrypt(plaintext, path):
    pk, _ = load_master_key()
    kem_ct, shared_secret = frodo_encapsulate(pk)
    aes_key = HKDF(shared_secret, info="vaultless-dek-wrap-v1" + path)
    ciphertext = AES-256-GCM(aes_key, plaintext, aad=path)
    store EncryptedBlob(kem_ct, nonce, ciphertext, aad)
```

**FrodoKEM-1344** chosen over Kyber/ML-KEM because:
- Matrix LWE — no structured lattice assumptions
- Most conservative PQ option, hardest to break with future math
- NIST security level 5 (≥ AES-256)

**KEK storage:** `VAULT_MASTER_KEY` env var (base64-encoded keypair). Generated on `vaultless init`. Never committed to git.

### Intent Layer
```
natural language
    → qwen2.5-coder:7b via Ollama (localhost:11434)
    → ParsedIntent {intent, confidence, risk, args, requires_confirm, summary}
    → executor re-validates all args (LLM output = untrusted)
    → vault action

Fallback: keyword matching if Ollama is down — vault never goes down with LLM
```

**LLM security boundary:**
```
LLM NEVER sees:          LLM always sees:
────────────────         ────────────────────
secret values            secret names/namespaces
encryption keys          access patterns
raw audit logs           structured summaries
raw token strings        token metadata only
```

### Audit Log
```json
{
  "timestamp": "2025-01-01T00:00:00Z",
  "actor": "tk_prod_abc123",
  "action": "secret_read",
  "target": "myapp/db_password",
  "result": "success",
  "prev_hash": "sha256:aabbcc...",
  "hash": "sha256:ddeeff..."
}
```
Hash chain: `entry.hash = SHA256(prev_hash + canonical_json(entry_body))`
Satisfies SOC-2 CC7.2. Verify with `vaultless audit verify`.

---

## CLI Surface

```bash
# Init
vaultless init                          # creates .vault/, generates FrodoKEM keypair

# Secrets
vaultless set myapp/db_password         # prompts for value
vaultless get myapp/db_password         # prints value
vaultless get myapp/db_password --raw   # pipeable (no decoration)
vaultless delete myapp/db_password
vaultless list myapp/

# Environments
vaultless checkout staging
vaultless merge staging prod            # promote secrets
vaultless status                        # current env + PQ status + chain health

# Tokens
vaultless token create --scope "myapp/*" --ttl 24h --label john
vaultless token revoke tk_abc123
vaultless token list

# LLM intent
vaultless ask "give john access to staging for 24 hours"
vaultless ask "who touched production secrets last week"
vaultless ask "rotate all keys older than 90 days"
vaultless ask "am I SOC-2 ready"
vaultless ask "anything suspicious in the last 24 hours"

# Zero-code-change app runner
vaultless run --namespace myapp -- python app.py
# myapp/db_password → MYAPP_DB_PASSWORD injected at runtime

# Compliance
vaultless compliance report --framework soc2
vaultless compliance report --framework iso27001 --output report.txt

# Audit
vaultless audit tail
vaultless audit verify
vaultless audit anomalies
```

---

## REST API

```
GET    /health
PUT    /secrets/{ns}/{key}      → write secret
GET    /secrets/{ns}/{key}      → read secret
DELETE /secrets/{ns}/{key}      → delete secret
GET    /secrets/{ns}            → list namespace
POST   /auth/token              → create token (admin only)
DELETE /auth/token/{id}         → revoke token (admin only)
GET    /auth/tokens             → list tokens (admin only)
POST   /ask                     → natural language intent (admin only)
GET    /audit                   → tail audit log (admin only)
GET    /audit/anomalies         → anomaly scan (admin only)
GET    /compliance/report       → SOC-2 / ISO 27001 report (admin only)
```

Auth: `Authorization: Bearer tk_...` header. Admin token (scope=`*`) required for management endpoints.

---

## Compliance Map

| Auditor Question | ISO 27001 | SOC-2 | Vaultless Feature |
|---|---|---|---|
| Who accessed what and when? | A.8.15 | CC7.2 | Hash-chained audit log |
| Who has prod access? | A.5.18 | CC6.1 | RBAC + scoped tokens |
| How do you revoke access? | A.5.18 | CC6.2 | `token revoke` |
| Secrets encrypted at rest? | A.8.24 | CC6.7 | AES-256-GCM + FrodoKEM-1344 |
| Can you show access reviews? | A.8.2 | CC6.3 | `compliance report` |
| Key rotation policy? | A.8.24 | CC6.7 | TTL + rotation commands |
| Environment separation? | A.8.25 | CC6.6 | Git-style branches |
| Disaster recovery? | A.17.1 | A1.2 | `vaultless push` (TODO) |

---

## What's Left (TODO)

```
Phase 5 — Ship
  compliance.py        full PDF report generator
  Dockerfile
  docker-compose.yml
  README.md
  vaultless push/pull  remote sync (git-style)
  crypto.py            key rotation command
```

---

## Tech Stack

```
Python 3.11+
├── FastAPI       → REST API
├── Click         → CLI
├── cryptography  → AES-256-GCM, HKDF, X25519 fallback
├── liboqs        → FrodoKEM-1344-SHAKE (yay -S liboqs)
├── httpx         → async Ollama API calls
├── pydantic      → request validation
└── rich          → CLI output

LLM:     qwen2.5-coder:7b-instruct-q4_K_M via Ollama (localhost:11434)
Storage: .vault/ on disk — no database
```

---

## Threat Model

**Protects against:**
- Secrets in plaintext on disk
- Unauthorized reads (token auth + RBAC)
- Tampered audit logs (hash chain)
- Expired/revoked token reuse (TTL enforcement)
- Accidental env var exposure (`vaultless run` injects at runtime only)
- Harvest-now-decrypt-later attacks on KEK (FrodoKEM-1344)

**Does NOT protect against:**
- Compromised host OS (root = game over)
- Memory scraping attacks
- Supply chain attacks on dependencies
- LLM prompt injection via secret names (mitigated: executor re-validates everything)

---

## Competitor Landscape

| Tool | Problem |
|------|---------|
| HashiCorp Vault | Massive complexity, needs platform engineer |
| Doppler | SaaS-only, no self-host, per-seat pricing |
| Infisical | Open core but complex, no compliance layer |
| Mozilla SOPS | GPG hell, no REST API, no team story |
| git-secret | Shell scripts, GPG, breaks constantly |

**Position:** Self-hosted + great UX + compliance-ready + post-quantum. Unclaimed territory.

---

## Business Model

| Tier | Target | Price | Includes |
|------|--------|-------|----------|
| OSS | Solo devs | Free | Core vault + CLI, self-hosted |
| Team | Startups | $29/mo | Push/pull, RBAC, 5 users |
| Compliance | Series A+ | $299/mo | ISO 27001 + SOC-2 reports |
| Enterprise | Fortune 500 | Custom | On-prem, SSO, auditor portal |
