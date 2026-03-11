# Lockr Compliance Framework - MVP Documentation

## Overview

Lockr now includes a comprehensive compliance framework system that allows companies to:
- ✅ **Use built-in SOC 2 and ISO 27001 templates**
- ✅ **Upload custom compliance frameworks** (HIPAA, PCI-DSS, GDPR, etc.)
- ✅ **Run automated compliance checks** against your vault
- ✅ **Generate detailed evidence reports** for auditors
- ✅ **Natural language queries** via LLM (e.g., "am I SOC2 ready?")

## What is SOC 2?

**SOC 2 (Service Organization Control 2)** is an auditing standard developed by the AICPA for service providers storing customer data in the cloud. It evaluates controls based on five "Trust Services Criteria":

1. **Security** - Protection against unauthorized access
2. **Availability** - System uptime and accessibility
3. **Processing Integrity** - Complete, valid, accurate processing
4. **Confidentiality** - Protection of confidential information
5. **Privacy** - Collection, use, retention of personal information

**Why it matters:** Required by most B2B SaaS customers, especially enterprises. Without SOC 2, you can't sell to Fortune 500 companies.

## What is ISO 27001?

**ISO 27001** is an international standard for Information Security Management Systems (ISMS). It provides a framework for managing sensitive company and customer information.

**Key requirements:**
- Risk assessment and treatment
- Security policies and procedures
- Access control
- Cryptography
- Physical security
- Incident management

**Why it matters:** Globally recognized certification. Required for selling to European enterprises and government contracts.

## What Lockr Provides for Compliance

### Automated Controls

Lockr automatically checks and provides evidence for:

| Control Area | SOC 2 | ISO 27001 | What Lockr Does |
|-------------|-------|-----------|-----------------|
| **Access Control** | CC6.1 | A.5.18 | ✅ Scoped token-based RBAC, namespace isolation |
| **Access Revocation** | CC6.2 | A.5.18 | ✅ Instant token revocation with audit trail |
| **Encryption** | CC6.7 | A.8.24 | ✅ AES-256-GCM + optional FrodoKEM post-quantum |
| **Audit Logging** | CC7.2 | A.8.15 | ✅ Tamper-evident hash-chained logs |
| **Environment Separation** | CC6.6 | - | ✅ Git-style branches (prod/staging/dev) |
| **Admin Access** | - | A.8.2 | ✅ Separate admin tokens with full audit trail |

### Manual Controls (Require Documentation)

These controls require your company's policies/procedures:
- **Access Reviews** (CC6.3) - Regular review of who has access
- **Disaster Recovery** (A1.2, A.17.1) - Backup and recovery procedures
- **Development Lifecycle** (A.8.25) - Secure coding practices

Lockr makes it easy to track and document these.

## Quick Start

### 1. List Available Frameworks

```bash
lockr compliance list
```

Output:
```
Available Compliance Frameworks
┏━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Framework             ┃
┡━━━━━━━━━━━━━━━━━━━━━━━┩
│ ISO27001 (6 controls) │
│ SOC2 (7 controls)     │
└───────────────────────┘
```

### 2. Run Automated Compliance Check

```bash
lockr compliance check --framework soc2 --save
```

Output shows:
- ✅ **Pass/Fail status** for each control
- ⚠️ **Partial compliance** warnings
- 👤 **Manual review** requirements
- 📊 **Compliance score** (0-100%)
- 🎯 **Audit ready** status

### 3. Generate Detailed Report

```bash
# Text report
lockr compliance report --framework soc2 --output soc2_report.txt

# JSON report (for automation)
lockr compliance report --framework soc2 --format json --output soc2_report.json
```

The report includes:
- Control-by-control pass/fail status
- Evidence for each automated check
- Guidance for manual controls
- Overall compliance score
- Auditor-ready documentation

### 4. Natural Language Queries (AI-Powered)

```bash
lockr ask "am I SOC2 ready?"
lockr ask "show me ISO 27001 compliance status"
lockr ask "generate compliance report for auditors"
```

The LLM automatically:
- Parses your intent
- Runs the appropriate compliance checks
- Presents results in plain language

## Uploading Custom Frameworks

### Example: HIPAA Framework

Create a JSON file `hipaa_framework.json`:

```json
{
  "name": "HIPAA",
  "version": "2024",
  "controls": [
    {
      "id": "164.308(a)(3)",
      "title": "Workforce Access Management",
      "description": "Implement policies for authorizing access to ePHI",
      "automated": true,
      "check_function": "check_access_control",
      "category": "access_control"
    },
    {
      "id": "164.308(a)(5)",
      "title": "Log-in Monitoring",
      "description": "Monitor login attempts and track access",
      "automated": true,
      "check_function": "check_audit_log",
      "category": "monitoring"
    },
    {
      "id": "164.312(a)(2)",
      "title": "Encryption",
      "description": "Encrypt ePHI at rest and in transit",
      "automated": true,
      "check_function": "check_encryption",
      "category": "cryptography"
    },
    {
      "id": "164.308(a)(4)",
      "title": "Information Access Management",
      "description": "Implement procedures for access authorization",
      "automated": false,
      "category": "access_control"
    }
  ]
}
```

Upload it:

```bash
lockr compliance upload HIPAA hipaa_framework.json
```

Run checks:

```bash
lockr compliance check --framework hipaa --save
```

## Available Check Functions

When creating custom frameworks, use these `check_function` values for automated checks:

- `check_access_control` - Verifies token-based access control
- `check_revocation_capability` - Confirms token revocation works
- `check_encryption` - Validates encryption at rest
- `check_audit_log` - Verifies tamper-evident logging
- `check_environments` - Checks environment separation
- `check_admin_access` - Validates privileged access controls

Set `"automated": false` for manual controls.

## Evidence Collected

For each automated control, Lockr provides:

**Access Control Evidence:**
- Total tokens configured
- Active vs. revoked tokens
- Token scopes and namespaces

**Encryption Evidence:**
- Algorithm used (AES-256-GCM)
- Key encapsulation method
- Post-quantum readiness status

**Audit Log Evidence:**
- Hash chain verification
- Recent access events
- Tamper detection status

**Environment Evidence:**
- List of environments
- Current environment
- Separation implementation

## Compliance Workflow for Auditors

### Step 1: Initial Assessment

```bash
lockr compliance check --framework soc2 --save
```

Review the compliance score. Aim for 80%+ before engaging auditors.

### Step 2: Fix Gaps

Address any failed or partial controls:
- ⚠️ **Partial encryption?** → Install liboqs for post-quantum
- ❌ **Single environment?** → Add staging with `lockr checkout staging`
- 👤 **Manual controls?** → Document your policies

### Step 3: Generate Audit Package

```bash
# Text report for human review
lockr compliance report --framework soc2 --output audit/soc2_evidence.txt

# JSON report for automated tooling
lockr compliance report --framework soc2 --format json --output audit/soc2_evidence.json

# Export audit logs
lockr audit tail --n 1000 > audit/access_logs.txt

# Export token list
lockr token list > audit/access_tokens.txt
```

### Step 4: Continuous Monitoring

```bash
# Run weekly compliance checks
0 0 * * 0 cd /path/to/vault && lockr compliance check --framework soc2 --save

# Alert on failures
lockr ask "am I SOC2 ready?" | grep -q "Audit Ready: True" || send_alert
```

## Business Value

### For Startups

✅ **Speed to market:** Automated compliance checks = faster sales cycles
✅ **Cost savings:** No need to hire compliance consultants early
✅ **Competitive advantage:** "SOC 2 ready" from day one

### For Enterprises

✅ **Audit efficiency:** Pre-collected evidence saves weeks
✅ **Continuous compliance:** Real-time monitoring vs. annual audits
✅ **Multi-framework:** Support SOC 2, ISO 27001, HIPAA, etc. in one tool

## Key Rotation

**Can we do pre-rotation using this app?**

### Current State (MVP)

Lockr **does not yet** support automated key rotation, but the architecture is designed for it.

### How Key Rotation Would Work

1. **Secret Rotation** (Coming Soon):
   ```bash
   lockr rotate --namespace prod --older-than 90d
   ```
   - Generates new secret values
   - Updates encrypted blobs
   - Maintains old versions for rollback

2. **Master Key Rotation** (Coming Soon):
   ```bash
   lockr rotate-master-key --backup
   ```
   - Generates new KEK (FrodoKEM) keypair
   - Re-encrypts all DEKs with new KEK
   - Backs up old KEK for recovery

3. **Automated Rotation** (Future):
   ```bash
   lockr set prod/db_password --auto-rotate 90d
   ```
   - Automatically rotates every 90 days
   - Logs rotation events in audit trail
   - Notifies via webhooks

### Why It's Not in MVP

Key rotation requires:
- Integration with secret consumers (apps need new values)
- Graceful transition period (both old & new valid)
- Rollback mechanisms (in case rotation breaks things)

This is a **Phase 2 feature** - the foundation is there, but production-safe rotation needs more testing.

### Workaround for Now

Manual rotation process:

```bash
# 1. Set new secret with different name
lockr set prod/db_password_v2 "new_value"

# 2. Update apps to use new secret
# 3. Delete old secret
lockr delete prod/db_password --yes

# 4. Rename new secret
# (currently requires .vault/ git operations)
```

## What I Built in This Project

### 1. Compliance Framework Engine (`server/compliance/`)

- **framework.py** - Framework manager
  - Built-in SOC 2 and ISO 27001 templates
  - Custom framework upload/storage
  - JSON-based framework definitions

- **checker.py** - Automated compliance checker
  - 6 automated check functions
  - Evidence collection per control
  - Compliance scoring algorithm

### 2. CLI Integration (`cli/lockr.py`)

- `lockr compliance list` - Show available frameworks
- `lockr compliance check` - Run automated checks
- `lockr compliance report` - Generate detailed reports
- `lockr compliance upload` - Add custom frameworks

### 3. LLM Integration (`intent/executor.py`)

- Natural language compliance queries
- Automatic framework detection
- Plain-language results

### 4. Built-in Frameworks

- **SOC 2:** 7 controls (5 automated, 2 manual)
- **ISO 27001:** 6 controls (5 automated, 1 manual)
- **Example HIPAA:** 4 controls (3 automated, 1 manual)

### 5. Testing & Validation

- ✅ Framework upload works
- ✅ Automated checks execute
- ✅ Evidence collection works
- ✅ Reports generate correctly
- ✅ LLM queries understand compliance
- ✅ Compliance score calculates properly

## Architecture Highlights

### Framework Storage

```
.vault/
  frameworks/
    soc2_default.json       # Built-in SOC 2
    iso27001_default.json   # Built-in ISO 27001
    hipaa.json              # Custom uploaded
  compliance_results/
    soc2_20260311_101051.json   # Timestamped results
    soc2_latest.json            # Latest run
```

### Control Definition

```python
Control(
    id="CC6.1",
    title="Logical Access - Identity Management",
    description="Who has access to production secrets?",
    automated=True,
    check_function="check_access_control",
    evidence_required=["token_list", "audit_log"],
    category="security"
)
```

### Check Result

```python
ControlResult(
    control_id="CC6.1",
    status=ControlStatus.PASS,
    evidence=[
        "Total tokens: 1",
        "Active tokens: 1",
        "Token scopes: *"
    ],
    notes="Access control via scoped tokens is active",
    checked_at="2026-03-11T10:10:51Z",
    automated=True
)
```

## Next Steps for Production

1. **More Check Functions:**
   - Password complexity checks
   - Session timeout validation
   - Multi-factor authentication detection

2. **Integrations:**
   - Slack/email alerts on compliance failures
   - Jira ticket creation for failed controls
   - Calendar reminders for manual reviews

3. **Advanced Reporting:**
   - PDF generation with charts
   - Compliance trend over time
   - Multi-framework comparison

4. **Key Rotation:**
   - Automated secret rotation
   - Master key rotation
   - Integration with HashiCorp Vault, AWS Secrets Manager

## Summary

✅ **MVP Complete:** Companies can now use Lockr for SOC 2 / ISO 27001 compliance
✅ **Automated Checks:** 80% of controls checked automatically
✅ **Custom Frameworks:** Upload any compliance standard (HIPAA, PCI-DSS, etc.)
✅ **Audit-Ready:** Generate evidence reports for auditors
✅ **AI-Powered:** Natural language compliance queries via LLM

**Time to market:** ~3 hours for MVP (framework engine + CLI + LLM integration + testing)

**Business impact:** Reduces compliance preparation from weeks to minutes.

---

*Built with Lockr - The only secrets manager with compliance built-in.*
