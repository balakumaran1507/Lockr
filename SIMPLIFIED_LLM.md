# Simplified LLM Command Selection - No Risk Scoring

## Overview

The LLM intent system has been simplified to remove risk scoring layers. Now it works as a simple **command catalog selector**:

1. User asks in natural language
2. LLM reads the question and selects matching command from catalog
3. System extracts arguments and executes
4. User sees the suggested CLI command they can run manually

## What Changed

### Before (Complex Risk-Based)

```
User query → LLM → Intent + Risk + Confidence + Confirmation → Validator → Executor
```

**Problems:**
- Risk scoring added complexity
- Confidence thresholds were arbitrary
- Confirmation gates slowed down workflows
- LLM had to calculate risk levels

### After (Simple Catalog-Based)

```
User query → LLM → Intent + Command + Args → Validator → Executor
```

**Benefits:**
- ✅ Simpler: Just catalog lookup
- ✅ Faster: No risk calculation
- ✅ Transparent: Shows exact CLI command
- ✅ Educational: Users learn the CLI

## Command Catalog

The LLM now selects from this fixed catalog:

```python
COMMAND_CATALOG = {
    "grant_access":      "lockr token create --scope {namespace} --ttl {ttl} --label {user}",
    "revoke_access":     "lockr token revoke {token_id}",
    "audit_query":       "lockr audit tail --namespace {namespace}",
    "compliance_check":  "lockr compliance check --framework {framework}",
    "anomaly_detect":    "lockr audit anomalies --since {since}",
    "secret_read":       "lockr get {namespace}/{key}",
    "secret_write":      "lockr set {namespace}/{key}",
    "secret_delete":     "lockr delete {namespace}/{key}",
    "secret_list":       "lockr list {namespace}",
}
```

## Updated System Prompt

**Old prompt:**
> "You are the intent parser for Lockr. Calculate risk levels (low/medium/high), confidence scores, and determine if confirmation is required..."

**New prompt:**
> "You are a command selector for Lockr. Read the user's natural language input and select the matching command from the catalog."

The LLM now:
- Reads from a command catalog (like a menu)
- Extracts arguments from the user query
- Returns structured JSON with intent + command + args

## Example Interactions

### Example 1: List Secrets

**Input:**
```
lockr ask "show me all secrets in test"
```

**Output:**
```
╭──────────────── 🧠 Command Selected ────────────────╮
│ Intent:    secret_list                              │
│ Command:   lockr list test                          │
│ Summary:   List all secrets in the test namespace.  │
│ Args:      {'namespace': 'test'}                    │
╰─────────────────────────────────────────────────────╯

✓ 📂 Listed secrets in 'test'.
Run manually: lockr list test
```

### Example 2: Compliance Check

**Input:**
```
lockr ask "check ISO 27001 compliance"
```

**Output:**
```
╭──────────────── 🧠 Command Selected ────────────────╮
│ Intent:    compliance_check                         │
│ Command:   lockr compliance check --framework iso27001 │
│ Summary:   Run ISO 27001 compliance check           │
│ Args:      {'framework': 'iso27001'}                │
╰─────────────────────────────────────────────────────╯

✓ ✅ ISO27001 compliance check complete. Score: 75.0% | Passed: 3/6
Run manually: lockr compliance check --framework iso27001
```

### Example 3: Grant Access

**Input:**
```
lockr ask "give john access to staging for 24 hours"
```

**Output:**
```
╭──────────────── 🧠 Command Selected ────────────────╮
│ Intent:    grant_access                             │
│ Command:   lockr token create --scope staging --ttl 24h --label john │
│ Summary:   Create access token for john             │
│ Args:      {'user': 'john', 'namespace': 'staging', 'ttl': '24h'} │
╰─────────────────────────────────────────────────────╯

✓ ✅ Granted john access to 'staging' for 24h.
Run manually: lockr token create --scope staging --ttl 24h --label john
```

## LLM Response Format

**Old format (complex):**
```json
{
  "intent": "secret_list",
  "confidence": 0.95,
  "risk": "low",
  "requires_confirm": false,
  "args": {"namespace": "test"},
  "summary": "List secrets in test namespace"
}
```

**New format (simple):**
```json
{
  "intent": "secret_list",
  "command": "lockr list test",
  "args": {"namespace": "test"},
  "summary": "List all secrets in the test namespace."
}
```

Removed:
- ❌ `confidence` field
- ❌ `risk` field
- ❌ `requires_confirm` field

Added:
- ✅ `command` field (exact CLI command)

## Code Changes

### 1. Updated `intent/prompts.py`

**Removed:**
```python
class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

INTENT_RISK_MAP = {...}
CONFIRM_REQUIRED = {...}
```

**Added:**
```python
COMMAND_CATALOG = {
    IntentType.SECRET_LIST: "lockr list {namespace}",
    IntentType.COMPLIANCE_CHECK: "lockr compliance check --framework {framework}",
    # ... etc
}
```

### 2. Simplified `intent/parser.py`

**Removed:**
- Risk level validation
- Confidence floor checking
- Confirmation requirements

**Kept:**
- Intent type validation
- Argument extraction
- Fallback to keyword matching

### 3. Streamlined `intent/executor.py`

**Old execution flow:**
```python
def execute(intent, confirmed):
    if requires_confirm and not confirmed:
        return REQUIRES_CONFIRM
    if confidence < 0.5:
        return FALLBACK
    if risk == HIGH:
        # special handling
    # ... execute
```

**New execution flow:**
```python
def execute(intent, confirmed):
    # Validate args
    # Execute
    # Return result + command
```

### 4. Updated CLI Display

**Old display:**
```
Intent: secret_list
Risk: LOW
Confidence: 95%
Requires Confirm: false
```

**New display:**
```
Intent: secret_list
Command: lockr list test
Summary: List all secrets in the test namespace
```

## Why This Is Better

### 1. **Transparency**
Users see exactly what CLI command will run. No hidden risk calculations.

### 2. **Educational**
Users learn the actual CLI commands by seeing them suggested.

### 3. **Simplicity**
Removed 3 layers of complexity:
- Risk scoring
- Confidence thresholds
- Confirmation gates

### 4. **Faster**
No extra calculations needed. Just:
1. Match intent
2. Extract args
3. Execute

### 5. **Debuggable**
When something goes wrong, users can run the suggested command manually to debug.

## Fallback Behavior

If Ollama is down, the system falls back to keyword matching:

```python
def _fallback_intent(user_input):
    if "list" in user_input.lower():
        return ParsedIntent(
            intent="secret_list",
            command="lockr list {namespace}",
            args={},
            summary="[fallback] Use specific CLI command for best results."
        )
```

The vault **never goes down** even if the LLM is unavailable.

## Migration Guide

If you had code using the old format:

**Before:**
```python
intent = parse_intent("show me secrets")
if intent["risk"] == "high":
    # do something
if intent["confidence"] < 0.7:
    # do something else
```

**After:**
```python
intent = parse_intent("show me secrets")
# Just use intent["intent"] and intent["args"]
# No more risk or confidence checks
```

## Summary

✅ **Removed:** Risk scoring, confidence thresholds, confirmation requirements
✅ **Added:** Command catalog, CLI command suggestions
✅ **Result:** Simpler, faster, more transparent LLM integration

The LLM is now a **command selector** rather than a **risk assessor**.

---

*Built for speed and simplicity.*
