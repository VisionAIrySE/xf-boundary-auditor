# XF Boundary Auditor — Implementation Spec

**For:** V (OpenClaw build agent)
**Written by:** Claude Code (Sonnet 4.6) — authoritative on CC internals
**Repo:** VisionAIrySE/xf-boundary-auditor
**Package name:** xf-boundary-auditor
**Skill command:** `/xf-audit`

---

## 1. CC Hook Contract (PreToolUse)

### How hooks are registered

CC hooks live in `~/.claude/settings.json` (user-global) or `.claude/settings.json` (project-local).

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/xf-boundary-auditor/hook.sh"
          }
        ]
      }
    ]
  }
}
```

`matcher: ""` means fire on every tool call. The hook itself filters by `tool_name`.

### What CC sends on stdin

CC delivers a JSON object on stdin for every PreToolUse event:

```json
{
  "hook_event_name": "PreToolUse",
  "tool_name": "Edit",
  "tool_input": {
    "file_path": "/path/to/file.py",
    "old_string": "...",
    "new_string": "..."
  }
}
```

For the `Write` tool:
```json
{
  "hook_event_name": "PreToolUse",
  "tool_name": "Write",
  "tool_input": {
    "file_path": "/path/to/file.py",
    "content": "..."
  }
}
```

**Critical:** Read from stdin, not argv. Parse with `json.loads(sys.stdin.read())`.

### Exit code contract

| Exit code | Meaning |
|-----------|---------|
| `0` | Allow — tool call proceeds normally |
| `2` | Block — tool call is cancelled. CC shows stdout to the user as the block reason |

- **stdout** on exit 2 = the message Claude sees explaining why it was blocked
- **stderr** is suppressed by CC when exit code is non-zero
- **stdout** on exit 0 = injected into Claude's context as a system note (use sparingly)

### Which tools to intercept

Filter to `Edit` and `Write` only:

```python
AUDIT_TOOLS = {"Edit", "Write"}
tool_name = hook_input.get("tool_name", "")
if tool_name not in AUDIT_TOOLS:
    sys.exit(0)  # pass through everything else silently
```

### File path extraction

```python
file_path = hook_input.get("tool_input", {}).get("file_path", "")
```

---

## 2. .xf/ Artifact Schema

### .xf/boundary_violations.json

Written on every audit run. Ralph Loop reads this to drive iteration.

```json
{
  "schema_version": "1.0",
  "audit_timestamp": "2026-03-19T04:00:00Z",
  "cwd": "/path/to/project",
  "total_violations": 3,
  "violations": [
    {
      "id": "v001",
      "type": "interface_existence",
      "severity": "error",
      "caller_module": "dispatch.sh",
      "caller_line": 491,
      "callee_module": "stack_scanner",
      "symbol": "get_stack_profile",
      "detail": "Symbol does not exist in callee. Did you mean: load_stack_profile?",
      "status": "open"
    },
    {
      "id": "v002",
      "type": "signature_contract",
      "severity": "error",
      "caller_module": "preuse_hook.sh",
      "caller_line": 133,
      "callee_module": "evaluator",
      "symbol": "build_recommendation_list",
      "detail": "Caller passes kwarg 'cc_tool_type' but callee signature does not include it.",
      "status": "open"
    }
  ],
  "checked_items": [],
  "ralph_iteration": 0
}
```

**`status` values:** `"open"` | `"confirmed_bug"` | `"confirmed_clean"` | `"fixed"`

**`type` values (MECE):**
- `interface_existence` — symbol imported/called doesn't exist in callee
- `signature_contract` — symbol exists but required params changed
- `data_contract` — producer writes field under key X, consumer reads it under key Y
- `environment_contract` — module requires env var that no installer guarantees
- `stale_symbol` — symbol renamed/deleted, caller still uses old name

### .xf/boundary_index.json

Persistent symbol catalog. Updated incrementally, survives between Ralph iterations.

```json
{
  "schema_version": "1.0",
  "last_scanned": "2026-03-19T04:00:00Z",
  "modules": {
    "stack_scanner": {
      "path": "stack_scanner.py",
      "exports": ["load_stack_profile", "scan_and_save"],
      "imports": ["json", "os", "pathlib"],
      "state_writes": [],
      "env_vars_read": []
    },
    "interceptor": {
      "path": "interceptor.py",
      "exports": ["check_bypass", "write_bypass", "should_intercept", "get_cc_tool_type"],
      "imports": ["json", "os", "time"],
      "state_writes": ["bypass", "last_suggested", "last_cc_tool_type"],
      "env_vars_read": []
    }
  },
  "callers": [
    {
      "caller": "dispatch.sh",
      "callee_module": "stack_scanner",
      "symbol": "load_stack_profile",
      "line": 491
    }
  ]
}
```

---

## 3. Python Scanner Interface

Abstract base — implement one subclass per language.

```python
# scanner_base.py
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class SymbolTable:
    module_name: str
    path: str
    exports: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    calls: List[dict] = field(default_factory=list)      # {symbol, line, args}
    state_writes: List[str] = field(default_factory=list) # JSON key names written
    state_reads: List[str] = field(default_factory=list)  # JSON key names read
    env_vars_read: List[str] = field(default_factory=list)

class ScannerBase(ABC):
    @abstractmethod
    def scan(self, path: str) -> Optional[SymbolTable]:
        """Scan a single file. Return SymbolTable or None if file not supported."""
        ...

    @abstractmethod
    def supports(self, path: str) -> bool:
        """Return True if this scanner handles files at this path."""
        ...
```

```python
# scanner_python.py — uses built-in ast, no dependencies
import ast
from scanner_base import ScannerBase, SymbolTable

class PythonScanner(ScannerBase):
    def supports(self, path: str) -> bool:
        return path.endswith(".py")

    def scan(self, path: str) -> SymbolTable:
        # Use ast.parse() to extract:
        # - Top-level function/class definitions → exports
        # - import / from X import Y statements → imports
        # - ast.Call nodes → calls (symbol name + line)
        # - json.loads / json.dumps with literal key strings → state_reads/writes
        # - os.environ.get() / os.getenv() → env_vars_read
        ...
```

```python
# scanner_bash.py — regex-based (no bash AST available)
import re
from scanner_base import ScannerBase, SymbolTable

class BashScanner(ScannerBase):
    def supports(self, path: str) -> bool:
        return path.endswith(".sh")

    def scan(self, path: str) -> SymbolTable:
        # Regex patterns:
        # Function definitions: ^function_name\s*\(\)
        # Python inline calls: python3 -c "...from X import Y..."
        # JSON field access: .get\("([^"]+)"\) in inline python strings
        # env var reads: \$\{?([A-Z_]+)\}?
        ...
```

**Scanner registry pattern:**

```python
# scanner_registry.py
from scanner_python import PythonScanner
from scanner_bash import BashScanner

SCANNERS = [PythonScanner(), BashScanner()]

def scan_file(path: str):
    for scanner in SCANNERS:
        if scanner.supports(path):
            return scanner.scan(path)
    return None
```

---

## 4. Hook Entry Point

```
~/.claude/xf-boundary-auditor/
├── hook.sh              # entry point registered in settings.json
├── auditor.py           # main audit logic
├── scanner_base.py
├── scanner_python.py
├── scanner_bash.py
├── scanner_registry.py
├── flow_analyzer.py     # builds caller→callee graph, detects violations
└── ralph_loop.py        # Ralph iteration driver
```

### hook.sh

```bash
#!/usr/bin/env bash
set -euo pipefail

AUDITOR_DIR="$(dirname "$0")"
HOOK_INPUT="$(cat)"  # read stdin ONCE, save to var

# Only audit Edit and Write
TOOL_NAME=$(echo "$HOOK_INPUT" | python3 -c "import json,sys; print(json.loads(sys.stdin.read()).get('tool_name',''))" <<< "$HOOK_INPUT" 2>/dev/null || echo "")

if [[ "$TOOL_NAME" != "Edit" && "$TOOL_NAME" != "Write" ]]; then
    exit 0
fi

python3 "$AUDITOR_DIR/auditor.py" "$HOOK_INPUT"
# auditor.py exits 0 (clean) or 2 (violations found)
```

### auditor.py exit contract

```python
import sys, json

hook_input = json.loads(sys.argv[1])
file_path = hook_input.get("tool_input", {}).get("file_path", "")

# 1. Build/update boundary index for this file and its callers
# 2. Check if proposed change breaks any existing callers
# 3. If violations: write .xf/boundary_violations.json, print report, exit 2
# 4. If clean: exit 0

violations = check_boundary(file_path, hook_input)

if violations:
    write_violations_json(violations)
    print(format_report(violations))  # stdout = shown to Claude on block
    sys.exit(2)

sys.exit(0)
```

---

## 5. Ralph Loop Prompt Structure

When `/xf-audit` is invoked (not `--report-only`), the skill spawns a Ralph Loop.

### Iteration prompt template

```
Read .xf/boundary_violations.json.

Count open violations (status == "open" or "confirmed_bug").

If count == 0:
  Output: <promise>BOUNDARY_AUDIT_COMPLETE: 0 violations</promise>
  Stop.

If count > 0:
  Take the FIRST open violation by id.
  Read the source files involved (caller_module + callee_module).
  Classify the violation:
    - CONFIRMED_BUG: caller references something that truly doesn't exist → fix it
    - CONFIRMED_CLEAN: false positive (dynamic dispatch, intentional pattern) → mark status=confirmed_clean
    - NEEDS_FIX: callee changed, caller not updated → update caller
  Apply exactly ONE fix.
  Update the violation's status in .xf/boundary_violations.json.
  Report: "Fixed: [type] [symbol] in [caller]:[line]. Remaining: [N-1] open violations."
```

### Completion promise

```
<promise>BOUNDARY_AUDIT_COMPLETE: 0 violations</promise>
```

### Max iterations

`initial_violation_count + 5` — hard stop. If stuck (no violation removed after N attempts), output:

```
<promise>BOUNDARY_AUDIT_STUCK: [N] violations remain unresolved. Manual review required.</promise>
```

---

## 6. Install Script Contract

`install.sh` must:

1. Copy auditor files to `~/.claude/xf-boundary-auditor/`
2. Register PreToolUse hook in `~/.claude/settings.json`
3. Register `/xf-audit` skill (path: `~/.claude/xf-boundary-auditor/skill.md`)
4. Create `.xf/` directory in cwd (or skip if not in a project)
5. Add `.xf/` to `.gitignore` if a git repo is detected

### settings.json hook registration

Read existing settings.json, merge hook entry, write back. Never overwrite the whole file.

```python
import json, os

settings_path = os.path.expanduser("~/.claude/settings.json")
try:
    with open(settings_path) as f:
        settings = json.load(f)
except Exception:
    settings = {}

hooks = settings.setdefault("hooks", {})
preuse = hooks.setdefault("PreToolUse", [])

hook_entry = {
    "matcher": "",
    "hooks": [{"type": "command", "command": "~/.claude/xf-boundary-auditor/hook.sh"}]
}

# Avoid duplicates
if not any(
    h.get("hooks", [{}])[0].get("command", "").endswith("xf-boundary-auditor/hook.sh")
    for h in preuse
):
    preuse.append(hook_entry)

with open(settings_path, "w") as f:
    json.dump(settings, f, indent=2)
```

---

## 7. .gitignore Entries

```
.xf/
```

Violations and index are runtime state. Not committed.

---

## 8. skill.md (for CC skill discovery)

```markdown
---
name: xf-audit
description: Boundary contract auditor. Maps every interface in your codebase, finds caller/callee mismatches, and fixes them via Ralph Loop until 0 violations remain. Catches renamed functions, changed signatures, stale state field keys, and missing env vars — before they ship.
---

Run boundary audit and fix all violations:
`/xf-audit`

Report only (no fixes applied):
`/xf-audit --report-only`

Audit specific path:
`/xf-audit path/to/module.py`
```

---

## 9. Open Questions (resolved — locked)

| Decision | Answer |
|----------|--------|
| MVP language scope | Python-only. BashScanner (regex) included for .sh files. TS in v2. |
| Hook target | PreToolUse, filtering Edit + Write only |
| Artifact location | `.xf/boundary_violations.json`, `.xf/boundary_index.json` |
| Default mode | Ralph Loop to 0 violations. `--report-only` flag for non-mutating mode. |
| Skill command | `/xf-audit` |
| Repo | VisionAIrySE/xf-boundary-auditor |
| Package name | xf-boundary-auditor |
| Completion promise | `<promise>BOUNDARY_AUDIT_COMPLETE: 0 violations</promise>` |

---

*This document is the authoritative CC integration spec. Implementation questions about Python AST, Ralph Loop mechanics, or CC hook behavior should be answered from this file.*
