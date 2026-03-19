---
name: xf-audit
description: Boundary contract auditor. Maps every interface in your codebase, finds caller/callee mismatches, and fixes them via Ralph Loop until 0 violations remain. Catches renamed functions, changed signatures, missing imports — before they ship. Use --report-only for CI/inspection without fixes.
---

## /xf-audit

You are running the XF Boundary Auditor Ralph Loop.

Your job: drive `.xf/boundary_violations.json` to zero open violations, one fix at a time.

---

### Mode detection

If the user passed `--report-only`:
- Read `.xf/boundary_violations.json`
- If the file doesn't exist, run the scanner first: execute `python3 ~/.claude/xf-boundary-auditor/auditor.py '{"hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":"__report_only__"}}'` from the project root
- Print the full violations list grouped by file
- Output: `BOUNDARY REPORT: N violations found. No fixes applied.`
- Stop. Do not fix anything.

---

### Default mode (Ralph Loop to zero)

**Step 1 — Initialize**

Read `.xf/boundary_violations.json`.

If the file doesn't exist or `total_violations` is 0 with no open items:
- Run the scanner: execute `python3 ~/.claude/xf-boundary-auditor/auditor.py '{"hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":"__xf_audit__"}}'` from the project root
- Re-read `.xf/boundary_violations.json`

Count violations where `status == "open"`. Call this `INITIAL_COUNT`.

Set `MAX_ITERATIONS = INITIAL_COUNT + 5`.

If `INITIAL_COUNT == 0`:
- Output: `<promise>BOUNDARY_AUDIT_COMPLETE: 0 violations</promise>`
- Stop.

Report to user: `XF Audit started. Found INITIAL_COUNT open violations. Max iterations: MAX_ITERATIONS.`

---

**Step 2 — Iteration loop**

Repeat until done:

1. Read `.xf/boundary_violations.json`
2. Count items where `status == "open"`. Call this `REMAINING`.
3. Check iteration count. If iterations exhausted (> MAX_ITERATIONS):
   - Output: `<promise>BOUNDARY_AUDIT_STUCK: REMAINING violations remain unresolved after MAX_ITERATIONS iterations. Manual review required.</promise>`
   - Stop.
4. If `REMAINING == 0`:
   - Output: `<promise>BOUNDARY_AUDIT_COMPLETE: 0 violations</promise>`
   - Stop.
5. Take the **first** violation where `status == "open"`. Call it `V`.
6. Read the source files involved: `V.caller_module` and `V.callee_module`.
7. Classify `V`:

   **CONFIRMED_BUG** — the caller imports a symbol that genuinely doesn't exist in the callee (renamed, deleted, never created). Fix: update the caller to use the correct symbol name. If the symbol was renamed, find the new name in the callee's exports. If deleted, remove or replace the call.

   **CONFIRMED_CLEAN** — false positive (dynamic dispatch, `__all__` export, conditional definition, or other legitimate pattern the static scanner can't resolve). Fix: mark status `confirmed_clean`. Do not change source.

   **NEEDS_FIX** — callee was refactored and caller wasn't updated. Fix: update the caller.

8. Apply exactly ONE fix. Do not fix multiple violations in one iteration.
9. Update `V.status` in `.xf/boundary_violations.json`:
   - Set to `"fixed"` if you changed source code
   - Set to `"confirmed_clean"` if it was a false positive
10. Update `total_violations` to reflect current open count.
11. Report: `Fixed [V.id]: [V.type] — [V.symbol] in [V.caller_module]:[V.caller_line]. Remaining: REMAINING-1 open violations.`
12. Loop back to step 1.

---

### Causal chain rule

One fix per iteration. If two fixes interact and the re-scan still shows violations, it must be clear which fix introduced the new state. Clean causal chain = debuggable loop.

---

### Completion promise

When `REMAINING == 0`:
```
<promise>BOUNDARY_AUDIT_COMPLETE: 0 violations</promise>
```

When stuck:
```
<promise>BOUNDARY_AUDIT_STUCK: N violations remain. Manual review required.</promise>
```

---

### Quick reference

| Command | Behavior |
|---------|----------|
| `/xf-audit` | Run scanner + Ralph Loop to 0 violations |
| `/xf-audit --report-only` | Run scanner, show violations, no fixes |
