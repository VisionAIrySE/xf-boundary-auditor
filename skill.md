---
name: xf-audit
description: Boundary contract auditor. Maps interfaces in your codebase, detects caller/callee mismatches, and (by default) fixes them via Ralph Loop until 0 violations remain. Use --report-only for CI/review.
---

Fix all boundary violations (default; runs Ralph Loop to 0):
`/xf-audit`

Report only (no fixes applied):
`/xf-audit --report-only`

Audit specific path:
`/xf-audit path/to/module.py`
