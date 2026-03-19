from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, Any, List

from flow_analyzer import build_index


AUDIT_TOOLS = {"Edit", "Write"}


def _ensure_xf_dir(root: str) -> str:
    p = os.path.join(root, ".xf")
    os.makedirs(p, exist_ok=True)
    return p


def _write_json(path: str, obj: Dict[str, Any]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)


def _find_unresolved_calls(root: str, index: Dict[str, Any]) -> List[Dict[str, Any]]:
    # MVP: existence only. We approximate existence by checking whether a called symbol
    # exists as an export in *any* scanned module.
    all_exports = set()
    for info in index.get("modules", {}).values():
        for sym in info.get("exports", []):
            all_exports.add(sym)

    from scanner_registry import scan_file

    import builtins

    builtin_names = set(dir(builtins))

    violations = []
    vid = 1
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", ".xf", ".venv", "venv", "__pycache__", "node_modules"}]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dirpath, fn)
            st = scan_file(path)
            if not st:
                continue
            imported = set(st.imported_symbols or [])
            for c in st.calls:
                sym = c.get("symbol")
                line = c.get("line")
                kind = c.get("kind")
                if kind != "name":
                    continue
                if not sym or sym in all_exports:
                    continue
                # ignore imported names and common builtins to reduce noise
                if sym in imported:
                    continue
                if sym in builtin_names:
                    continue
                violations.append({
                    "id": f"v{vid:03d}",
                    "type": "interface_existence",
                    "severity": "error",
                    "caller_module": os.path.relpath(path, root),
                    "caller_line": line or 0,
                    "callee_module": "<unknown>",
                    "symbol": sym,
                    "detail": f"Symbol '{sym}' is called but was not found in any scanned module exports.",
                    "status": "open",
                })
                vid += 1

    return violations


def _format_report(violations: List[Dict[str, Any]]) -> str:
    lines = ["[XF Boundary Auditor] Boundary violations detected (interface existence):", ""]
    for v in violations[:20]:
        lines.append(f"- {v['caller_module']}:{v['caller_line']} calls missing symbol '{v['symbol']}'")
    if len(violations) > 20:
        lines.append(f"…and {len(violations)-20} more")
    lines.append("")
    lines.append("Blocked Edit/Write to prevent shipping broken boundaries.")
    lines.append("Run /xf-audit (default) to repair to 0, or /xf-audit --report-only to inspect.")
    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) < 2:
        return 0

    raw = sys.argv[1]
    try:
        hook_input = json.loads(raw)
    except Exception:
        # hook.sh should pass the full JSON string; if parse fails, do not block
        return 0

    tool_name = hook_input.get("tool_name", "")
    if tool_name not in AUDIT_TOOLS:
        return 0

    root = os.getcwd()
    xf_dir = _ensure_xf_dir(root)

    index = build_index(root)
    idx_obj = {
        "schema_version": "1.0",
        "last_scanned": datetime.now(timezone.utc).isoformat(),
        "modules": index.get("modules", {}),
        "callers": index.get("callers", []),
    }
    _write_json(os.path.join(xf_dir, "boundary_index.json"), idx_obj)

    violations = _find_unresolved_calls(root, index)

    vio_obj = {
        "schema_version": "1.0",
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "cwd": root,
        "total_violations": len(violations),
        "violations": violations,
        "checked_items": [],
        "ralph_iteration": 0,
    }
    _write_json(os.path.join(xf_dir, "boundary_violations.json"), vio_obj)

    if violations:
        sys.stdout.write(_format_report(violations))
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
