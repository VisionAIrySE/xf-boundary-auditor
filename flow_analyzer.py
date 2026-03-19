from __future__ import annotations

import os
from dataclasses import asdict
from typing import Dict, List, Tuple, Any

from scanner_registry import scan_file


def _iter_source_files(root: str) -> List[str]:
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # prune common junk
        dirnames[:] = [d for d in dirnames if d not in {".git", ".worktrees", ".xf", ".venv", "venv", "__pycache__", "node_modules"}]
        for fn in filenames:
            if fn.endswith(".py"):
                out.append(os.path.join(dirpath, fn))
    return out


def build_index(root: str) -> Dict[str, Any]:
    """Single-pass scan of the repo.

    Returns:
      - modules: module_name -> {path, exports, imports, ...}
      - callers: best-effort resolved call edges (not used for MVP enforcement)
      - from_imports: list of {caller_module, caller_line, callee_module, symbol}
    """
    modules: Dict[str, Any] = {}
    callers: List[Dict[str, Any]] = []
    from_imports: List[Dict[str, Any]] = []

    symbol_tables = []
    for path in _iter_source_files(root):
        st = scan_file(path)
        if not st:
            continue
        symbol_tables.append(st)
        modules[st.module_name] = {
            "path": os.path.relpath(st.path, root),
            "exports": sorted(set(st.exports)),
            "imports": sorted(set(st.imports)),
            "state_writes": st.state_writes,
            "env_vars_read": st.env_vars_read,
        }

        # capture from-imports (needed for MVP existence enforcement)
        for imp in getattr(st, "from_imports", []) or []:
            mod = (imp.get("module") or "").split(".")[-1]
            name = imp.get("name")
            line = imp.get("line") or 0
            if not mod or not name or name == "*":
                continue
            from_imports.append({
                "caller_module": os.path.relpath(path, root),
                "caller_line": line,
                "callee_module": mod,
                "symbol": name,
            })

    # optional: resolved call edges
    export_to_module: Dict[str, str] = {}
    for m, info in modules.items():
        for sym in info.get("exports", []):
            export_to_module.setdefault(sym, m)

    for st in symbol_tables:
        for c in st.calls:
            if c.get("kind") != "name":
                continue
            sym = c.get("symbol")
            if not sym:
                continue
            callee_module = export_to_module.get(sym)
            if callee_module:
                callers.append({
                    "caller": os.path.relpath(st.path, root),
                    "callee_module": callee_module,
                    "symbol": sym,
                    "line": c.get("line"),
                })

    return {"modules": modules, "callers": callers, "from_imports": from_imports}


def from_import_existence_violations(index: Dict[str, Any]) -> List[Dict[str, Any]]:
    """MVP high-signal check: local `from X import Y` must match X's exports."""
    modules = index.get("modules", {})
    exports_by_module = {m: set(info.get("exports", [])) for m, info in modules.items()}

    violations: List[Dict[str, Any]] = []
    vid = 1

    for edge in index.get("from_imports", []) or []:
        callee = edge.get("callee_module")
        sym = edge.get("symbol")
        if not callee or not sym:
            continue
        if callee not in exports_by_module:
            # out of repo scope
            continue
        if sym in exports_by_module[callee]:
            continue

        violations.append({
            "id": f"v{vid:03d}",
            "type": "interface_existence",
            "severity": "error",
            "caller_module": edge.get("caller_module"),
            "caller_line": edge.get("caller_line") or 0,
            "callee_module": callee,
            "symbol": sym,
            "detail": f"from {callee} import {sym} — symbol does not exist in local module exports.",
            "status": "open",
        })
        vid += 1

    return violations
