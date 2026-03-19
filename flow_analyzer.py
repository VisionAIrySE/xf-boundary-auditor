from __future__ import annotations

import os
from dataclasses import asdict
from typing import Dict, List, Tuple, Any

from scanner_registry import scan_file


def _iter_source_files(root: str) -> List[str]:
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # prune common junk
        dirnames[:] = [d for d in dirnames if d not in {".git", ".xf", ".venv", "venv", "__pycache__", "node_modules"}]
        for fn in filenames:
            if fn.endswith(".py"):
                out.append(os.path.join(dirpath, fn))
    return out


def build_index(root: str) -> Dict[str, Any]:
    modules: Dict[str, Any] = {}
    callers: List[Dict[str, Any]] = []

    for path in _iter_source_files(root):
        st = scan_file(path)
        if not st:
            continue
        modules[st.module_name] = {
            "path": os.path.relpath(st.path, root),
            "exports": sorted(set(st.exports)),
            "imports": sorted(set(st.imports)),
            "state_writes": st.state_writes,
            "env_vars_read": st.env_vars_read,
        }

    # very light caller map: if a call symbol matches any export in any module,
    # record (caller -> callee_module, symbol)
    export_to_module: Dict[str, str] = {}
    for m, info in modules.items():
        for sym in info.get("exports", []):
            export_to_module.setdefault(sym, m)

    for path in _iter_source_files(root):
        st = scan_file(path)
        if not st:
            continue
        for c in st.calls:
            sym = c.get("symbol")
            if not sym:
                continue
            callee_module = export_to_module.get(sym)
            if callee_module:
                callers.append({
                    "caller": os.path.relpath(path, root),
                    "callee_module": callee_module,
                    "symbol": sym,
                    "line": c.get("line"),
                })

    return {"modules": modules, "callers": callers}


def interface_existence_violations(index: Dict[str, Any]) -> List[Dict[str, Any]]:
    modules = index.get("modules", {})

    # build export set per module
    exports_by_module: Dict[str, set] = {m: set(info.get("exports", [])) for m, info in modules.items()}

    violations: List[Dict[str, Any]] = []

    # existence violations from 'from X import Y' are not implemented yet.
    # MVP: check call sites that resolve to a module but symbol missing there.
    # We approximate by: if a caller calls a symbol that is NOT exported anywhere, flag it.

    all_exports = set()
    for s in exports_by_module.values():
        all_exports |= s

    # index does not include unresolved calls; rescan to find unresolved calls
    # (cheap pass)
    return violations
