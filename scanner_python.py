from __future__ import annotations

import ast
import os
from typing import Optional, List, Dict, Any

from scanner_base import ScannerBase, SymbolTable


class _CallCollector(ast.NodeVisitor):
    def __init__(self):
        self.calls: List[Dict[str, Any]] = []

    def visit_Call(self, node: ast.Call):
        # MVP: only enforce existence for *bare* names (ast.Name).
        # Attribute calls (obj.method) are too dynamic for the existence check.
        if isinstance(node.func, ast.Name):
            self.calls.append({
                "symbol": node.func.id,
                "line": getattr(node, "lineno", None),
                "kind": "name",
            })
        elif isinstance(node.func, ast.Attribute):
            self.calls.append({
                "symbol": node.func.attr,
                "line": getattr(node, "lineno", None),
                "kind": "attr",
            })
        self.generic_visit(node)


class PythonScanner(ScannerBase):
    def supports(self, path: str) -> bool:
        return path.endswith(".py") and os.path.isfile(path)

    def scan(self, path: str) -> Optional[SymbolTable]:
        try:
            src = open(path, "r", encoding="utf-8").read()
            tree = ast.parse(src, filename=path)
        except Exception:
            return None

        module_name = os.path.splitext(os.path.basename(path))[0]
        st = SymbolTable(module_name=module_name, path=path)

        # Top-level exports only (functions/classes defined at module level)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                st.exports.append(node.name)

        # All imports at any nesting level — catches imports inside function bodies,
        # test methods, conditionals, etc.
        # Dispatch uses this pattern extensively: from X import Y inside test methods
        # and inline python3 -c blocks. ast.walk covers every node in the tree.
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    st.imports.append(alias.name)
                    st.imported_symbols.append(alias.asname or alias.name.split(".")[-1])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    st.imports.append(node.module)
                for alias in node.names:
                    st.imported_symbols.append(alias.asname or alias.name)
                    st.from_imports.append({
                        "module": node.module,
                        "name": alias.name,
                        "asname": alias.asname,
                        "line": getattr(node, "lineno", None),
                    })

        cc = _CallCollector()
        cc.visit(tree)
        st.calls = cc.calls

        return st
