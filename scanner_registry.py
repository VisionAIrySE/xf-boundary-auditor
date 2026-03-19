from __future__ import annotations

from typing import Optional

from scanner_base import SymbolTable
from scanner_python import PythonScanner


SCANNERS = [PythonScanner()]


def scan_file(path: str) -> Optional[SymbolTable]:
    for s in SCANNERS:
        if s.supports(path):
            return s.scan(path)
    return None
