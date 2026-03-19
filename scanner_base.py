from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class SymbolTable:
    module_name: str
    path: str
    exports: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)  # imported modules
    imported_symbols: List[str] = field(default_factory=list)  # names imported into module namespace
    calls: List[Dict[str, Any]] = field(default_factory=list)  # {symbol, line, kind}
    state_writes: List[str] = field(default_factory=list)
    state_reads: List[str] = field(default_factory=list)
    env_vars_read: List[str] = field(default_factory=list)


class ScannerBase(ABC):
    @abstractmethod
    def supports(self, path: str) -> bool:
        ...

    @abstractmethod
    def scan(self, path: str) -> Optional[SymbolTable]:
        ...
