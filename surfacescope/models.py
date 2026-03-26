from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any


@dataclass
class TargetRecord:
    target: str
    resolved_ips: list[str] = field(default_factory=list)
    dns: dict[str, list[str]] = field(default_factory=dict)
    http: dict[str, Any] = field(default_factory=dict)
    tls: dict[str, Any] = field(default_factory=dict)
    ports: list[dict[str, Any]] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    score: int = 0
    severity: str = "info"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
