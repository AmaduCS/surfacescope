from __future__ import annotations

from typing import Any

ADMIN_PORTS = {21, 22, 3306, 3389, 5432, 6379}


def severity_from_score(score: int) -> str:
    if score >= 8:
        return "high"
    if score >= 4:
        return "medium"
    if score >= 1:
        return "low"
    return "info"


def score_target(record: dict[str, Any]) -> tuple[int, list[str], str]:
    score = 0
    reasons: list[str] = []

    http = record.get("http", {}) or {}
    tls = record.get("tls", {}) or {}
    ports = record.get("ports", []) or []

    missing = http.get("missing_security_headers", [])
    if len(missing) >= 3:
        score += 2
        reasons.append("Missing multiple web security headers")

    if http.get("scheme") == "http":
        score += 2
        reasons.append("HTTP exposed without HTTPS preference")

    if http.get("likely_login"):
        score += 2
        reasons.append("Login or admin-like page detected")

    for port in ports:
        if port.get("port") in ADMIN_PORTS:
            score += 2
            reasons.append(f"Sensitive service exposed on port {port.get('port')}")

    expires = tls.get("expires_in_days")
    if isinstance(expires, int):
        if expires < 0:
            score += 3
            reasons.append("TLS certificate appears expired")
        elif expires <= 30:
            score += 2
            reasons.append("TLS certificate expires within 30 days")

    if tls.get("enabled") is False and http.get("url", "").startswith("https"):
        score += 1
        reasons.append("HTTPS expected but TLS inspection failed")

    severity = severity_from_score(score)
    return score, reasons, severity
