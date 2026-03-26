from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any


def inspect_tls(hostname: str, port: int = 443, timeout: int = 5) -> dict[str, Any]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
    except Exception as exc:
        return {"enabled": False, "error": str(exc)}

    not_after = cert.get("notAfter")
    expires_in_days = None
    if not_after:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        expires_in_days = (expiry - datetime.now(timezone.utc)).days

    subject = dict(item[0] for item in cert.get("subject", [])) if cert.get("subject") else {}
    issuer = dict(item[0] for item in cert.get("issuer", [])) if cert.get("issuer") else {}
    sans = [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"]
    return {
        "enabled": True,
        "subject": subject,
        "issuer": issuer,
        "sans": sans,
        "not_after": not_after,
        "expires_in_days": expires_in_days,
    }
