from __future__ import annotations

import socket
from typing import Any

import dns.resolver


def collect_dns(target: str) -> dict[str, Any]:
    resolver = dns.resolver.Resolver()
    records: dict[str, list[str]] = {}
    for rtype in ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]:
        try:
            answers = resolver.resolve(target, rtype)
            values = []
            for item in answers:
                if rtype == "MX":
                    values.append(str(item.exchange).rstrip("."))
                else:
                    values.append(str(item).strip('"').rstrip("."))
            if values:
                records[rtype] = sorted(set(values))
        except Exception:
            continue

    resolved_ips: list[str] = []
    try:
        for _, _, _, _, sockaddr in socket.getaddrinfo(target, None):
            host = sockaddr[0]
            if host not in resolved_ips:
                resolved_ips.append(host)
    except Exception:
        pass

    return {"target": target, "dns": records, "resolved_ips": resolved_ips}
