from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any

COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
}


def _scan_one(host: str, port: int, timeout: float) -> dict[str, Any] | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            return {"port": port, "service": COMMON_PORTS.get(port, "unknown"), "state": "open"}
    except Exception:
        return None
    finally:
        sock.close()
    return None


def scan_ports(host: str, ports: list[int], timeout: float = 0.7, workers: int = 50) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_scan_one, host, port, timeout) for port in ports]
        for future in futures:
            result = future.result()
            if result:
                findings.append(result)
    return sorted(findings, key=lambda x: x["port"])
