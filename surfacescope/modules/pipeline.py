from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.console import Console

from surfacescope.models import TargetRecord
from surfacescope.modules.discovery import discover_subdomains
from surfacescope.modules.dns_tools import collect_dns
from surfacescope.modules.http_probe import probe_http
from surfacescope.modules.portscan import scan_ports
from surfacescope.modules.reporting import write_reports
from surfacescope.modules.scoring import score_target
from surfacescope.modules.tls_tools import inspect_tls
from surfacescope.utils import ensure_dir, load_json, save_json

console = Console()


DEMO_RECORDS = [
    {
        "target": "demo.example.internal",
        "dns": {"A": ["198.51.100.10"], "MX": ["mail.example.internal"]},
        "resolved_ips": ["198.51.100.10"],
        "http": {
            "url": "http://demo.example.internal",
            "scheme": "http",
            "status_code": 200,
            "title": "Admin Login",
            "headers": {"server": "nginx"},
            "missing_security_headers": ["content-security-policy", "x-frame-options", "referrer-policy"],
            "tech": ["nginx"],
            "likely_login": True,
            "redirect_chain": ["http://demo.example.internal"],
            "favicon_hash": "demo123",
        },
        "tls": {"enabled": False, "error": "demo mode"},
        "ports": [
            {"port": 22, "service": "ssh", "state": "open"},
            {"port": 80, "service": "http", "state": "open"},
            {"port": 3306, "service": "mysql", "state": "open"},
        ],
    }
]


def _parse_ports(raw: str) -> list[int]:
    ports = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        ports.append(int(part))
    return sorted(set(ports))


def run_pipeline(
    target: str,
    output_dir: str,
    ports: str = "80,443,8080,8443,22,3306,5432,6379,3389",
    skip_port_scan: bool = False,
    resume: bool = False,
    include_subdomains: bool = False,
    demo: bool = False,
) -> list[dict[str, Any]]:
    out = ensure_dir(output_dir)

    if demo:
        records = []
        for seed in DEMO_RECORDS:
            model = TargetRecord(**seed)
            score, findings, severity = score_target(model.to_dict())
            model.score = score
            model.findings = findings
            model.severity = severity
            records.append(model.to_dict())
        write_reports(out, records)
        save_json(Path(out) / "dns_inventory.json", [{"target": r["target"], "dns": r["dns"], "resolved_ips": r["resolved_ips"]} for r in records])
        save_json(Path(out) / "http_inventory.json", [{"target": r["target"], "http": r["http"]} for r in records])
        save_json(Path(out) / "tls_inventory.json", [{"target": r["target"], "tls": r["tls"]} for r in records])
        save_json(Path(out) / "port_inventory.json", [{"target": r["target"], "ports": r["ports"]} for r in records])
        return records

    targets = [target]
    if include_subdomains:
        discovered = discover_subdomains(target)
        targets = sorted(set(targets + discovered))

    parsed_ports = _parse_ports(ports)

    dns_cache_path = Path(out) / "dns_inventory.json"
    http_cache_path = Path(out) / "http_inventory.json"
    tls_cache_path = Path(out) / "tls_inventory.json"
    port_cache_path = Path(out) / "port_inventory.json"

    dns_cache = {item["target"]: item for item in (load_json(dns_cache_path, []) if resume else [])}
    http_cache = {item["target"]: item for item in (load_json(http_cache_path, []) if resume else [])}
    tls_cache = {item["target"]: item for item in (load_json(tls_cache_path, []) if resume else [])}
    port_cache = {item["target"]: item for item in (load_json(port_cache_path, []) if resume else [])}

    records: list[dict[str, Any]] = []
    dns_inventory = []
    http_inventory = []
    tls_inventory = []
    port_inventory = []

    for item in targets:
        console.print(f"[cyan]Processing[/cyan] {item}")
        dns_payload = dns_cache.get(item) or collect_dns(item)
        dns_inventory.append(dns_payload)

        http_payload = http_cache.get(item) or {"target": item, "http": probe_http(item)}
        http_inventory.append(http_payload)

        tls_payload = tls_cache.get(item) or {"target": item, "tls": inspect_tls(item)}
        tls_inventory.append(tls_payload)

        resolved_ips = dns_payload.get("resolved_ips", [])
        primary_ip = next((ip for ip in resolved_ips if ":" not in ip), item)
        ports_payload = port_cache.get(item) or {
            "target": item,
            "ports": [] if skip_port_scan else scan_ports(primary_ip, parsed_ports),
        }
        port_inventory.append(ports_payload)

        record = TargetRecord(
            target=item,
            resolved_ips=dns_payload.get("resolved_ips", []),
            dns=dns_payload.get("dns", {}),
            http=http_payload.get("http", {}),
            tls=tls_payload.get("tls", {}),
            ports=ports_payload.get("ports", []),
        )
        score, findings, severity = score_target(record.to_dict())
        record.score = score
        record.findings = findings
        record.severity = severity
        records.append(record.to_dict())

    save_json(dns_cache_path, dns_inventory)
    save_json(http_cache_path, http_inventory)
    save_json(tls_cache_path, tls_inventory)
    save_json(port_cache_path, port_inventory)
    write_reports(out, records)
    return records
