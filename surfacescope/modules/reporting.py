from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from surfacescope.utils import save_csv, save_json


def write_reports(output_dir: str | Path, records: list[dict[str, Any]]) -> None:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).isoformat()

    save_json(output_path / "final_results.json", records)

    csv_rows = []
    for record in records:
        csv_rows.append(
            {
                "target": record["target"],
                "severity": record["severity"],
                "score": record["score"],
                "resolved_ips": ", ".join(record.get("resolved_ips", [])),
                "url": record.get("http", {}).get("url", ""),
                "open_ports": ", ".join(str(p["port"]) for p in record.get("ports", [])),
                "findings": " | ".join(record.get("findings", [])),
            }
        )
    save_csv(output_path / "findings.csv", csv_rows)

    md_lines = [
        "# SurfaceScope Report",
        "",
        f"Generated: `{generated_at}`",
        "",
    ]
    for record in records:
        md_lines.extend(
            [
                f"## {record['target']}",
                f"- Severity: **{record['severity']}**",
                f"- Score: **{record['score']}**",
                f"- Resolved IPs: `{', '.join(record.get('resolved_ips', [])) or 'n/a'}`",
                f"- URL: `{record.get('http', {}).get('url', '') or 'n/a'}`",
                f"- Open ports: `{', '.join(str(p['port']) for p in record.get('ports', [])) or 'none'}`",
                "- Findings:",
            ]
        )
        findings = record.get("findings", []) or ["No notable findings"]
        md_lines.extend([f"  - {item}" for item in findings])
        md_lines.append("")
    (output_path / "report.md").write_text("\n".join(md_lines), encoding="utf-8")

    env = Environment(
        loader=FileSystemLoader(str(Path(__file__).resolve().parents[1] / "templates")),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.j2")
    html = template.render(records=records, generated_at=generated_at)
    (output_path / "report.html").write_text(html, encoding="utf-8")
