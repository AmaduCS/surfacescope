from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from surfacescope.modules.dns_tools import collect_dns
from surfacescope.modules.http_probe import probe_http
from surfacescope.modules.pipeline import run_pipeline
from surfacescope.modules.reporting import write_reports
from surfacescope.modules.scoring import score_target
from surfacescope.utils import ensure_dir, load_json

console = Console()


def _show_summary(records: list[dict]) -> None:
    table = Table(title="SurfaceScope Summary")
    table.add_column("Target")
    table.add_column("Severity")
    table.add_column("Score")
    table.add_column("URL")
    table.add_column("Open Ports")
    for record in records:
        table.add_row(
            record["target"],
            record["severity"],
            str(record["score"]),
            record.get("http", {}).get("url", "") or "n/a",
            ", ".join(str(p["port"]) for p in record.get("ports", [])) or "none",
        )
    console.print(table)


@click.group()
def main() -> None:
    """SurfaceScope CLI."""


@main.command()
@click.option("--target", required=False, help="Authorized domain or host to inspect.")
@click.option("--output-dir", default="outputs/run", show_default=True)
@click.option("--ports", default="80,443,8080,8443,22,3306,5432,6379,3389", show_default=True)
@click.option("--skip-port-scan", is_flag=True, help="Skip TCP port scan stage.")
@click.option("--resume", is_flag=True, help="Reuse cached stage output if present.")
@click.option("--include-subdomains", is_flag=True, help="Attempt certificate-transparency subdomain discovery.")
@click.option("--demo", is_flag=True, help="Run offline demo data instead of real probing.")
def run(target: str | None, output_dir: str, ports: str, skip_port_scan: bool, resume: bool, include_subdomains: bool, demo: bool) -> None:
    if not target and not demo:
        raise click.UsageError("Provide --target for a real run or use --demo.")
    records = run_pipeline(
        target=target or "demo",
        output_dir=output_dir,
        ports=ports,
        skip_port_scan=skip_port_scan,
        resume=resume,
        include_subdomains=include_subdomains,
        demo=demo,
    )
    _show_summary(records)
    console.print(f"[green]Reports written to[/green] {output_dir}")


@main.command()
@click.option("--target", required=True)
def dns(target: str) -> None:
    console.print_json(data=collect_dns(target))


@main.command()
@click.option("--target", required=True)
def http(target: str) -> None:
    console.print_json(data=probe_http(target))


@main.command()
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--output-dir", default="outputs/report", show_default=True)
def report(input_path: Path, output_dir: str) -> None:
    records = load_json(input_path, [])
    normalized = []
    for record in records:
        score, findings, severity = score_target(record)
        record["score"] = score
        record["findings"] = findings
        record["severity"] = severity
        normalized.append(record)
    ensure_dir(output_dir)
    write_reports(output_dir, normalized)
    console.print(f"[green]Generated reports in[/green] {output_dir}")


if __name__ == "__main__":
    main()
