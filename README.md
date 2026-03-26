# SurfaceScope

**SurfaceScope** is a Python-based CLI tool for **authorized** attack-surface inventory, web fingerprinting, lightweight exposure scoring, and report generation.

I built this project to strengthen my hands-on skills in cybersecurity, Python automation, service discovery, HTTP/TLS analysis, and security reporting. It is designed for portfolio use, internal asset discovery, lab environments, and defensive security workflows.

SurfaceScope does **not** include exploitation, payloads, or attack chaining. Its purpose is to help identify what an internet-facing asset is exposing, enrich the findings with useful technical context, and generate structured outputs for triage and documentation.

---

## Why I built this

I wanted to create a practical security engineering project that combines:

- Python development
- CLI design
- attack surface discovery
- HTTP and TLS inspection
- basic exposure prioritization
- structured reporting

Rather than building a single-purpose script, I wanted to build a tool that reflects a real security workflow: collect, inspect, enrich, score, and report.

---

## What this project demonstrates

SurfaceScope highlights my ability to:

- build a modular Python CLI application
- work with DNS, HTTP, and TLS data
- automate external asset inspection workflows
- turn raw findings into structured reports
- design reusable security tooling
- write tests for core logic
- present technical results clearly

---

## Key features

SurfaceScope includes:

- DNS enrichment (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`)
- optional certificate-transparency subdomain discovery
- HTTP fingerprinting with redirect tracking and favicon hashing
- TLS certificate inspection and certificate expiry checks
- lightweight TCP port scanning for common ports
- transparent rules-based exposure scoring
- JSON, CSV, Markdown, and HTML reporting
- resume mode to skip completed stages
- **offline demo mode** for safe end-to-end testing
- unit tests for scoring and parsing helpers

---

## Why this project stands out

Compared with a basic recon or scanning script, SurfaceScope is designed as a more complete workflow.

It does not just collect raw data. It:

1. identifies externally visible services
2. enriches findings with DNS, HTTP, and TLS context
3. applies basic exposure scoring
4. exports results in multiple useful formats

This makes it more useful for defensive triage, reporting, and portfolio demonstration than a simple one-stage scanner.

---

## Core workflow

1. Collect inventory targets
2. Enrich DNS data
3. Probe HTTP/HTTPS services
4. Inspect TLS certificates
5. Optionally scan common TCP ports
6. Score exposures
7. Export reports

---

## Example use cases

SurfaceScope is suitable for:

- personal lab environments
- owned domains and infrastructure
- internal asset visibility exercises
- portfolio demonstrations
- safe demo runs for recruiters or interviewers
- basic exposure review before deeper manual testing

---

## Safety

Use SurfaceScope only on systems you own or have explicit written permission to assess.

This tool is intended for defensive, educational, and authorized security workflows only.

---

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .