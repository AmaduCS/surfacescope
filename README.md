SurfaceScope is an original Python CLI for authorized attack-surface inventory, web fingerprinting, lightweight exposure scoring, and report generation.

It is designed for portfolio use, internal asset discovery, lab environments, and defensive security workflows. It does not include exploitation, payloads, or attack chaining.

Why this project stands out
Compared with a basic recon pipeline, SurfaceScope adds:

DNS enrichment (A, AAAA, CNAME, MX, NS, TXT)
optional certificate-transparency subdomain discovery
HTTP fingerprinting with redirect tracking and favicon hashing
TLS certificate inspection and expiry checks
lightweight TCP port scanning for common ports
simple exposure scoring with transparent reasons
JSON, CSV, Markdown, and HTML reporting
resume mode to skip completed stages
offline demo mode so you can test the full pipeline safely
unit tests for scoring and parsing helpers
Core workflow
Collect inventory targets
Enrich DNS data
Probe HTTP/HTTPS
Inspect TLS certificates
Optionally scan common TCP ports
Score exposures
Export reports
Safety
Use SurfaceScope only on systems you own or have explicit written permission to assess.

Installation
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
Quick start
Offline demo run
This exercises the full pipeline without touching external infrastructure.

surfacescope run --demo --output-dir outputs/demo
Real authorized target
surfacescope run --target example.com --ports 80,443,8080 --output-dir outputs/example
Skip port scanning
surfacescope run --target example.com --skip-port-scan
Resume a previous run
surfacescope run --target example.com --output-dir outputs/example --resume
Commands
Run full pipeline
surfacescope run --target example.com
DNS-only enrichment
surfacescope dns --target example.com
HTTP-only fingerprinting
surfacescope http --target example.com
Generate reports from an existing JSON file
surfacescope report --input outputs/example/final_results.json --output-dir outputs/example
Output files
A run produces:

dns_inventory.json
http_inventory.json
tls_inventory.json
port_inventory.json
final_results.json
findings.csv
report.md
report.html
How scoring works
SurfaceScope uses a transparent rules-based score. It adds points for patterns such as:

exposed admin or database ports
missing security headers
HTTP without redirect to HTTPS
expiring or invalid TLS certificates
publicly exposed login panels or admin-like paths in titles/headers
This is not a vulnerability scanner. It is a triage aid.

Tests
pytest
Example portfolio talking points
clean CLI UX with click and rich
modular code with separate collectors and reporters
offline demo mode for safe validation
reproducible report generation for GitHub screenshots
test coverage for core logic
Publish checklist
Before pushing to GitHub, update any repository links, badges, and screenshots you want to include.

License
MIT