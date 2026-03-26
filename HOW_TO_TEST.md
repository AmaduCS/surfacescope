# How to Test SurfaceScope

## 1. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 2. Install the project

```bash
pip install -e .
```

## 3. Run unit tests

```bash
pytest
```

## 4. Run the safe offline demo

```bash
surfacescope run --demo --output-dir outputs/demo
```

This should create:

- `outputs/demo/final_results.json`
- `outputs/demo/findings.csv`
- `outputs/demo/report.md`
- `outputs/demo/report.html`

## 5. Try a real authorized target

Only do this on assets you own or are explicitly authorized to assess.

```bash
surfacescope run --target example.com --output-dir outputs/example
```

## 6. Re-run with cache reuse

```bash
surfacescope run --target example.com --output-dir outputs/example --resume
```

## 7. DNS and HTTP subcommands

```bash
surfacescope dns --target example.com
surfacescope http --target example.com
```
