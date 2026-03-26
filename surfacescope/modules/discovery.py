from __future__ import annotations

import requests


CRT_URL = "https://crt.sh/"


def discover_subdomains(domain: str, timeout: int = 15) -> list[str]:
    params = {"q": f"%.{domain}", "output": "json"}
    try:
        response = requests.get(CRT_URL, params=params, timeout=timeout)
        response.raise_for_status()
        rows = response.json()
    except Exception:
        return []

    results: set[str] = set()
    for row in rows:
        value = row.get("name_value", "")
        for item in value.splitlines():
            item = item.strip().lstrip("*.")
            if item.endswith(domain):
                results.add(item)
    return sorted(results)
