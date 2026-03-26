from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from surfacescope.utils import simple_favicon_hash

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]

TECH_MARKERS = {
    "wordpress": ["wp-content", "wordpress"],
    "nginx": ["server: nginx"],
    "apache": ["server: apache"],
    "cloudflare": ["cf-ray", "cloudflare"],
    "bootstrap": ["bootstrap"],
}


def _detect_tech(text: str) -> list[str]:
    lowered = text.lower()
    hits: list[str] = []
    for name, markers in TECH_MARKERS.items():
        if any(marker in lowered for marker in markers):
            hits.append(name)
    return sorted(set(hits))


def _extract_title(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    return soup.title.get_text(strip=True) if soup.title else ""


def probe_http(target: str, timeout: int = 8) -> dict[str, Any]:
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
            headers = {k.lower(): v for k, v in response.headers.items()}
            body = response.text[:50000]
            title = _extract_title(body)
            favicon_hash = ""
            favicon_url = urljoin(str(response.url), "/favicon.ico")
            try:
                favicon_response = requests.get(favicon_url, timeout=timeout, verify=False)
                if favicon_response.ok and favicon_response.content:
                    favicon_hash = simple_favicon_hash(favicon_response.content)
            except Exception:
                favicon_hash = ""

            missing_headers = [header for header in SECURITY_HEADERS if header not in headers]
            redirect_chain = [item.url for item in response.history] + [str(response.url)]
            likely_login = bool(re.search(r"login|sign in|admin|dashboard", f"{title} {body[:2000]}", re.I))
            tech = _detect_tech("\n".join([body, "\n".join(f"{k}: {v}" for k, v in headers.items())]))
            return {
                "url": str(response.url),
                "scheme": scheme,
                "status_code": response.status_code,
                "title": title,
                "headers": headers,
                "server": headers.get("server", ""),
                "content_type": headers.get("content-type", ""),
                "redirect_chain": redirect_chain,
                "missing_security_headers": missing_headers,
                "tech": tech,
                "likely_login": likely_login,
                "favicon_hash": favicon_hash,
            }
        except Exception:
            continue
    return {"url": "", "error": "unreachable", "missing_security_headers": SECURITY_HEADERS.copy(), "tech": []}
