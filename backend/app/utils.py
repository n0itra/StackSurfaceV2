from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse


def normalize_input(value: str) -> tuple[str, str]:
    raw = value.strip()
    if not raw:
        raise ValueError("Empty target input")
    candidate = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else f"https://{raw}"
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    if not host or ":" in host and host.count(":") > 1:
        raise ValueError(f"Unsupported target: {value}")
    scheme = parsed.scheme.lower() if parsed.scheme in {"http", "https"} else "https"
    port = parsed.port
    netloc = host + (f":{port}" if port else "")
    path = parsed.path or "/"
    normalized = urlunparse((scheme, netloc, path, "", parsed.query, ""))
    return host, normalized


def in_scope(name: str, root: str) -> bool:
    name = name.lower().rstrip(".")
    root = root.lower().rstrip(".")
    return name == root or name.endswith("." + root)


def clean_host_lines(text: str, root: str) -> list[str]:
    values = set()
    for line in text.splitlines():
        candidate = line.strip().lower().rstrip(".")
        if not candidate or candidate.startswith("#"):
            continue
        candidate = candidate.replace("*.", "", 1)
        if in_scope(candidate, root):
            values.add(candidate)
    return sorted(values)


def mask_secret(value: str | None) -> str | None:
    if not value:
        return value
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * max(4, len(value) - 8) + value[-4:]
