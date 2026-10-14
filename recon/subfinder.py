"""Optional passive hostname enumeration through ProjectDiscovery Subfinder.

This module never probes discovered hosts. Only hostnames inside the requested root
domain are returned; selecting them for an active crawl remains a separate user action.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from urllib.parse import urlparse

HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
MAX_OUTPUT_BYTES = 2 * 1024 * 1024


def discover_subdomains(target: str, timeout: int = 90, should_stop=None, on_log=None) -> dict:
    """Run Subfinder in passive mode; return validated, in-scope hostnames and status."""
    parsed = urlparse((target or "").strip())
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("target must be a full HTTP(S) URL")
    root = parsed.hostname.lower().rstrip(".").encode("idna").decode("ascii")
    log = on_log or (lambda _message: None)
    stop = should_stop or (lambda: False)
    executable = shutil.which("subfinder")
    if not executable:
        log("[Subfinder] Not installed/on PATH; passive Subfinder phase skipped.")
        return {"subfinder_subdomains": [], "subfinder_status": "not-installed", "subfinder_error": ""}
    if stop():
        return {"subfinder_subdomains": [], "subfinder_status": "stopped", "subfinder_error": ""}

    command = [executable, "-silent", "-d", root]
    try:
        completed = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=max(5, min(int(timeout), 300)),
            check=False, shell=False,
        )
    except subprocess.TimeoutExpired:
        log(f"[Subfinder] Timed out after {max(5, min(int(timeout), 300))} seconds.")
        return {"subfinder_subdomains": [], "subfinder_status": "timeout", "subfinder_error": "timeout"}
    except OSError as exc:
        message = f"{type(exc).__name__}: {exc}"
        log(f"[Subfinder] Could not start: {message}")
        return {"subfinder_subdomains": [], "subfinder_status": "error", "subfinder_error": message}

    raw = completed.stdout[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
    found = set()
    for line in raw.splitlines():
        host = line.strip().lower().rstrip(".")
        if not host:
            continue
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            continue
        if HOST_RE.fullmatch(host) and (host == root or host.endswith("." + root)):
            found.add(host)

    if completed.returncode not in (0, None):
        stderr = completed.stderr[:4096].decode("utf-8", errors="replace").strip()
        error = stderr or f"Subfinder exited with code {completed.returncode}"
        status = "partial" if found else "error"
        log(f"[Subfinder] {error}")
    else:
        error, status = "", "queried"
    hosts = sorted(found)
    log(f"[Subfinder] Passive sources returned {len(hosts)} in-scope hostnames; no hosts were actively probed.")
    return {
        "subfinder_subdomains": hosts,
        "subfinder_status": status,
        "subfinder_error": error,
    }
