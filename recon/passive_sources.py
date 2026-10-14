"""Bounded passive recon sources (Certificate Transparency and Wayback CDX)."""
from __future__ import annotations
from urllib.parse import urlparse
import shutil
import subprocess
import requests

USER_AGENT = "Recon-GUI/3.0 (passive research; authorized use)"
MAX_SUBDOMAINS = 500
MAX_HISTORICAL_URLS = 1000
MAX_SUBFINDER_HOSTS = 5000
MAX_SUBFINDER_OUTPUT_BYTES = 2 * 1024 * 1024


def collect_passive(target: str, timeout: int = 12, on_log=None, include_subfinder: bool = False) -> dict:
    """Query public passive indexes only; discovered hosts are never probed."""
    parsed = urlparse((target or "").strip())
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("target must be a valid HTTP(S) URL")
    root = parsed.hostname.lower().strip(".")
    log = on_log or (lambda _message: None)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json,text/plain,*/*"})
    subdomains, historical_urls, errors = set(), set(), []
    sources = []
    try:
        response = session.get("https://crt.sh/", params={"q": f"%.{root}", "output": "json"},
                               timeout=max(3, min(int(timeout), 20)))
        if response.status_code == 200:
            try:
                rows = response.json()
            except ValueError:
                rows = []
            for row in rows if isinstance(rows, list) else []:
                for name in str(row.get("name_value") or "").splitlines():
                    name = name.strip().lower().lstrip("*.").rstrip(".")
                    if name == root or name.endswith("." + root):
                        subdomains.add(name)
                    if len(subdomains) >= MAX_SUBDOMAINS:
                        break
                if len(subdomains) >= MAX_SUBDOMAINS:
                    break
            log(f"[Passive] Certificate Transparency returned {len(subdomains)} hostnames.")
            sources.append({"name": "crt.sh", "status": "queried", "count": len(subdomains)})
        else:
            errors.append(f"crt.sh HTTP {response.status_code}")
            sources.append({"name": "crt.sh", "status": "partial", "count": 0})
    except (requests.RequestException, ValueError) as exc:
        errors.append(f"crt.sh: {type(exc).__name__}: {exc}")
        sources.append({"name": "crt.sh", "status": "partial", "count": 0})
    try:
        response = session.get(
            "https://web.archive.org/cdx/search/cdx",
            params={"url": f"{root}/*", "output": "json", "fl": "original",
                    "filter": "statuscode:200", "collapse": "urlkey", "limit": str(MAX_HISTORICAL_URLS)},
            timeout=max(3, min(int(timeout), 20)))
        if response.status_code == 200:
            try:
                rows = response.json()
            except ValueError:
                rows = []
            for row in rows[1:] if isinstance(rows, list) and rows else []:
                value = row[0] if isinstance(row, list) and row else ""
                host = (urlparse(value).hostname or "").lower()
                if value.startswith(("http://", "https://")) and (host == root or host.endswith("." + root)):
                    historical_urls.add(value)
                if len(historical_urls) >= MAX_HISTORICAL_URLS:
                    break
            log(f"[Passive] Wayback returned {len(historical_urls)} historical URLs.")
            sources.append({"name": "Wayback CDX", "status": "queried", "count": len(historical_urls)})
        else:
            errors.append(f"Wayback CDX HTTP {response.status_code}")
            sources.append({"name": "Wayback CDX", "status": "partial", "count": 0})
    except (requests.RequestException, ValueError) as exc:
        errors.append(f"Wayback CDX: {type(exc).__name__}: {exc}")
        sources.append({"name": "Wayback CDX", "status": "partial", "count": 0})
    finally:
        session.close()

    if include_subfinder:
        executable = shutil.which("subfinder")
        if not executable:
            log("[Subfinder] Not installed / not on PATH; continuing with the other passive sources.")
            sources.append({"name": "Subfinder", "status": "not-installed", "count": 0})
        else:
            try:
                completed = subprocess.run(
                    [executable, "-silent", "-d", root],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=max(15, min(int(timeout) * 8, 120)), check=False, shell=False,
                )
                output = completed.stdout[:MAX_SUBFINDER_OUTPUT_BYTES].decode("utf-8", errors="replace")
                discovered = set()
                for line in output.splitlines():
                    hostname = line.strip().lower().rstrip(".")
                    if not hostname or len(hostname) > 253:
                        continue
                    try:
                        hostname = hostname.encode("idna").decode("ascii")
                    except UnicodeError:
                        continue
                    if hostname == root or hostname.endswith("." + root):
                        discovered.add(hostname)
                    if len(discovered) >= MAX_SUBFINDER_HOSTS:
                        break
                subdomains.update(discovered)
                status = "queried" if completed.returncode == 0 else "partial"
                sources.append({"name": "Subfinder", "status": status, "count": len(discovered)})
                log(f"[Subfinder] Collected {len(discovered)} in-scope passive hostnames (exit={completed.returncode}).")
                if completed.returncode != 0:
                    errors.append(f"Subfinder exited with status {completed.returncode}")
                if len(completed.stdout) > MAX_SUBFINDER_OUTPUT_BYTES:
                    errors.append(f"Subfinder output truncated at {MAX_SUBFINDER_OUTPUT_BYTES} bytes")
            except subprocess.TimeoutExpired:
                errors.append("Subfinder timed out; other passive results were retained")
                sources.append({"name": "Subfinder", "status": "timeout", "count": 0})
                log("[Subfinder] Timed out; passive scan continues with results already collected.")
            except OSError as exc:
                errors.append(f"Subfinder: {type(exc).__name__}: {exc}")
                sources.append({"name": "Subfinder", "status": "error", "count": 0})
                log(f"[Subfinder] Failed: {type(exc).__name__}: {exc}")

    return {
        "passive_subdomains": sorted(subdomains), "historical_urls": sorted(historical_urls),
        "passive_sources": sources,
        "passive_errors": errors,
    }
