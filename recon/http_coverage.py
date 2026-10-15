"""Coverage summaries for observed HTTP outcomes without retaining query values."""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def _safe_url(value: str) -> str:
    """Return origin + path only; never copy query values into diagnostics."""
    try:
        parsed = urlsplit(str(value or ""))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return parsed.path or "(unknown URL)"
        host = parsed.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port and not (
            (parsed.scheme.lower() == "http" and port == 80)
            or (parsed.scheme.lower() == "https" and port == 443)
        ):
            host = f"{host}:{port}"
        return urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", "", ""))
    except (TypeError, ValueError, UnicodeError):
        return "(invalid URL)"


def summarize_http_outcomes(
    pages=None, wordlist_results=None, asset_probe_results=None, javascript_fetch_errors=None
) -> dict:
    """Count response classes and failed requests across active HTTP phases.

    These are observed outcomes, not a claim that every possible URL has been found.
    Query strings, fragments, response bodies and raw exception messages are not copied
    into the diagnostic lists.
    """
    status_counts: dict[str, int] = {}
    failed_requests = []
    server_errors = []
    restricted = []
    transport_errors = 0
    server_error_count = 0
    restricted_count = 0
    failed_detail_count = 0
    phases = (
        ("crawl", pages or []),
        ("content-discovery", wordlist_results or []),
        ("asset-head", asset_probe_results or []),
        ("javascript", javascript_fetch_errors or []),
    )

    for phase, records in phases:
        for item in records:
            if not isinstance(item, dict):
                continue
            url = _safe_url(item.get("url") or item.get("final_url") or "")
            status = item.get("status")
            error = str(item.get("error") or "").strip()
            error_type = str(item.get("error_type") or "").strip()
            diagnostic_error = error_type or error
            try:
                code = int(status) if status is not None else 0
            except (TypeError, ValueError, OverflowError):
                code = 0

            if code:
                key = str(code)
                status_counts[key] = status_counts.get(key, 0) + 1

            if code <= 0:
                transport_errors += 1
                failed_detail_count += 1
                if len(failed_requests) < 500:
                    failed_requests.append({
                        "url": url,
                        "phase": phase,
                        "error_type": (
                            diagnostic_error.split(":", 1)[0]
                            if diagnostic_error else "No HTTP response"
                        ),
                    })
            elif diagnostic_error:
                # An HTTP response was received, but this phase could not analyze it.
                # Count it as an incomplete result without misclassifying it as a transport error.
                failed_detail_count += 1
                if len(failed_requests) < 500:
                    failed_requests.append({
                        "url": url,
                        "phase": phase,
                        "error_type": diagnostic_error.split(":", 1)[0],
                    })

            if 500 <= code <= 599:
                server_error_count += 1
                if len(server_errors) < 500:
                    server_errors.append({"url": url, "phase": phase, "status": code})
            if code in {401, 403}:
                restricted_count += 1
                if len(restricted) < 500:
                    restricted.append({"url": url, "phase": phase, "status": code})

    return {
        "http_status_counts": dict(sorted(status_counts.items(), key=lambda item: int(item[0]))),
        "transport_error_count": transport_errors,
        "failed_requests": failed_requests,
        "failed_requests_list_truncated": failed_detail_count > len(failed_requests),
        "server_error_response_count": server_error_count,
        "server_error_responses": server_errors,
        "server_error_list_truncated": server_error_count > len(server_errors),
        "restricted_response_count": restricted_count,
        "restricted_responses": restricted,
        "restricted_response_list_truncated": restricted_count > len(restricted),
    }
