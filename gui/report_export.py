"""Plain-text rendering for exported recon reports."""


def _section(lines, title):
    lines.extend(("", "=" * 78, title.upper(), "=" * 78))


def render_text_report(report: dict) -> str:
    """Render a complete, readable TXT report without third-party dependencies."""
    report = report or {}
    lines = [
        "RECON-GUI - RECONNAISSANCE REPORT",
        f"Target: {report.get('target', '(not recorded)')}",
        f"Status: {'Stopped by user' if report.get('stopped_by_user') else 'Partial (rate limited)' if report.get('crawler_rate_limited_stop') or report.get('wordlist_rate_limited_stop') else 'Completed'}",
        f"Pages crawled: {len(report.get('pages', []))}",
        f"Pages after filters: {len(report.get('filtered_pages', []))}",
        f"Filter: {report.get('matcher_description', '(no filters)')}",
        f"Favicon hash: {report.get('favicon_hash') or '(not found)'}",
        "Crawler rate limit: " + (
            "stopped safely" if report.get("crawler_rate_limited_stop")
            else "not triggered / resumed after Retry-After"
        ),
        "Content Discovery rate limit: " + (
            "stopped safely" if report.get("wordlist_rate_limited_stop")
            else "not triggered / resumed after Retry-After"
        ),
    ]

    _section(lines, "Pages")
    for page in report.get("pages", []):
        chain = " -> ".join(str(item.get("status", "")) for item in page.get("redirect_chain", []))
        lines.append(
            f"[{page.get('status', 'ERR')}] {page.get('url', '')} | "
            f"words={page.get('word_count', 0)} | bytes={page.get('content_length', 0)} | "
            f"title={page.get('title', '')}"
        )
        if page.get("final_url") and page.get("final_url") != page.get("url"):
            lines.append(f"    Final URL: {page['final_url']}")
        if chain:
            lines.append(f"    Redirect chain: {chain}")
        if page.get("error"):
            lines.append(f"    Error: {page['error']}")

    _section(lines, "Filtered Pages")
    for page in report.get("filtered_pages", []):
        lines.append(
            f"[{page.get('status', 'ERR')}] {page.get('url', '')} | "
            f"words={page.get('word_count', 0)} | bytes={page.get('content_length', 0)} | "
            f"title={page.get('title', '')}"
        )

    for title, key in (
        ("Emails", "emails"),
        ("Subdomains", "subdomains"),
        ("Endpoints", "endpoints"),
        ("Discovered Routes", "discovered_routes"),
        ("JavaScript Files", "js_files"),
        ("Source Maps", "source_maps"),
    ):
        _section(lines, title)
        values = report.get(key, [])
        lines.extend(f"- {value}" for value in values) if values else lines.append("(none found)")

    _section(lines, "Content Discovery - All Responses")
    results = report.get("wordlist_results", [])
    if not results:
        lines.append("(not enabled or no responses)")
    for item in results:
        if item.get("baseline_match"):
            label = "LIKELY WILDCARD"
        elif item.get("potential_hit"):
            label = "POTENTIAL HIT"
        else:
            label = "RESPONSE"
        lines.append(
            f"[{item.get('status', '')}] [{label}] {item.get('url', '')} | "
            f"bytes={item.get('size', 0)} | words={item.get('word_count', 0)} | "
            f"type={item.get('content_type', '')}"
        )
        if item.get("location"):
            lines.append(f"    Location: {item['location']}")

    _section(lines, "Potential Content Discovery Hits")
    hits = report.get("wordlist_hits", [])
    if not hits:
        lines.append("(none)")
    for item in hits:
        lines.append(
            f"[{item.get('status', '')}] {item.get('url', '')} | "
            f"bytes={item.get('size', 0)} | words={item.get('word_count', 0)}"
        )

    _section(lines, "HTTP Security Headers")
    audits = report.get("header_audits", [])
    if not audits:
        lines.append("(none)")
    for audit in audits:
        lines.append(audit.get("url", ""))
        for name, value in audit.get("present", {}).items():
            lines.append(f"    PRESENT  {name}: {value}")
        for name in audit.get("missing", []):
            lines.append(f"    MISSING  {name}")

    similarity = report.get("similarity", {})
    for title, key in (
        ("Exact Duplicate Groups", "exact_duplicates"),
        ("Soft-404 Candidates", "soft_404_candidates"),
        ("Similar Path Variants", "same_path_variants"),
        ("Redirect Duplicates", "redirect_duplicates"),
    ):
        _section(lines, title)
        groups = similarity.get(key, [])
        if not groups:
            lines.append("(none)")
        for group in groups:
            lines.append(str(group))

    _section(lines, "HTML Forms (No Submission Performed)")
    forms = report.get("forms", [])
    if not forms:
        lines.append("(none found)")
    for form in forms:
        lines.append(
            f"[{form.get('method', 'GET')}] {form.get('action', '')} | "
            f"fields={form.get('field_count', 0)} | "
            f"csrf_field_present={form.get('csrf_field_present', False)} | "
            f"same_origin={form.get('same_origin_action', False)}"
        )
        for field in form.get("fields", []):
            lines.append(
                f"    {field.get('name', '')}: {field.get('type', '')}"
                + (" [required]" if field.get("required") else "")
            )

    _section(lines, "JSON-LD / Structured Data")
    for item in report.get("json_ld", []):
        lines.append(f"{item.get('type', '(unknown type)')} | {item.get('name', '')} | {item.get('page', '')}")
    if not report.get("json_ld"):
        lines.append("(none found)")

    _section(lines, "Sensitive Data Candidates (Values Redacted)")
    findings = report.get("sensitive_findings", [])
    if not findings:
        lines.append("(none found)")
    for item in findings:
        lines.append(
            f"[{item.get('severity', 'medium')}] {item.get('type', '')} | "
            f"{item.get('page', '')} | source={item.get('source', '')} | [REDACTED]"
        )

    for title, key in (("Passive Subdomains", "passive_subdomains"), ("Historical URLs", "historical_urls")):
        _section(lines, title)
        values = report.get(key, [])
        lines.extend(f"- {value}" for value in values) if values else lines.append("(none found)")
    _section(lines, "Passive Sources")
    for item in report.get("passive_sources", []):
        lines.append(f"{item.get('name')}: {item.get('status')} ({item.get('count', 0)} items)")
    for item in report.get("passive_errors", []):
        lines.append(f"Warning: {item}")

    _section(lines, "Scan History Comparison")
    diff = report.get("history_diff", {})
    lines.append(f"Current scan: {report.get('scan_id', '(not saved)')}")
    lines.append(f"Previous scan: {diff.get('previous_scan_id', '(first scan)')}")
    lines.append(
        f"Added: {diff.get('added_count', 0)} | Removed: {diff.get('removed_count', 0)} "
        f"| Changed: {diff.get('changed_count', 0)}"
    )
    for key, label in (("added_urls", "NEW"), ("removed_urls", "REMOVED"), ("changed_urls", "CHANGED")):
        for url in diff.get(key, []):
            lines.append(f"[{label}] {url}")
    if report.get("history_error"):
        lines.append(f"History warning: {report['history_error']}")

    _section(lines, "Optional Module Status")
    lines.append(f"JavaScript rendering enabled: {report.get('rendering_enabled', False)}")
    lines.append(f"Rendered pages: {report.get('rendered_pages', 0)}")
    lines.append(f"robots.txt: {report.get('robots_url', '(not read)')}")
    lines.append(f"Crawl-delay: {report.get('crawl_delay_seconds', 0)} seconds")
    lines.append(f"Authentication configured: {report.get('auth_configured', False)}")
    lines.append(f"Authentication fields: {', '.join(report.get('auth_types', [])) or '(none)'}")

    lines.extend(("", "End of report."))
    return "\n".join(lines)


def render_csv_report(report: dict) -> str:
    """Render a flat spreadsheet-friendly CSV without raw page bodies or credentials."""
    import csv
    import io

    report = report or {}
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["record_type", "url", "status", "title", "severity", "details"])

    for page in report.get("pages", []) or []:
        writer.writerow([
            "page", page.get("url", ""), page.get("status", ""), page.get("title", ""),
            "", "words={}; bytes={}; final_url={}; content_type={}; depth={}".format(
                page.get("word_count", 0), page.get("content_length", 0),
                page.get("final_url", ""), page.get("content_type", ""), page.get("depth", 0),
            ),
        ])
    for item in report.get("wordlist_results", []) or []:
        writer.writerow([
            "content_discovery", item.get("url", ""), item.get("status", ""),
            "", "potential" if item.get("potential_hit") else "",
            "bytes={}; words={}; type={}; baseline_match={}".format(
                item.get("size", 0), item.get("word_count", 0),
                item.get("content_type", ""), item.get("baseline_match", False),
            ),
        ])
    for kind in (
        "emails", "subdomains", "endpoints", "discovered_routes", "js_files",
        "source_maps", "passive_subdomains", "historical_urls",
    ):
        for value in report.get(kind, []) or []:
            writer.writerow(["finding:" + kind, "", "", "", "", value])
    for kind in ("forms", "json_ld", "sensitive_findings"):
        for item in report.get(kind, []) or []:
            details = dict(item)
            # Defensive redaction if a future module adds raw secret-like keys.
            for key in list(details):
                if any(word in key.lower() for word in ("password_value", "secret_value", "token_value", "raw_secret")):
                    details[key] = "[REDACTED]"
            writer.writerow([
                "finding:" + kind, item.get("page", item.get("url", "")), "",
                item.get("name", item.get("type", "")), item.get("severity", ""),
                json.dumps(details, ensure_ascii=False, sort_keys=True, default=str),
            ])
    for audit in report.get("header_audits", []) or []:
        writer.writerow([
            "security_headers", audit.get("url", ""), "", "", "",
            "missing=" + ", ".join(audit.get("missing", []) or []),
        ])
    return output.getvalue()
