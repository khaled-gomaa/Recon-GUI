"""Plain-text rendering for exported recon reports."""


def _section(lines, title):
    lines.extend(("", "=" * 78, title.upper(), "=" * 78))


def render_text_report(report: dict) -> str:
    """Render a complete, readable TXT report without third-party dependencies."""
    report = report or {}
    lines = [
        "RECON-GUI - RECONNAISSANCE REPORT",
        f"Target: {report.get('target', '(not recorded)')}",
        f"Status: {'Stopped by user' if report.get('stopped_by_user') else 'Completed'}",
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

    lines.extend(("", "End of report."))
    return "\n".join(lines)
