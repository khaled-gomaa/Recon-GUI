"""Human-readable and spreadsheet-friendly recon report exporters."""
import json


def _section(lines, title):
    lines.extend(("", "=" * 78, title.upper(), "=" * 78))


def render_text_report(report: dict) -> str:
    """Render a complete, readable TXT report without third-party dependencies."""
    report = report or {}
    lines = [
        "RECON-GUI - RECONNAISSANCE REPORT",
        f"Target: {report.get('target', '(not recorded)')}",
        f"Status: {'Stopped by user' if report.get('stopped_by_user') else 'Partial (rate limited)' if report.get('crawler_rate_limited_stop') or report.get('wordlist_rate_limited_stop') else 'Partial (page/depth/wordlist cap)' if report.get('page_limit_reached') or report.get('depth_limit_reached') or report.get('wordlist_candidate_limit_reached') else 'Completed'}",
        f"Pages crawled: {len(report.get('pages', []))}",
        f"Pages after filters: {len(report.get('filtered_pages', []))}",
        f"Content Discovery words loaded: {report.get('wordlist_words_loaded', 0)}",
        f"Content Discovery candidates generated: {report.get('wordlist_candidates', 0)}",
        f"Explicit wordlist limit reached: {report.get('wordlist_candidate_limit_reached', False)}",
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

    _section(lines, "Network Requests (Metadata Only)")
    network_records = report.get("network_observations", [])
    if not network_records:
        lines.append("(no runtime network observations; static inference is shown in Endpoint Inventory)")
    for item in network_records:
        lines.append(
            f"[{item.get('method', 'UNKNOWN')}] {item.get('url', '')} | "
            f"status={item.get('status', '(not observed)')} | source={item.get('source', '')} | "
            f"query_names={', '.join(item.get('query_parameters', []))} | "
            f"body_names={', '.join(item.get('body_parameters', []))} | "
            f"type={item.get('resource_type', '')} | content_type={item.get('content_type', '')}"
        )
        if item.get("page"):
            lines.append(f"    Initiated by: {item['page']}")

    _section(lines, "Cookie Map (Names and Attributes Only)")
    cookie_map = report.get("cookie_map", [])
    if not cookie_map:
        lines.append("(no cookie metadata captured)")
    for item in cookie_map:
        attrs = [
            label for key, label in (
                ("secure", "Secure"), ("httponly", "HttpOnly")
            ) if item.get(key)
        ]
        if item.get("samesite"):
            attrs.append("SameSite=" + str(item.get("samesite")))
        lines.append(
            f"{item.get('name', '')} | domain={item.get('domain', '')} | "
            f"path={item.get('path', '')} | attributes={', '.join(attrs)} | "
            f"source={item.get('source', '')} | url={item.get('url', '')}"
        )

    _section(lines, "Endpoint Inventory")
    endpoint_inventory = report.get("endpoint_inventory", [])
    if not endpoint_inventory:
        lines.append("(none found)")
    for item in endpoint_inventory:
        lines.append(
            f"{item.get('endpoint', '')} | methods={', '.join(item.get('methods', []))} | "
            f"sources={', '.join(item.get('sources', []))} | "
            f"parameters={', '.join(item.get('parameters', []))} | "
            f"locations={item.get('location_count', 0)}"
        )

    _section(lines, "Parameter Inventory (Names Only; Values Omitted)")
    parameters = report.get("parameters", [])
    if not parameters:
        lines.append("(none found)")
    for item in parameters:
        lines.append(
            f"{item.get('name', '')} | class={item.get('classification', '')} | "
            f"sources={', '.join(item.get('sources', []))} | occurrences={item.get('occurrences', 0)} | "
            f"methods={', '.join(item.get('methods', []))}"
        )
        for location in item.get("locations", [])[:5]:
            lines.append(f"    Location: {location}")

    _section(lines, "Correlated Review Findings")
    related_findings = report.get("related_findings", [])
    if not related_findings:
        lines.append("(none generated)")
    for item in related_findings:
        lines.append(
            f"[{item.get('severity', 'info')}] {item.get('title', '')} | "
            f"confidence={item.get('confidence', '')} | category={item.get('category', '')}"
        )
        for evidence in item.get("evidence", []) or []:
            lines.append(f"    Evidence: {evidence}")
        lines.append(f"    Recommendation: {item.get('recommendation', '')}")

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
    _section(lines, "Endpoint and Parameter Changes")
    lines.append(f"Comparison status: {diff.get('comparison_status', '(no previous scan)')}")
    lines.append(f"New endpoints: {diff.get('added_endpoint_count', len(diff.get('added_endpoints', [])))}")
    for endpoint in diff.get("added_endpoints", []):
        lines.append(f"[NEW ENDPOINT] {endpoint}")
    lines.append(f"Removed endpoints: {diff.get('removed_endpoint_count', len(diff.get('removed_endpoints', [])))}")
    for endpoint in diff.get("removed_endpoints", []):
        lines.append(f"[REMOVED ENDPOINT] {endpoint}")
    lines.append(f"Changed endpoints: {diff.get('changed_endpoint_count', len(diff.get('changed_endpoints', [])))}")
    for endpoint in diff.get("changed_endpoints", []):
        lines.append(f"[CHANGED ENDPOINT] {endpoint}")
    lines.append(f"New parameters: {diff.get('added_parameter_count', len(diff.get('added_parameters', [])))}")
    for name in diff.get("added_parameters", []):
        lines.append(f"[NEW PARAMETER] {name}")
    lines.append(f"Removed parameters: {diff.get('removed_parameter_count', len(diff.get('removed_parameters', [])))}")
    for name in diff.get("removed_parameters", []):
        lines.append(f"[REMOVED PARAMETER] {name}")
    lines.append(f"New review findings: {diff.get('added_finding_count', len(diff.get('added_findings', [])))}")

    if report.get("history_error"):
        lines.append(f"History warning: {report['history_error']}")

    _section(lines, "Optional Module Status")
    lines.append(f"JavaScript rendering enabled: {report.get('rendering_enabled', False)}")
    lines.append(f"Rendered pages: {report.get('rendered_pages', 0)}")
    lines.append(f"Historical URLs actively crawled: {report.get('historical_urls_crawled', False)}")
    lines.append(f"Page limit reached: {report.get('page_limit_reached', False)}")
    lines.append(f"Depth limit reached with unvisited links: {report.get('depth_limit_reached', False)}")
    lines.append(f"Wordlist candidate limit reached: {report.get('wordlist_candidate_limit_reached', False)}")
    lines.append(f"Endpoint records: {len(report.get('endpoint_inventory', []))}")
    lines.append(f"Parameter names: {len(report.get('parameters', []))}")
    lines.append(f"Content Discovery words loaded: {report.get('wordlist_words_loaded', 0)}")
    lines.append(f"Content Discovery candidates: {report.get('wordlist_candidates', 0)}")
    lines.append(f"Subfinder: {report.get('subfinder_status', 'not-run')}")
    lines.append(f"Manual Browser Session enabled: {report.get('manual_browser_session_enabled', False)}")
    lines.append(f"Runtime network observations: {len(report.get('network_observations', []))}")
    lines.append(f"Cookie metadata records: {len(report.get('cookie_map', []))}")
    lines.append(f"Correlated review findings: {len(report.get('related_findings', []))}")
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
    for item in report.get("endpoint_inventory", []) or []:
        writer.writerow([
            "endpoint", item.get("endpoint", ""), "", "", "",
            json.dumps({
                "methods": item.get("methods", []),
                "sources": item.get("sources", []),
                "parameters": item.get("parameters", []),
                "locations": item.get("locations", []),
            }, ensure_ascii=False, sort_keys=True),
        ])
    for item in report.get("network_observations", []) or []:
        writer.writerow([
            "network_request", item.get("url", ""), item.get("status") or "",
            item.get("method", ""), "",
            json.dumps({
                "source": item.get("source", ""),
                "resource_type": item.get("resource_type", ""),
                "content_type": item.get("content_type", ""),
                "query_parameters": item.get("query_parameters", []),
                "body_parameters": item.get("body_parameters", []),
                "page": item.get("page", ""),
            }, ensure_ascii=False, sort_keys=True),
        ])
    for item in report.get("cookie_map", []) or []:
        writer.writerow([
            "cookie_metadata", item.get("url", ""), "", item.get("name", ""), "",
            json.dumps({
                "domain": item.get("domain", ""),
                "path": item.get("path", ""),
                "secure": item.get("secure", False),
                "httponly": item.get("httponly", False),
                "samesite": item.get("samesite", ""),
                "source": item.get("source", ""),
            }, ensure_ascii=False, sort_keys=True),
        ])
    for item in report.get("parameters", []) or []:
        writer.writerow([
            "parameter", "", "", item.get("name", ""), "",
            json.dumps({
                "classification": item.get("classification", ""),
                "sources": item.get("sources", []),
                "occurrences": item.get("occurrences", 0),
                "methods": item.get("methods", []),
                "locations": item.get("locations", []),
            }, ensure_ascii=False, sort_keys=True),
        ])
    for item in report.get("related_findings", []) or []:
        writer.writerow([
            "correlated_finding", "", "", item.get("title", ""),
            item.get("severity", ""),
            json.dumps({
                "category": item.get("category", ""),
                "confidence": item.get("confidence", ""),
                "evidence": item.get("evidence", []),
                "recommendation": item.get("recommendation", ""),
            }, ensure_ascii=False, sort_keys=True),
        ])

    for audit in report.get("header_audits", []) or []:
        writer.writerow([
            "security_headers", audit.get("url", ""), "", "", "",
            "missing=" + ", ".join(audit.get("missing", []) or []),
        ])
    return output.getvalue()
