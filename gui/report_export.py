"""Human-readable and spreadsheet-friendly recon report exporters."""
import json


def _section(lines, title):
    lines.extend(("", "=" * 78, title.upper(), "=" * 78))


def render_text_report(report: dict) -> str:
    """Render a complete, readable TXT report without third-party dependencies."""
    report = report or {}
    import_only = bool(report.get("har_import_summary")) and not report.get("started_at") and not report.get("pages")
    has_rate_limit = bool(
        report.get("crawler_rate_limited_stop")
        or report.get("wordlist_rate_limited_stop")
        or report.get("css_rate_limited_stop")
        or report.get("js_rate_limited_stop")
        or (report.get("asset_probe_summary", {}) or {}).get("rate_limited_stop")
    )
    has_coverage_cap = bool(
        report.get("page_limit_reached")
        or report.get("depth_limit_reached")
        or report.get("wordlist_candidate_limit_reached")
        or report.get("content_limit_reached")
        or (report.get("css_discovery_summary", {}) or {}).get("status") in {"partial", "error"}
        or (report.get("css_discovery_summary", {}) or {}).get("css_limit_reached")
        or (report.get("seed_import_summary", {}) or {}).get("limit_reached")
        or (report.get("asset_probe_summary", {}) or {}).get("partial")
        or report.get("unattempted_js_files")
    )
    has_http_errors = bool(
        report.get("transport_error_count")
        or report.get("server_error_response_count")
        or report.get("js_fetch_error_count")
    )
    status = (
        "HAR metadata imported (no active scan run)" if import_only else
        "Stopped by user" if report.get("stopped_by_user") else
        "Partial (rate limited)" if has_rate_limit else
        "Partial (request/server errors or incomplete JavaScript)" if has_http_errors else
        "Partial (page/depth/wordlist/content cap)" if has_coverage_cap else
        "Completed (no known caps or request errors)"
    )
    lines = [
        "RECON-GUI - RECONNAISSANCE REPORT",
        f"Target: {report.get('target', '(not recorded)')}",
        f"Status: {status}",
        f"Pages crawled: {len(report.get('pages', []))}",
        f"Pages after filters: {len(report.get('filtered_pages', []))}",
        f"Asset references found (not necessarily fetched): {len(report.get('asset_inventory', []))}",
        f"Asset HEAD checks: {(report.get('asset_probe_summary', {}) or {}).get('requests_completed', 0)}; failed={(report.get('asset_probe_summary', {}) or {}).get('request_failures', 0)}; enabled={(report.get('asset_probe_summary', {}) or {}).get('enabled', False)}; partial={(report.get('asset_probe_summary', {}) or {}).get('partial', False)}",
        f"Runtime request capture mode: {report.get('network_capture_mode', 'unknown')}",
        f"Observed browser request records: {report.get('runtime_network_request_count', len(report.get('network_observations', []))) or 0}",
        f"Cookie identities: {report.get('cookie_identity_count', len(report.get('cookie_map', []))) or 0}",
        f"Cookie observations: {report.get('cookie_observation_count', len(report.get('cookie_map', []))) or 0}",
        f"Cookie identity/URL associations: {report.get('cookie_url_count', 0) or 0}",
        f"Content Discovery requests attempted: {report.get('wordlist_requests_attempted', len(report.get('wordlist_results', []))) or 0}",
        f"Content Discovery candidates unattempted: {report.get('wordlist_requests_unattempted', 0) or 0}",
        f"Content Discovery status: {report.get('wordlist_scan_status', 'unknown')}",
        f"Content Discovery words loaded: {report.get('wordlist_words_loaded', 0)}",
        f"Content Discovery candidates generated: {report.get('wordlist_candidates', 0)}",
        f"JavaScript fetch failures: {report.get('js_fetch_error_count', 0)}",
        f"JavaScript rate-limited stop: {report.get('js_rate_limited_stop', False)}",
        f"HTTP status counts: {report.get('http_status_counts', {})}",
        f"Transport/request errors: {report.get('transport_error_count', 0)}",
        f"HTTP 5xx responses: {report.get('server_error_response_count', 0)}",
        f"Restricted responses (401/403): {report.get('restricted_response_count', 0)}",
        f"Explicit wordlist limit reached: {report.get('wordlist_candidate_limit_reached', False)}",
        f"Wordlist word cap: {report.get('wordlist_max_words', 0) or 'unlimited'}; reached: {report.get('wordlist_word_limit_reached', False)}",
        f"Generated path cap: {report.get('wordlist_max_candidates', 0) or 'unlimited'}; reached: {report.get('wordlist_path_limit_reached', False)}",
        f"Content/body truncation cap reached: {report.get('content_limit_reached', False)}",
        f"Imported seed source: {(report.get('seed_import_summary', {}) or {}).get('source_file', '(none)')}",
        f"Imported seed URLs accepted/crawled: {(report.get('seed_import_summary', {}) or {}).get('accepted_count', 0)}/{report.get('imported_seed_urls_crawled', 0)}",
        f"Imported seed source cap reached: {(report.get('seed_import_summary', {}) or {}).get('limit_reached', False)}",
        f"Manual browser session elapsed/window: {report.get('manual_browser_seconds', 0)}/{report.get('manual_browser_window_seconds', 0)} seconds",
        f"Filter: {report.get('matcher_description', '(no filters)')}",
        f"Favicon hash: {report.get('favicon_hash') or '(not found)'}",
        "Crawler rate limit: " + (
            "stopped safely" if report.get("crawler_rate_limited_stop")
            else "not triggered / resumed after Retry-After"
        ),
        "CSS discovery rate limit: " + (
            "stopped safely; subsequent active phases skipped" if report.get("css_rate_limited_stop")
            else "not triggered / phase completed or was skipped"
        ),
        "Content Discovery rate limit: " + (
            "stopped safely" if report.get("wordlist_rate_limited_stop")
            else "not triggered / resumed after Retry-After"
        ),
    ]

    har_summary = report.get("har_import_summary", {}) or {}
    if har_summary:
        _section(lines, "HAR Import Summary")
        lines.append(f"Files imported: {har_summary.get('files_imported', 0)}")
        lines.append(f"Entries seen/imported: {har_summary.get('entries_seen', 0)}/{har_summary.get('entries_imported', 0)}")
        lines.append(f"Unique request records: {har_summary.get('unique_requests', 0)}")
        lines.append(f"Import truncated: {har_summary.get('truncated', False)}")
        for warning in har_summary.get("warnings", []) or []:
            lines.append("WARNING: " + str(warning))

    _section(lines, "HTTP Coverage / Failed Requests")
    for item in report.get("failed_requests", []) or []:
        lines.append(
            f"[FAILED] [{item.get('phase', '')}] {item.get('url', '')} "
            f"| error={item.get('error_type', 'No HTTP response')}"
        )
    if report.get("failed_requests_list_truncated"):
        lines.append("WARNING: failed-request detail list was capped; the error count includes more records.")
    for item in report.get("server_error_responses", []) or []:
        lines.append(
            f"[HTTP {item.get('status')}] [{item.get('phase', '')}] {item.get('url', '')}"
        )
    if report.get("server_error_list_truncated"):
        lines.append("WARNING: server-error detail list was capped; the count includes more records.")
    for item in report.get("restricted_responses", []) or []:
        lines.append(
            f"[HTTP {item.get('status')}] [{item.get('phase', '')}] {item.get('url', '')}"
        )

    _section(lines, "Pages")
    for page in report.get("pages", []):
        chain = " -> ".join(str(item.get("status", "")) for item in page.get("redirect_chain", []))
        lines.append(
            f"[{page.get('status', 'ERR')}] {page.get('url', '')} | "
            f"words={page.get('word_count', 0)} | bytes={page.get('content_length', 0)} | "
            f"title={page.get('title', '')}"
            + (" | BODY TRUNCATED" if page.get("body_truncated") else "")
        )
        if page.get("final_url") and page.get("final_url") != page.get("url"):
            lines.append(f"    Final URL: {page['final_url']}")
        if chain:
            lines.append(f"    Redirect chain: {chain}")
        if page.get("error"):
            lines.append(f"    Error: {page['error']}")

    probe_summary = report.get("asset_probe_summary", {}) or {}
    if probe_summary.get("enabled"):
        _section(lines, "Asset HEAD Probe Summary")
        for label, key in (
            ("Unique same-origin candidates", "unique_same_origin_candidates"),
            ("Selected candidates", "selected_candidates"),
            ("Completed HEAD requests", "requests_completed"),
            ("Failed HEAD requests", "request_failures"),
            ("Skipped outside origin", "skipped_out_of_origin"),
            ("Limit reached", "limit_reached"),
            ("Rate limited", "rate_limited"),
            ("Rate-limited stop", "rate_limited_stop"),
            ("Unattempted selected URLs", "unattempted"),
            ("Partial coverage", "partial"),
        ):
            lines.append(f"{label}: {probe_summary.get(key, False if 'reached' in label.lower() or 'limited' in label.lower() or 'coverage' in label.lower() else 0)}")

    css_summary = report.get("css_discovery_summary", {}) or {}
    _section(lines, "CSS / Nested Asset Discovery")
    lines.append(f"Status: {css_summary.get('status', 'not run')}")
    lines.append(
        f"Stylesheets discovered / attempted / fetched: "
        f"{css_summary.get('css_files_discovered', 0)} / "
        f"{css_summary.get('css_files_attempted', 0)} / "
        f"{css_summary.get('css_files_fetched', 0)}"
    )
    lines.append(f"Rate-limited stop: {bool(report.get('css_rate_limited_stop'))}")
    lines.append(f"Truncated stylesheets: {len(css_summary.get('css_files_truncated', []) or [])}")
    for item in css_summary.get("css_file_errors", []) or []:
        lines.append(f"CSS warning: {item.get('status', '')} {item.get('url', '')} {item.get('error', '')}".strip())
    for url in css_summary.get("css_files_truncated", []) or []:
        lines.append(f"TRUNCATED CSS: {url}")

    _section(lines, "Asset References (URLs from page markup or CSS; not proof that the resource exists)")
    for item in report.get("asset_inventory", []) or []:
        if not item.get("in_scope", False):
            evidence = "external reference; not fetched"
        elif item.get("fetched_by_page_crawler"):
            evidence = "requested by page crawler"
        elif item.get("fetched_by_js_collector"):
            evidence = "downloaded by JavaScript collector"
        elif item.get("fetched_by_css_collector"):
            evidence = "downloaded by CSS collector"
        else:
            evidence = "reference only; not fetched"
        if item.get("probe_checked"):
            evidence += (
                f"; HEAD={item.get('probe_status') if item.get('probe_status') is not None else 'failed'}"
                f" ({item.get('probe_result', 'no result')})"
            )
            if item.get("probe_content_type"):
                evidence += "; type=" + str(item.get("probe_content_type"))
            if item.get("probe_content_length") is not None:
                evidence += "; bytes=" + str(item.get("probe_content_length"))
        lines.append(
            f"[{item.get('kind', 'resource')}] {item.get('url', '')} | "
            f"extension={item.get('extension', '') or '(none)'} | "
            f"sources={', '.join(item.get('sources', []) or []) or '(unknown)'} | "
            f"referrers={item.get('reference_count', 0)} | {evidence}"
        )
        if item.get("query_parameter_names"):
            lines.append("    Query parameter names: " + ", ".join(item.get("query_parameter_names", [])))
    if not report.get("asset_inventory"):
        lines.append("(no static asset references found in captured page markup)")

    _section(lines, "Filtered Pages")
    for page in report.get("filtered_pages", []):
        lines.append(
            f"[{page.get('status', 'ERR')}] {page.get('url', '')} | "
            f"words={page.get('word_count', 0)} | bytes={page.get('content_length', 0)} | "
            f"title={page.get('title', '')}"
        )

    verification = report.get("subdomain_verification", {}) or {}
    verified_hosts = verification.get("results", []) or []
    _section(lines, "Selected Subdomain Verification (Explicit DNS + HTTP HEAD)")
    if not verified_hosts:
        lines.append("(not run or no valid selected subdomains)")
    for item in verified_hosts:
        lines.append(
            f"{item.get('host', '')} | DNS={item.get('dns_status', 'unknown')} "
            f"| IPs={', '.join(item.get('ip_addresses', []) or []) or '--'} "
            f"| HTTP={item.get('http_status') if item.get('http_status') is not None else item.get('http_result', 'not tested')} "
            f"| URL={item.get('http_url', '') or '--'}"
        )
        if item.get("error"):
            lines.append(f"    Connection note: {item['error']}")
    if verification.get("truncated"):
        lines.append(
            f"Verification was capped: {verification.get('verified_count', 0)} checked; "
            f"{verification.get('skipped_count', 0)} remain unchecked."
        )

    for title, key in (
        ("Emails", "emails"),
        ("Subdomains", "subdomains"),
        ("Endpoints", "endpoints"),
        ("Discovered Routes", "discovered_routes"),
        ("JavaScript Files", "js_files"),
        ("Source Maps", "source_maps"),
        ("Truncated JavaScript Files", "truncated_js_files"),
        ("Discovered JavaScript Not Attempted", "unattempted_js_files"),
    ):
        _section(lines, title)
        values = report.get(key, [])
        lines.extend(f"- {value}" for value in values) if values else lines.append("(none found)")

    _section(lines, "Crawl Coverage / Truncation Limits")
    coverage = report.get("coverage_summary", {}) or {}
    if coverage:
        for label, key in (
            ("Pages fetched", "pages_crawled"), ("Page cap", "page_cap"),
            ("Maximum depth", "max_depth"), ("JS files discovered", "javascript_files_discovered"),
            ("JS files attempted", "javascript_files_attempted"),
            ("JS files truncated", "javascript_files_truncated"),
            ("JS files failed/inaccessible", "javascript_files_failed"),
            ("JS files unattempted", "javascript_files_unattempted"),
            ("Response bodies truncated", "response_bodies_truncated"),
        ):
            lines.append(f"{label}: {coverage.get(key, 0)}")
        lines.append(f"Page limit reached: {coverage.get('page_limit_reached', False)}")
        lines.append(f"Depth limit reached: {coverage.get('depth_limit_reached', False)}")
        lines.append(
            f"Wordlist words: {coverage.get('wordlist_words_loaded', 0)} / "
            f"cap {coverage.get('wordlist_max_words', 0) or 'unlimited'}; "
            f"word cap reached: {coverage.get('wordlist_word_limit_reached', False)}"
        )
        lines.append(
            f"Generated paths: {coverage.get('wordlist_candidates', 0)} / "
            f"cap {coverage.get('wordlist_max_candidates', 0) or 'unlimited'}; "
            f"path cap reached: {coverage.get('wordlist_path_limit_reached', False)}"
        )
        lines.append(f"Wordlist limit reached: {coverage.get('wordlist_limit_reached', False)}")
        lines.append(
            f"Recursive discovery: enabled={coverage.get('wordlist_recursive_enabled', False)}; "
            f"depth cap={coverage.get('wordlist_recursion_depth', 1)}; "
            f"directory candidates={coverage.get('wordlist_recursive_dirs_found', 0)}; "
            f"rounds completed={coverage.get('wordlist_recursion_rounds', 0)}; "
            f"depth cap reached={coverage.get('wordlist_recursion_depth_limit_reached', False)}"
        )
        lines.append(f"Content limit reached: {coverage.get('content_limit_reached', False)}")
    for note in report.get("content_limit_notes", []) or []:
        lines.append("WARNING: " + str(note))
    if not coverage and not report.get("content_limit_notes"):
        lines.append("(no crawl coverage limits were reported as reached)")

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
    lines.append(
        f"Identities: {report.get('cookie_identity_count', len(cookie_map))}; "
        f"observations: {report.get('cookie_observation_count', len(cookie_map))}; "
        f"identity/URL associations: {report.get('cookie_url_count', 0)}"
    )
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
            f"sources={', '.join(item.get('sources', []) or [item.get('source', '')])} | "
            f"observations={item.get('observation_count', 1)} | "
            f"URLs={item.get('url_count', 1)} | sample={item.get('url', '')}"
        )
        for sample_url in (item.get('sample_urls', []) or [])[1:5]:
            lines.append(f"    also observed at: {sample_url}")

    _section(lines, "Endpoint Inventory")
    endpoint_inventory = report.get("endpoint_inventory", [])
    if not endpoint_inventory:
        lines.append("(none found)")
    for item in endpoint_inventory:
        evidence = "; ".join(
            f"{entry.get('method', '')}: {', '.join(entry.get('evidence', []) or [])} "
            f"[{', '.join(entry.get('sources', []) or [])}]"
            for entry in (item.get("method_evidence", []) or [])
        ) or "no method evidence"
        lines.append(
            f"{item.get('endpoint', '')} | methods={', '.join(item.get('methods', []))} | "
            f"method_evidence={evidence} | sources={', '.join(item.get('sources', []))} | "
            f"parameters={', '.join(item.get('parameters', []))} | "
            f"locations={item.get('location_count', 0)}"
        )

    _section(lines, "Request Intelligence (Observed vs Inferred; Values Removed)")
    request_intelligence = report.get("request_intelligence", []) or []
    if not request_intelligence:
        lines.append("(no method evidence recorded)")
    for item in request_intelligence:
        lines.append(
            f"[{str(item.get('evidence', 'inferred')).upper()}] "
            f"[{item.get('method', 'UNKNOWN')}] {item.get('url', '')} | "
            f"sources={', '.join(item.get('sources', []) or [])} | "
            f"parameters={', '.join(item.get('parameter_names', []) or [])} | "
            f"statuses={', '.join(str(code) for code in item.get('status_codes', []) or [])} | "
            f"content-types={', '.join(item.get('content_types', []) or [])}"
        )

    source_coverage = report.get("coverage", {}) or {}
    _section(lines, "Source-aware Discovery Coverage")
    if source_coverage:
        lines.append(f"Assessment: {source_coverage.get('assessment', 'not calculated')}")
        lines.append(f"Pages: {source_coverage.get('pages', {})}")
        lines.append(f"HTTP outcomes: {source_coverage.get('http', {})}")
        lines.append(f"Discovery counts: {source_coverage.get('discovery', {})}")
        source_groups = source_coverage.get("sources", {}) or {}
        for category, values in sorted(source_groups.items()):
            lines.append(f"{category}: {values}")
        for reason in source_coverage.get("partial_reasons", []) or []:
            lines.append("GAP: " + str(reason))
        for note in source_coverage.get("notes", []) or []:
            lines.append("NOTE: " + str(note))
    else:
        lines.append("(not calculated)")

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
            f"[{item.get('status', '')}] [{label}] [{item.get('method', 'GET')}] "
            f"{item.get('url', '')} | bytes={item.get('size', 0)} | "
            f"words={item.get('word_count', 0)} | type={item.get('content_type', '')} | "
            f"hash={item.get('content_hash', '')} | truncated={item.get('response_truncated', False)}"
        )
        for field, label_text in (
            ("final_url", "Final URL"), ("location", "Redirect Location"),
            ("server", "Server"), ("last_modified", "Last-Modified"),
            ("allow", "Allow"), ("www_authenticate", "WWW-Authenticate"),
        ):
            if item.get(field):
                lines.append(f"    {label_text}: {item[field]}")
        if item.get("set_cookie_names"):
            lines.append("    Set-Cookie metadata: " + ", ".join(
                cookie.get("name", "") + "(" + "/".join(
                    flag for flag, enabled in (
                        ("Secure", cookie.get("secure")),
                        ("HttpOnly", cookie.get("httponly")),
                        ("SameSite=" + str(cookie.get("samesite")), bool(cookie.get("samesite"))),
                    ) if enabled
                ) + ")"
                for cookie in item["set_cookie_names"]
            ))

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
    _section(lines, "Asset Inventory Changes")
    lines.append(f"Comparison status: {diff.get('comparison_status', '(no previous scan)')}")
    for key, label in (
        ("added_assets", "NEW ASSET"),
        ("removed_assets", "REMOVED ASSET"),
        ("changed_assets", "CHANGED ASSET"),
    ):
        lines.append(f"{label.title()} count: {diff.get(key.replace('_assets', '_asset_count'), len(diff.get(key, [])))}")
        for asset in diff.get(key, []) or []:
            lines.append(f"[{label}] {asset}")

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

    har_summary = report.get("har_import_summary", {}) or {}
    if har_summary:
        writer.writerow([
            "har_import_summary", "", "", "",
            "partial" if har_summary.get("truncated") or har_summary.get("warnings") else "",
            json.dumps(har_summary, ensure_ascii=False, sort_keys=True),
        ])

    for page in report.get("pages", []) or []:
        writer.writerow([
            "page", page.get("url", ""), page.get("status", ""), page.get("title", ""),
            "", "words={}; bytes={}; final_url={}; content_type={}; depth={}; body_truncated={}".format(
                page.get("word_count", 0), page.get("content_length", 0),
                page.get("final_url", ""), page.get("content_type", ""), page.get("depth", 0),
                page.get("body_truncated", False),
            ),
        ])
    for item in report.get("asset_inventory", []) or []:
        if not item.get("in_scope", False):
            fetch_evidence = "external reference; not fetched"
        elif item.get("fetched_by_page_crawler"):
            fetch_evidence = "requested by page crawler"
        elif item.get("fetched_by_js_collector"):
            fetch_evidence = "downloaded by JavaScript collector"
        else:
            fetch_evidence = "reference only; not fetched"
        writer.writerow([
            "asset_reference", item.get("url", ""), "", "",
            "external" if not item.get("in_scope", False) else "",
            "kind={}; extension={}; referrers={}; fetch_evidence={}; head_status={}; head_result={}; head_type={}; head_bytes={}; query_parameter_names={}".format(
                item.get("kind", "resource"), item.get("extension", ""),
                item.get("reference_count", 0), fetch_evidence,
                item.get("probe_status", "") if item.get("probe_checked") else "not-checked",
                item.get("probe_result", "") if item.get("probe_checked") else "not-checked",
                item.get("probe_content_type", ""), item.get("probe_content_length", ""),
                ",".join(item.get("query_parameter_names", []) or []),
            ),
        ])

    for item in report.get("wordlist_results", []) or []:
        writer.writerow([
            "content_discovery", item.get("url", ""), item.get("status", ""),
            "", "potential" if item.get("potential_hit") else "",
            "method={}; source={}; bytes={}; words={}; type={}; final_url={}; "
            "location={}; server={}; last_modified={}; allow={}; content_hash={}; "
            "response_truncated={}; baseline_match={}; error={}; set_cookie_names={}".format(
                item.get("method", "GET"), item.get("source", "wordlist"),
                item.get("size", 0), item.get("word_count", 0),
                item.get("content_type", ""), item.get("final_url", ""),
                item.get("location", ""), item.get("server", ""),
                item.get("last_modified", ""), item.get("allow", ""),
                item.get("content_hash", ""), item.get("response_truncated", False),
                item.get("baseline_match", False), item.get("error", ""),
                json.dumps(item.get("set_cookie_names", []), ensure_ascii=False, sort_keys=True),
            ),
        ])
    coverage = report.get("coverage_summary", {}) or {}
    for item in report.get("failed_requests", []) or []:
        writer.writerow([
            "request_failure", item.get("url", ""), "", item.get("phase", ""),
            "error", item.get("error_type", "No HTTP response"),
        ])
    for item in report.get("js_fetch_errors", []) or []:
        writer.writerow([
            "javascript_fetch_failure", item.get("url", ""), item.get("status", ""),
            "javascript", "partial", item.get("error_type", "not analyzed"),
        ])
    for url in (report.get("unattempted_js_files", []) or []):
        writer.writerow(["javascript_not_attempted", url, "", "javascript", "partial", "Not fetched/analyzed in this scan"])
    for item in report.get("server_error_responses", []) or []:
        writer.writerow([
            "http_server_error", item.get("url", ""), item.get("status", ""),
            item.get("phase", ""), "partial", "HTTP 5xx response",
        ])
    for item in report.get("restricted_responses", []) or []:
        writer.writerow([
            "http_restricted", item.get("url", ""), item.get("status", ""),
            item.get("phase", ""), "review", "HTTP 401/403 response",
        ])

    if coverage:
        writer.writerow([
            "coverage_summary", "", "", "",
            "partial" if (
                report.get("transport_error_count") or report.get("server_error_response_count")
                or report.get("js_fetch_error_count") or report.get("js_rate_limited_stop")
                or report.get("unattempted_js_files")
                or report.get("content_limit_reached") or report.get("page_limit_reached")
                or report.get("depth_limit_reached") or report.get("wordlist_candidate_limit_reached")
            ) else "no-limit-reported",
            json.dumps(coverage, ensure_ascii=False, sort_keys=True),
        ])
    for note in report.get("content_limit_notes", []) or []:
        writer.writerow(["coverage_warning", "", "", "", "warning", str(note)])

    verification = report.get("subdomain_verification", {}) or {}
    for item in verification.get("results", []) or []:
        writer.writerow([
            "subdomain_verification", item.get("http_url", "") or item.get("host", ""),
            item.get("http_status") if item.get("http_status") is not None else item.get("dns_status", ""),
            item.get("host", ""), item.get("dns_status", ""),
            json.dumps({
                "ip_addresses": item.get("ip_addresses", []),
                "http_result": item.get("http_result", ""),
                "http_url": item.get("http_url", ""),
                "server": item.get("server", ""),
                "error": item.get("error", ""),
            }, ensure_ascii=False, sort_keys=True),
        ])
    if verification.get("truncated"):
        writer.writerow([
            "subdomain_verification_coverage", "", "", "", "partial",
            f"verified={verification.get('verified_count', 0)}; unchecked={verification.get('skipped_count', 0)}",
        ])

    for kind in (
        "emails", "subdomains", "endpoints", "discovered_routes", "js_files",
        "source_maps", "truncated_js_files", "passive_subdomains", "historical_urls",
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
                "method_evidence": item.get("method_evidence", []),
                "sources": item.get("sources", []),
                "parameters": item.get("parameters", []),
                "locations": item.get("locations", []),
            }, ensure_ascii=False, sort_keys=True),
        ])
    for item in report.get("request_intelligence", []) or []:
        writer.writerow([
            "request_intelligence", item.get("url", ""),
            ", ".join(str(code) for code in item.get("status_codes", []) or []),
            item.get("method", ""), item.get("evidence", ""),
            json.dumps({
                "sources": item.get("sources", []),
                "parameter_names": item.get("parameter_names", []),
                "content_types": item.get("content_types", []),
                "initiating_pages": item.get("initiating_pages", []),
                "resource_types": item.get("resource_types", []),
            }, ensure_ascii=False, sort_keys=True),
        ])
    source_coverage = report.get("coverage", {}) or {}
    if source_coverage:
        writer.writerow([
            "source_coverage", source_coverage.get("target", ""), "",
            source_coverage.get("assessment", ""),
            "partial" if source_coverage.get("partial") else "",
            json.dumps(source_coverage, ensure_ascii=False, sort_keys=True),
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
                "sources": item.get("sources", []),
                "observation_count": item.get("observation_count", 1),
                "url_count": item.get("url_count", 1),
                "sample_urls": item.get("sample_urls", []),
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

    history_diff = report.get("history_diff", {}) or {}
    if history_diff:
        writer.writerow([
            "history_diff_summary", "", "", "",
            "partial" if str(history_diff.get("comparison_status", "")).startswith("partial") else "",
            json.dumps({
                key: history_diff.get(key, [])
                for key in (
                    "added_assets", "removed_assets", "changed_assets",
                    "added_endpoints", "removed_endpoints", "changed_endpoints",
                    "added_parameters", "removed_parameters", "changed_parameters",
                    "added_urls", "removed_urls", "changed_urls",
                )
            }, ensure_ascii=False, sort_keys=True),
        ])
        for key, record_type in (
            ("added_assets", "asset_added"),
            ("removed_assets", "asset_removed"),
            ("changed_assets", "asset_changed"),
        ):
            for asset in history_diff.get(key, []) or []:
                writer.writerow([record_type, str(asset), "", "", "", "source=scan_history_diff"])

    for audit in report.get("header_audits", []) or []:
        writer.writerow([
            "security_headers", audit.get("url", ""), "", "", "",
            "missing=" + ", ".join(audit.get("missing", []) or []),
        ])
    return output.getvalue()


def _export_value(value) -> str:
    """Convert report values to readable text without expanding request bodies or secrets."""
    if value is None:
        return ""
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_export_value(item) for item in value)
    return str(value)


def _endpoint_method_evidence(item: dict) -> str:
    records = item.get("method_evidence", []) or []
    if not records:
        methods = item.get("methods", []) or []
        return "; ".join(f"{method}: evidence unavailable" for method in methods) or "No method evidence"
    return "; ".join(
        f"{record.get('method', 'UNKNOWN')}: {', '.join(record.get('evidence', []) or [])}"
        f" [{', '.join(record.get('sources', []) or [])}]"
        for record in records
    )


def _report_sections(report: dict):
    """Create stable tables shared by Markdown and standalone HTML exports."""
    report = report or {}
    pages = report.get("pages", []) or []
    endpoints = report.get("endpoint_inventory", []) or []
    parameters = report.get("parameters", []) or []
    network = report.get("network_observations", []) or []
    cookies = report.get("cookie_map", []) or []
    assets = report.get("asset_inventory", []) or []
    discovery = report.get("wordlist_results", []) or []
    coverage = report.get("coverage_summary", {}) or {}
    text_report = render_text_report(report)
    status = next(
        (line.split("Status:", 1)[1].strip() for line in text_report.splitlines() if line.startswith("Status:")),
        "See coverage summary",
    )

    overview = [
        ("Target", report.get("target", "")),
        ("Status", status),
        ("Started at", report.get("started_at", "")),
        ("Pages crawled", len(pages)),
        ("Endpoint count", len(endpoints)),
        ("Parameter-name count", len(parameters)),
        ("Network request records", len(network)),
        ("Cookie metadata records", len(cookies)),
        ("Asset references", len(assets)),
        ("Content Discovery responses", len(discovery)),
    ]
    sections = [("Scan Overview", ["Field", "Value"], overview)]
    if coverage:
        sections.append((
            "Coverage and Limits", ["Metric", "Value"],
            [(key, value) for key, value in sorted(coverage.items())],
        ))

    sections.append((
        "Pages", ["URL", "Status", "Title", "Content type", "Words", "Bytes", "Depth", "Body truncated"],
        [(
            item.get("url", ""), item.get("status", ""), item.get("title", ""),
            item.get("content_type", ""), item.get("word_count", 0),
            item.get("content_length", 0), item.get("depth", 0), item.get("body_truncated", False),
        ) for item in pages],
    ))
    sections.append((
        "Endpoint Inventory", ["Endpoint", "Methods", "Method evidence", "Sources", "Parameter names", "Locations"],
        [(
            item.get("endpoint", ""), item.get("methods", []), _endpoint_method_evidence(item),
            item.get("sources", []), item.get("parameters", []), item.get("locations", []),
        ) for item in endpoints],
    ))
    source_coverage = report.get("coverage", {}) or {}
    if source_coverage:
        source_rows = [
            ("Assessment", source_coverage.get("assessment", "not calculated")),
            ("Pages", json.dumps(source_coverage.get("pages", {}), ensure_ascii=False, sort_keys=True)),
            ("HTTP outcomes", json.dumps(source_coverage.get("http", {}), ensure_ascii=False, sort_keys=True)),
            ("Discovery counts", json.dumps(source_coverage.get("discovery", {}), ensure_ascii=False, sort_keys=True)),
            ("Endpoint sources", json.dumps((source_coverage.get("sources", {}) or {}).get("endpoints", {}), ensure_ascii=False, sort_keys=True)),
            ("Asset sources", json.dumps((source_coverage.get("sources", {}) or {}).get("assets", {}), ensure_ascii=False, sort_keys=True)),
            ("Request accounting", json.dumps(source_coverage.get("request_accounting", {}), ensure_ascii=False, sort_keys=True)),
        ]
        source_rows.extend(("Known gap", reason) for reason in source_coverage.get("partial_reasons", []) or [])
        source_rows.extend(("Note", note) for note in source_coverage.get("notes", []) or [])
        sections.append(("Source-aware Discovery Coverage", ["Metric", "Value"], source_rows))

    sections.append((
        "Request Intelligence (observed vs inferred)",
        ["Endpoint", "Method", "Evidence", "Sources", "Parameter names", "Content types", "Statuses", "Initiating pages", "Resource types"],
        [(
            item.get("url", ""), item.get("method", ""), item.get("evidence", ""),
            item.get("sources", []), item.get("parameter_names", []),
            item.get("content_types", []), item.get("status_codes", []),
            item.get("initiating_pages", []), item.get("resource_types", []),
        ) for item in report.get("request_intelligence", []) or []],
    ))
    sections.append((
        "Parameter Inventory", ["Name", "Classification", "Methods", "Sources", "Occurrences", "Locations"],
        [(
            item.get("name", ""), item.get("classification", ""), item.get("methods", []),
            item.get("sources", []), item.get("occurrences", 0), item.get("locations", []),
        ) for item in parameters],
    ))
    sections.append((
        "Network Requests (metadata only)",
        ["URL (query values removed)", "Method", "Status", "Resource type", "Query names", "Body names", "Source", "Initiating page"],
        [(
            item.get("url", ""), item.get("method", ""), item.get("status", ""),
            item.get("resource_type", ""), item.get("query_parameters", []),
            item.get("body_parameters", []), item.get("source", ""), item.get("page", ""),
        ) for item in network],
    ))
    sections.append((
        "Cookie Map (names and attributes only)",
        ["URL", "Cookie name", "Domain", "Path", "Secure", "HttpOnly", "SameSite", "Source"],
        [(
            item.get("url", ""), item.get("name", ""), item.get("domain", ""), item.get("path", "/"),
            item.get("secure", False), item.get("httponly", item.get("httpOnly", False)),
            item.get("samesite", item.get("sameSite", "")), item.get("source", ""),
        ) for item in cookies],
    ))
    sections.append((
        "Asset References",
        ["URL (query values removed)", "Kind", "Extension", "Sources", "Referrers", "In scope", "Fetched evidence", "HEAD status", "HEAD result"],
        [(
            item.get("url", ""), item.get("kind", ""), item.get("extension", ""), item.get("sources", []),
            item.get("referrers", []), item.get("in_scope", False),
            (
                "page crawler" if item.get("fetched_by_page_crawler") else
                "JS collector" if item.get("fetched_by_js_collector") else
                "CSS collector" if item.get("fetched_by_css_collector") else "reference only"
            ),
            item.get("probe_status", "") if item.get("probe_checked") else "not checked",
            item.get("probe_result", ""),
        ) for item in assets],
    ))
    sections.append((
        "Content Discovery (GET only)",
        ["URL", "Status", "Bytes", "Words", "Content type", "Potential hit", "Wildcard match", "Response truncated"],
        [(
            item.get("url", ""), item.get("status", ""), item.get("size", ""),
            item.get("word_count", ""), item.get("content_type", ""),
            item.get("potential_hit", False), item.get("baseline_match", False),
            item.get("response_truncated", False),
        ) for item in discovery],
    ))
    forms = report.get("forms", []) or []
    sections.append((
        "HTML Forms (not submitted)", ["Page", "Method", "Action", "Field names", "Possible CSRF field"],
        [(
            item.get("page", ""), item.get("method", "GET"), item.get("action", ""),
            [field.get("name", "") for field in item.get("fields", []) or []],
            item.get("csrf_field_present", False),
        ) for item in forms],
    ))
    findings = report.get("related_findings", []) or []
    sections.append((
        "Correlated Review Findings",
        ["Severity", "Title", "Category", "Confidence", "Evidence", "Recommendation"],
        [(
            item.get("severity", "info"), item.get("title", ""), item.get("category", ""),
            item.get("confidence", ""), item.get("evidence", []), item.get("recommendation", ""),
        ) for item in findings],
    ))
    subdomains = sorted(set(report.get("subdomains", []) or []) | set(report.get("passive_subdomains", []) or []))
    sections.append(("Discovered Subdomains", ["Hostname"], [(value,) for value in subdomains]))
    sections.append(("Historical URL Candidates", ["URL"], [(value,) for value in report.get("historical_urls", []) or []]))
    passive_sources = report.get("passive_sources", []) or []
    sections.append((
        "Passive Source Status", ["Source", "Status", "Count"],
        [(item.get("name", ""), item.get("status", ""), item.get("count", 0)) for item in passive_sources],
    ))
    verification = report.get("subdomain_verification", {}) or {}
    if verification:
        sections.append((
            "Selected Subdomain Verification", ["Hostname", "DNS status", "HTTP status", "Result", "Error"],
            [(
                item.get("host", ""), item.get("dns_status", ""), item.get("http_status", ""),
                item.get("http_result", ""), item.get("error", ""),
            ) for item in verification.get("results", []) or []],
        ))
    notes = list(report.get("content_limit_notes", []) or [])
    notes.extend(report.get("passive_errors", []) or [])
    notes.extend(report.get("css_discovery_errors", []) or [])
    seed_summary = report.get("seed_import_summary", {}) or {}
    if seed_summary:
        notes.extend(seed_summary.get("warnings", []) or [])
    har_summary = report.get("har_import_summary", {}) or {}
    if har_summary:
        notes.extend(har_summary.get("warnings", []) or [])
    sections.append(("Coverage and Import Warnings", ["Warning / Note"], [(str(note),) for note in notes]))

    history = report.get("history_diff", {}) or {}
    history_rows = []
    for key, label in (
        ("added_urls", "Added page"), ("removed_urls", "Removed page"), ("changed_urls", "Changed page"),
        ("added_endpoints", "Added endpoint"), ("removed_endpoints", "Removed endpoint"), ("changed_endpoints", "Changed endpoint"),
        ("added_parameters", "Added parameter"), ("removed_parameters", "Removed parameter"), ("changed_parameters", "Changed parameter"),
        ("added_assets", "Added asset"), ("removed_assets", "Removed asset"), ("changed_assets", "Changed asset"),
    ):
        history_rows.extend((label, item) for item in history.get(key, []) or [])
    sections.append(("History Changes", ["Change type", "Item"], history_rows))
    return sections


def render_markdown_report(report: dict) -> str:
    """Render a standalone Markdown report containing the unified recon inventories."""
    import html

    report = report or {}
    text_report = render_text_report(report)
    status = next(
        (line.split("Status:", 1)[1].strip() for line in text_report.splitlines() if line.startswith("Status:")),
        "See coverage summary",
    )

    def cell(value):
        text = _export_value(value).replace("\r", " ").replace("\n", " ")
        text = html.escape(text, quote=False)
        return text.replace("|", r"\|")

    lines = [
        "# Recon-GUI Reconnaissance Report",
        "",
        f"- Target: {cell(report.get('target', '(not recorded)'))}",
        f"- Status: {cell(status)}",
        f"- Started at: {cell(report.get('started_at', '(not recorded)'))}",
        "",
        "> The coverage summary documents configured limits and known gaps. An unreported gap does not prove 100% coverage.",
        "",
    ]
    for title, headers, rows in _report_sections(report):
        lines.extend(("", f"## {title}", ""))
        if not rows:
            lines.extend(["(none found)", ""])
            continue
        lines.append("| " + " | ".join(cell(header) for header in headers) + " |")
        lines.append("| " + " | ".join("---" for _ in headers) + " |")
        for row in rows:
            values = list(row)
            if len(values) < len(headers):
                values.extend([""] * (len(headers) - len(values)))
            lines.append("| " + " | ".join(cell(value) for value in values[:len(headers)]) + " |")
        lines.append("")
    lines.extend(("", "## Data handling", "",
                  "Request and response bodies, query values, and cookie/token values are not intentionally included in the request and cookie inventories. Review exported URLs and findings before sharing.",
                  ""))
    return "\n".join(lines)


def render_html_report(report: dict) -> str:
    """Render a self-contained HTML report; every dynamic value is HTML-escaped."""
    import html

    report = report or {}
    text_report = render_text_report(report)
    status = next(
        (line.split("Status:", 1)[1].strip() for line in text_report.splitlines() if line.startswith("Status:")),
        "See coverage summary",
    )

    def escape(value):
        return html.escape(_export_value(value), quote=True)

    sections_html = []
    for title, headers, rows in _report_sections(report):
        head = "".join(f"<th scope=\"col\">{escape(header)}</th>" for header in headers)
        if rows:
            body_rows = []
            for row in rows:
                values = list(row)
                if len(values) < len(headers):
                    values.extend([""] * (len(headers) - len(values)))
                cells = "".join(f"<td>{escape(value)}</td>" for value in values[:len(headers)])
                body_rows.append(f"<tr>{cells}</tr>")
            body = "".join(body_rows)
        else:
            body = f"<tr><td colspan=\"{len(headers)}\" class=\"empty\">(none found)</td></tr>"
        sections_html.append(
            f"<section><h2>{escape(title)}</h2><div class=\"table-wrap\"><table>"
            f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div></section>"
        )
    title = "Recon-GUI Reconnaissance Report"
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{escape(title)}</title><style>"
        ":root{color-scheme:light;--ink:#172b4d;--muted:#52627a;--line:#d8e0eb;--paper:#f4f7fb;--white:#fff;}"
        "*{box-sizing:border-box}body{margin:0;background:var(--paper);color:#1e293b;font:14px/1.5 Segoe UI,Arial,sans-serif}"
        "header{background:var(--ink);color:#fff;padding:28px max(20px,calc((100vw - 1400px)/2))}"
        "header h1{margin:0 0 8px;font-size:25px}header p{margin:4px 0;color:#d6e2f3;overflow-wrap:anywhere}"
        "main{max-width:1400px;margin:auto;padding:20px}section{margin:20px 0;background:var(--white);border:1px solid var(--line);border-radius:10px;overflow:hidden}"
        "h2{font-size:18px;margin:0;padding:14px 16px;color:var(--ink);border-bottom:1px solid var(--line)}"
        ".table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:12px}th,td{padding:9px 11px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line);white-space:pre-wrap;overflow-wrap:anywhere;min-width:90px;max-width:520px}"
        "th{position:sticky;top:0;background:#edf2f8;color:var(--ink)}tr:last-child td{border-bottom:0}.empty{color:var(--muted);font-style:italic}"
        "footer{max-width:1400px;margin:auto;padding:0 20px 28px;color:var(--muted);font-size:12px}.pill{display:inline-block;border:1px solid #c9d5e5;border-radius:20px;padding:2px 9px;background:#fff;color:var(--ink)}"
        "@media print{body{background:#fff}section{break-inside:avoid}header{background:#fff;color:#111;border-bottom:2px solid #333;padding:16px}header p{color:#333}main{padding:0}section{border-color:#888}h2{color:#111}}"
        "</style></head><body>"
        f"<header><h1>{escape(title)}</h1><p>Target: {escape(report.get('target', '(not recorded)'))}</p>"
        f"<p>Status: <span class=\"pill\">{escape(status)}</span></p>"
        f"<p>Started: {escape(report.get('started_at', '(not recorded)'))}</p></header>"
        f"<main>{''.join(sections_html)}</main>"
        "<footer>Coverage limits are shown explicitly; a clean report does not prove full coverage. "
        "Review URLs and findings before sharing. Request bodies and cookie/token values are not intentionally included in the inventories.</footer>"
        "</body></html>"
    )
