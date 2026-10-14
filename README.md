# Recon-GUI — Desktop Web Reconnaissance

Recon-GUI is a Python desktop application for mapping and documenting web assets on targets you own or are explicitly authorized to assess.

## Core features

- Bounded same-host crawling with configurable depth, page count, and concurrency.
- Canonical URL handling, redirect-chain tracking, response metadata, page hashes, similarity groups, and soft-404 candidates.
- Hidden-route discovery from forms, iframes, data attributes, meta refresh, inline scripts/comments, sitemaps, robots.txt, and same-host JavaScript.
- Optional Playwright rendering to discover routes created by client-side JavaScript, with same-origin request/response metadata capture.
- Optional headed Manual Browser Session for user-driven login/MFA and browsing. Captures same-origin request methods, status codes, query/body parameter names, and cookie names/attributes; cookie/token values and request bodies are not exported.
- JavaScript collection, endpoint extraction, source-map references, static method inference for common `fetch`, `axios`, XHR, and jQuery calls, and follow-up route crawling. Static method inference is a lead, not proof the request executed.
- Unified endpoint inventory with methods, discovery sources, request initiator page, resource type, query parameter names, and observed body parameter names. Query strings and body values are never retained in the request inventory.
- Evidence-backed correlated review findings with severity/confidence, supporting evidence, and manual-review recommendations; these are leads, not confirmed vulnerabilities.
- HTML form inventory (fields, method, action, and possible CSRF field names) without submitting forms.
- JSON-LD extraction and redacted candidate detection for known token/key patterns and secret-like assignments.
- Security-header audits, favicon hash, emails, and subdomains.
- Passive lookups through Certificate Transparency (crt.sh), Wayback CDX, and optional Subfinder (when installed). All passive hostname sources are merged; discovered subdomains are reported only and are never automatically actively crawled. Historical URLs enter the crawl only when “Crawl same-host historical URLs” is enabled.
- Expanded Content Discovery using the complete custom or bundled wordlist by default (no implicit 500-word truncation), configurable extensions and exact paths, deduplication, response hashes, status/redirect metadata, response header hints, cookie attribute metadata, and wildcard/soft-404 classification. Each wordlist candidate is currently sent as a GET request only.
- Shared in-memory HTTP cookie jar between crawl, JavaScript collection, and Content Discovery phases, plus optional imported Cookie header. Session values are not written to reports or scan history.
- Local SQLite scan history grouped by origin, including newly added, removed, and changed URL, endpoint, and parameter comparisons between scans. Partial/stopped/rate-limited scans do not infer removals.
- Filterable results and readable TXT, machine-readable JSON, and spreadsheet-friendly CSV reports.
- Optional external CLI integrations for GAU, Nuclei, and ffuf in the External Tools tab. Subfinder is a separate passive hostname discovery phase in Scan Options; Nmap remains excluded from the core web crawler because port scanning is a different activity.
- Honors a valid Crawl-delay in robots.txt. On HTTP 429, the crawler waits only when the response provides a supported Retry-After; otherwise it stops safely rather than bypassing rate limits.

## Quick start (Windows)

    python -m venv .venv
    .venv\Scripts\activate
    python -m pip install -r requirements.txt
    python main.py

## Optional JavaScript rendering

Playwright is deliberately not a core dependency. To enable the checkbox in the GUI:

    python -m pip install -r requirements-optional.txt
    playwright install chromium

The automated renderer is bounded to 30 pages and two concurrent tabs. It uses a shared browser context across rendered pages so same-origin cookie state can persist; cross-origin requests are blocked. The optional Manual Browser Session opens a visible Chromium window for up to 90 seconds so you can log in or navigate. Install Playwright and Chromium first.

## Optional external tools

Install the tools you need separately using their official installation instructions and make sure their executable is available on PATH.

- **GAU** — historical URL discovery.
- **Nuclei** — template-based security checks, explicitly initiated from the GUI with a conservative rate limit.
- **ffuf** — wordlist path discovery, explicitly initiated from the GUI with a conservative rate limit and a selected local wordlist.

The GUI's External Tools tab can check which CLI tools are installed. Subfinder is used separately as an optional passive hostname source and is never used to crawl discovered hosts automatically; Nmap remains outside the core web crawler. External CLIs have independent rate-limit handling and do not share the built-in crawler's HTTP 429 Retry-After manager; stop active CLI tools and respect the target's retry guidance if rate limiting is observed. Nuclei and ffuf require a confirmation before execution. Their CLI processes have a bounded runtime and output size and can be stopped from the GUI. CLI integrations do not inherit the GUI's session token or cookies; configure them separately only when appropriate for your authorized test.

## Authentication and data handling

- Built-in authentication fields and session cookie values are kept in application memory only and are not added to reports or scan-history records.
- The Cookie Map records cookie names and safe attributes only. Network Request records include normalized URL paths, methods, response metadata, source, and parameter names, never query/body values or raw request bodies.
- Manual browser capture is opt-in and user-driven; it does not automatically submit HTML forms or click buttons.
- Candidate secret findings contain a type, source, severity, and a redacted marker; the matched raw value is never included.
- Form analysis only inspects markup and does not submit the form or perform login attempts.
- The history database is local to your user profile. On Windows it is normally stored at %LOCALAPPDATA%\Recon-GUI\history.sqlite3; other systems use ~/.recon-gui/history.sqlite3 unless XDG_DATA_HOME is set.
- Export files can still contain URLs, email addresses, hostnames, and findings. Review them before sharing.

## HTTP 429 and request pacing

If the origin returns HTTP 429, Recon-GUI parses Retry-After (seconds or an HTTP date), pauses queued requests for supported waits, and resumes at the configured rate. If no usable retry guidance is provided, the requested wait exceeds the automatic ceiling, or the limit recurs too often, that phase stops safely. The application does not try to evade server-enforced limits. Content Discovery is low-rate by default; when a crawl delay is present, it reduces the path scanner to one worker and applies the delay between requests. Wordlist scanning has no implicit word-count cap, but it still has an explicit response-body read cap (currently 1 MiB per response), timeouts, a bounded concurrency setting, and server-respecting stop behavior. The UI reports configured page limits and rate-limit stops; “all results” cannot be guaranteed when paths are unknown or access is restricted.

## Build a portable Windows app

A Windows build workflow is included at Actions → Windows application build. Run it manually, or push a version tag beginning with `v`. Download the `ReconGUI-Windows-...` artifact from the successful workflow, extract the entire folder, and run `ReconGUI.exe`. Keep the companion files and folders next to the executable; this is a portable application folder, not a single-file installer. Optional Playwright and external CLI tools still need their separate installation steps.

## Tests

    python -m pip install pytest pytest-timeout aiohttp beautifulsoup4 lxml requests mmh3
    python -m pytest -q

GitHub Actions runs compile checks and the regression suite with per-test and overall deadlines.

## Legal

Use only on systems you own or where you have explicit authorization. Respect scope, service terms, traffic limits, and any program rules. This application is a reconnaissance aid; findings are candidates that require manual validation.
