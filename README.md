# Recon-GUI — Desktop Web Reconnaissance

Recon-GUI is a Python desktop application for mapping and documenting web assets on targets you own or are explicitly authorized to assess.

## Core features

- Bounded same-host crawling with configurable depth, page count, and concurrency.
- Canonical URL handling, redirect-chain tracking, response metadata, page hashes, similarity groups, and soft-404 candidates.
- Hidden-route discovery from forms, iframes, data attributes, meta refresh, inline scripts/comments, sitemaps, robots.txt, and same-host JavaScript.
- Optional Playwright rendering to discover routes created by client-side JavaScript.
- JavaScript collection, endpoint extraction, source-map references, and bounded follow-up route crawling.
- HTML form inventory (fields, method, action, and possible CSRF field names) without submitting forms.
- JSON-LD extraction and redacted candidate detection for known token/key patterns and secret-like assignments.
- Security-header audits, favicon hash, emails, and subdomains.
- Optional passive lookups through Certificate Transparency (crt.sh) and Wayback CDX; results are not actively probed by the passive module.
- Optional Content Discovery using a custom or bundled wordlist, with response history and wildcard/soft-hit classification.
- Optional in-memory Bearer token, Basic Auth, and Cookie headers for the built-in crawler, JavaScript collection, and Content Discovery.
- Local SQLite scan history grouped by origin, including newly added, removed, and changed URL comparisons between scans.
- Filterable results and readable TXT, machine-readable JSON, and spreadsheet-friendly CSV reports.
- Optional external CLI integrations for Subfinder, GAU, Nuclei, and ffuf. They run only when explicitly selected in the External Tools tab.
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

The renderer is bounded to 30 pages and two concurrent tabs. Cross-host browser requests are blocked. If Playwright or Chromium is not installed, the ordinary HTTP crawler continues and logs a clear message.

## Optional external tools

Install the tools you need separately using their official installation instructions and make sure their executable is available on PATH.

- **Subfinder** — passive subdomain enumeration.
- **GAU** — historical URL discovery.
- **Nuclei** — template-based security checks, explicitly initiated from the GUI with a conservative rate limit.
- **ffuf** — wordlist path discovery, explicitly initiated from the GUI with a conservative rate limit and a selected local wordlist.

The GUI's External Tools tab can check which tools are installed. Nuclei and ffuf require a confirmation before execution. Their CLI processes have a bounded runtime and output size and can be stopped from the GUI. CLI integrations do not inherit the GUI's session token or cookies; configure them separately only when appropriate for your authorized test.

## Authentication and data handling

- Built-in authentication fields are held in application memory only and are not added to reports or scan-history records.
- Candidate secret findings contain a type, source, severity, and a redacted marker; the matched raw value is never included.
- Form analysis only inspects markup and does not submit the form or perform login attempts.
- The history database is local to your user profile. On Windows it is normally stored at %LOCALAPPDATA%\Recon-GUI\history.sqlite3; other systems use ~/.recon-gui/history.sqlite3 unless XDG_DATA_HOME is set.
- Export files can still contain URLs, email addresses, hostnames, and findings. Review them before sharing.

## HTTP 429 and request pacing

If the origin returns HTTP 429, Recon-GUI parses Retry-After (seconds or an HTTP date), pauses queued requests for supported waits, and resumes at the configured rate. If no usable retry guidance is provided, the requested wait exceeds the automatic ceiling, or the limit recurs too often, that phase stops safely. The application does not try to evade server-enforced limits. Content Discovery is low-rate by default; when a crawl delay is present, it reduces the path scanner to one worker and applies the delay between requests.

## Tests

    python -m pip install pytest pytest-timeout aiohttp beautifulsoup4 lxml requests mmh3
    python -m pytest -q

GitHub Actions runs compile checks and the regression suite with per-test and overall deadlines.

## Legal

Use only on systems you own or where you have explicit authorization. Respect scope, service terms, traffic limits, and any program rules. This application is a reconnaissance aid; findings are candidates that require manual validation.
