# Recon-GUI — Desktop Web Reconnaissance

Recon-GUI is a Python desktop application for mapping and documenting web assets on targets you own or are explicitly authorized to assess.

## Core features

- Same-host crawling with configurable depth, page count (up to 5000), and concurrency. When page or depth limits leave additional links unvisited, the scan is explicitly marked partial and history comparisons do not infer removals from incomplete coverage.
- Import extra crawl seeds from TXT URL lists, Search Console-style CSV exports, XML/gzip sitemaps, JSON URL collections, or common access logs. Imports are deduplicated and restricted to the exact configured hostname; imported seeds are starting points, not authorization checks, and still obey normal crawl limits. This helps discover orphan pages that internal links alone cannot reveal.
- The JavaScript renderer performs a small, bounded scroll sequence per page to trigger lazy-loaded and infinite-scroll content without clicking controls or submitting forms. This improves SPA coverage but cannot guarantee that every dynamically generated record or route is exposed.
- Canonical URL handling, redirect-chain tracking, response metadata, page hashes, similarity groups, and soft-404 candidates.
- Hidden-route discovery from forms, iframes, data attributes, meta refresh, inline scripts/comments, sitemaps, robots.txt, and same-host JavaScript.
- Static asset reference inventory from images/srcset, scripts, stylesheets, fonts, media, preload/prefetch links, inline CSS URLs, and downloadable files. Asset URLs have query values removed in the inventory; entries explicitly distinguish references from URLs that were actually requested by the page crawler or JavaScript collector. External asset links are recorded as references only and are not probed. Optional **Check same-origin asset links with HEAD** validates referenced paths using response status/headers only; it does not download bodies or follow redirects, is bounded by a configurable per-scan cap, and honors Retry-After or stops safely.
- Optional Playwright rendering to discover routes created by client-side JavaScript, with same-origin request/response metadata capture.
- Recursive same-origin CSS discovery: fetches referenced stylesheets, parses `url()`, `@import`, and source-map references, records nested image/font/media/download assets, and reports CSS truncation/errors. External CSS references are inventory-only and are never fetched.
- Optional headed Manual Browser Session for user-driven login/MFA and browsing. The capture window is configurable (30–600 seconds; 180 seconds by default). Same-origin request methods/statuses, parameter names, and cookie metadata are recorded; cookie/token values and request bodies are not exported. Cookie and localStorage state are handed directly in memory to the subsequent JS-render phase when enabled; browser state is never written to disk/report. sessionStorage is not automatically transferred.
- JavaScript collection without a fixed file-count cap, endpoint extraction, source-map references, static method inference for common `fetch`, `axios`, XHR, and jQuery calls (including template-literal routes with dynamic path placeholders), and iterative follow-up route crawling until no new pages are added or the configured crawler boundary is reached. Each JS file is still individually capped at 2 MiB and oversized files are reported as truncated. Static method inference is a lead, not proof the request executed.
- Unified endpoint inventory with methods, discovery sources, request initiator page, resource type, query parameter names, and observed body parameter names. Query strings and body values are never retained in the request inventory.
- Import button for browser/Burp-exported HAR files. HAR imports are read-only: only requests matching the configured target hostname are merged into the Network Requests, Cookie Map, endpoint, and parameter inventories. URL query values, request/response bodies, and cookie values are discarded; oversized or truncated imports display warnings.
- Evidence-backed correlated review findings with severity/confidence, supporting evidence, and manual-review recommendations; these are leads, not confirmed vulnerabilities.
- HTML form inventory (fields, method, action, and possible CSRF field names) without submitting forms.
- JSON-LD extraction and redacted candidate detection for known token/key patterns and secret-like assignments.
- Security-header audits, favicon hash, emails, and subdomains.
- Passive lookups through Certificate Transparency (crt.sh), Wayback CDX (up to 10,000 archived URLs, marked partial when the ceiling is reached), and optional Subfinder (when installed). crt.sh results are parsed without the old 500-host cap. All passive hostname sources are merged; discovered subdomains are reported only and are never automatically crawled. A separate Subdomains tab lets you explicitly select hosts for bounded DNS + one HTTP HEAD check, review resolved IPs/statuses, and set one selected hostname as the next scan target. The verifier pins connections to the validated public DNS answers and blocks HTTP probes when DNS returns private, loopback, link-local, or otherwise non-public IPs. It never follows redirects or sends session credentials. This check does not prove bounty-program authorization. Same-host archived query URLs also feed parameter-name inventory without requiring active requests. Historical URLs enter the crawl only when “Crawl same-host historical URLs” is enabled.
- Streaming Content Discovery using the complete custom or bundled wordlist by default (no implicit 500-word truncation), a bounded request queue, duplicate-path suppression, expanded built-in extensions and a custom extension list. The GUI exposes optional word and generated-path caps (both default to 0 = unlimited); if either cap is actually reached, the scan/history is marked partial. Optional **Recursive directory discovery** reuses the same wordlist beneath directory-like hits, with a selectable recursion depth from 1–5 and the same global generated-path cap across all rounds. It is off by default; reaching the recursion-depth ceiling with further directory candidates marks the scan/history partial. Each candidate is sent as a GET request only.
- Shared in-memory HTTP cookie jar between crawl, JavaScript collection, Content Discovery, and optional asset HEAD checks, plus optional imported Cookie header. Session values are not written to reports or scan history.
- A **Coverage / Gaps** tab explains reached page/depth/wordlist/recursion caps, rate limits, truncated data, failed requests (including JavaScript assets that returned errors), HTTP 5xx responses, rate-limited JavaScript discovery, and restricted 401/403 responses. Request diagnostics strip query strings and omit raw exception messages. A scan is not labelled complete when observed transport errors or server-error responses leave evidence incomplete. Local SQLite scan history grouped by origin compares URL, endpoint, parameter, and asset-reference additions/removals/changes; incomplete, stopped, rate-limited, request-failed, server-error, or capped asset-probe phases do not infer removals.
- Filterable results and readable TXT, machine-readable JSON, and spreadsheet-friendly CSV reports.
- Optional external CLI integrations for GAU, Nuclei, and ffuf in the External Tools tab. Subfinder is a separate passive hostname discovery phase in Scan Options; Nmap remains excluded from the core web crawler because port scanning is a different activity.
- Honors a valid Crawl-delay in robots.txt. On HTTP 429, the crawler waits only when the response provides a supported Retry-After; otherwise it stops safely rather than bypassing rate limits.

## Quick start (Windows and Linux)

Recon-GUI runs from source with Python and PySide6 on both Windows and Linux. On Windows, the included launcher creates an isolated `.venv`, installs every dependency from `requirements.txt` (including public-suffix support for domain-scope checks), verifies `tldextract`, and then starts the app.

### Windows (recommended)

Double-click `run_windows.bat`, or launch it from Command Prompt:

    run_windows.bat

The first run requires Python 3.12, an internet connection for dependency installation, and permission to create files in the project folder. Dependencies are installed in the project's `.venv`; they are not added to other Python environments. Later launches reuse that environment and verify/update requirements.

### Windows (manual PowerShell setup)

    py -3.12 -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
    python main.py

If PowerShell blocks activation, use Command Prompt and run:

    py -3.12 -m venv .venv
    .venv\Scripts\activate.bat
    python -m pip install -r requirements.txt
    python main.py

### Troubleshooting: missing `tldextract`

If the log reports `No module named 'tldextract'`, install requirements into the exact interpreter used to launch Recon-GUI:

    py -m pip install -r requirements.txt

With a project virtual environment, use:

    .venv\Scripts\python.exe -m pip install -r requirements.txt

Do not ignore the error during explicit subdomain verification: public-suffix support is used to avoid treating unrelated hosted tenants as one authorized domain.

### Troubleshooting: portable Windows build reports missing `.tld_set_snapshot`

If the portable `ReconGUI.exe` reports `No remote Public Suffix List found` or a missing `tldextract\\.tld_set_snapshot` file, that build is missing required packaged data. It is not fixed by changing the target URL or disabling the network. Download a newly built Windows artifact that passes the `--self-test-domain-scope` smoke test. The build pipeline now stages the snapshot explicitly, checks that the file exists inside the packaged application, and runs the domain-scope self-test before uploading it.

Older portable folders cannot repair their own missing bundled resource. Keep the new artifact's entire folder structure together when extracting it; do not copy only `ReconGUI.exe` out of the folder.

### Linux (Ubuntu/Debian/Kali)

    python3.12 -m venv .venv
    source .venv/bin/activate
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
    python main.py

Install Python 3.12 and the system's standard Qt/X11 or Wayland libraries first. If the GUI reports a missing Qt platform plugin or XCB library, install the corresponding system libraries provided by your Linux distribution. On a headless machine, a desktop session or remote desktop is needed to show the GUI.

## Optional JavaScript rendering

Playwright is deliberately not a core dependency. To enable the checkbox in the GUI:

    python -m pip install -r requirements-optional.txt
    playwright install chromium

The automated renderer processes crawled HTML pages up to the configured Max pages limit (up to 5000) with two concurrent tabs. It uses a shared browser context across rendered pages so same-origin cookie state can persist; cross-origin requests are blocked. The optional Manual Browser Session opens a visible Chromium window for the configured period, allowing manual login and navigation before the HTTP crawl begins. Captured cookies and localStorage state are passed to the later rendering phase in memory only. Install Playwright and Chromium first.

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
- External seed imports are subject to a 50 MiB source-file cap, a 100 MiB decompressed-file cap, and a 100,000 URL cap. Reaching the URL cap is shown as partial coverage. Imported URLs may carry query values from logs/exports; review reports before sharing them.
- Candidate secret findings contain a type, source, severity, and a redacted marker; the matched raw value is never included.
- Form analysis only inspects markup and does not submit the form or perform login attempts.
- The history database is local to your user profile. On Windows it is normally stored at %LOCALAPPDATA%\Recon-GUI\history.sqlite3; other systems use ~/.recon-gui/history.sqlite3 unless XDG_DATA_HOME is set. Oversized HTML/XML/robots responses, JS files, and Content Discovery response bodies are marked as truncated in the coverage report. A scan with such truncated evidence is flagged partial instead of implying complete coverage.
- Export files can still contain URLs, email addresses, hostnames, and findings. Review them before sharing.

## HTTP 429 and request pacing

If the origin returns HTTP 429, Recon-GUI parses Retry-After (seconds or an HTTP date), pauses queued requests for supported waits, and resumes at the configured rate. If no usable retry guidance is provided, the requested wait exceeds the automatic ceiling, or the limit recurs too often, that phase stops safely. The application does not try to evade server-enforced limits. Content Discovery is low-rate by default; when a crawl delay is present, it reduces the path scanner to one worker and applies the delay between requests. Wordlist scanning has no implicit word-count cap, but it still has an explicit response-body read cap (currently 1 MiB per response), timeouts, a bounded concurrency setting, and server-respecting stop behavior. The UI reports configured page limits and rate-limit stops; “all results” cannot be guaranteed when paths are unknown or access is restricted.

## Cross-platform validation

GitHub Actions runs syntax checks and the regression suite on both `ubuntu-latest` and `windows-latest` using Python 3.12. You can run the source with `python main.py` on Windows or Linux. Optional Playwright and external CLI tools still need their separate installation steps.

## Portable Windows build

A portable Windows application folder can be built from Actions → **Windows portable application build**. Choose **Run workflow**, then download the successful `ReconGUI-Windows-...` artifact. Extract the entire folder and run `ReconGUI.exe`; keep its companion files and folders next to the executable. The workflow also runs for pull requests and pushes to `main`. This portable build is optional; source-based execution remains supported on Windows and Linux.

## Tests

    python -m pip install pytest pytest-timeout aiohttp beautifulsoup4 lxml requests mmh3 tldextract
    python -m pytest -q

GitHub Actions runs compile checks and the regression suite with per-test and overall deadlines.

## Legal

Use only on systems you own or where you have explicit authorization. Respect scope, service terms, traffic limits, and any program rules. This application is a reconnaissance aid; findings are candidates that require manual validation.
