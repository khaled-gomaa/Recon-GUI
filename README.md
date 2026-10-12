# Recon Crawler v2

Desktop website crawler for reconnaissance on Windows.
Inspired by SiteOne Crawler + vyre (Rust subdomain prober).

## Features
- Deep crawl with configurable depth & page limit
- Canonical URL handling (host casing, default ports, fragments, IDNs) to reduce duplicate requests
- Honors HTML `<base href>` when resolving links and JavaScript assets
- Full redirect chain tracking (301/302/307/308)
- Status codes + colors (200 green, 3xx yellow, 4xx red)
- Word count per page
- Similarity detection (exact dupes, soft-404, path variants)
- HTML discovery from hidden anchors, forms, iframe actions, data attributes, meta refresh, inline scripts/comments, and same-host routes extracted from external JavaScript
- JavaScript file collection + endpoint extraction + source maps; discovered first-party routes are crawled in bounded follow-up passes
- Low-rate wordlist path checks with capped wordlist/response sizes and automatic stop on HTTP 429 (including baseline requests)
- Security header audit
- Email & subdomain harvesting
- Favicon hash (mmh3) - identifies tech and shared infra
- Consistent descriptive User-Agent and verified TLS certificates
- Matchers/Filters (status code, content length, word count) with exact values, numeric ranges (1000-2000), and status classes (2xx/3xx/5xx)
- Optional Content Discovery tab using a custom wordlist or bundled common wordlist; full response history includes 404s and likely wildcard responses
- HTTP status rows use consistent foreground/background coloring in both page and content-discovery tables
- Bounded concurrency (default 5, maximum 20 in the crawler GUI)
- Worker resilience: logging/reporting callback failures do not break page/path discovery
- Regression tests run with per-test and overall CI deadlines to avoid multi-hour hangs
- Export complete results as readable TXT or structured JSON
- Polished desktop UI with grouped scan controls, dedicated Match/Exclude filters, Clear Filters, and local re-filtering
- HTTP 429 handling respects Retry-After, pauses queued requests, and stops safely if the server provides no usable retry guidance

## Using the discovery features

- **Hidden link discovery** runs with the normal crawl. It checks anchors, forms, iframe/frame targets, canonical/alternate links, data attributes, meta refreshes, inline JavaScript, HTML comments, and routes extracted from same-host JavaScript bundles. It then follows discovered same-host routes in up to two bounded passes, subject to the configured page/depth limits.
- **Content Discovery** is an optional active phase. Tick the Content Discovery checkbox before starting. Leave the wordlist field blank to use the bundled `wordlists/common.txt`, or browse to a custom wordlist. The Content Discovery tab shows each HTTP response (including 404s), response size, approximate word count, status color, and a likely-hit/wildcard classification. Scanning is capped and stops scheduling further requests after HTTP 429.
- **Filters** can be changed before or after a scan. Enter comma-separated exact values (e.g. `200,301`), numeric ranges (e.g. `1000-2000`), and status classes such as `2xx` or `5xx`, then click **Apply filters**. “Match” fields keep matching results; “Filter” fields exclude matching results. **Clear** resets all fields. Applying filters does not repeat network requests.
- **HTTP 429**: if the server supplies a valid `Retry-After` of at most 120 seconds, queued requests pause for that duration then resume at the configured rate. If the header is missing/invalid, the wait exceeds that bound, or rate limiting repeats too often, the relevant phase stops safely. The app does not try to bypass rate limits. The Stop button remains responsive during cool-downs.
- **Export**: use **Export TXT** for a readable report containing all pages, currently filtered pages, recon findings, content-discovery responses, potential hits, header audits, and similarity findings; use **Export JSON** for machine-readable data.
- Use active Content Discovery only for targets you own or are explicitly authorized to test.

## Quick Start
    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt
    python main.py

## Legal
Use only on targets you own or have permission to test.
