# Recon Crawler v2

Desktop website crawler for reconnaissance on Windows.
Inspired by SiteOne Crawler + vyre (Rust subdomain prober).

## Features
- Deep crawl with configurable depth & page limit
- Full redirect chain tracking (301/302/307/308)
- Status codes + colors (200 green, 3xx yellow, 4xx red)
- Word count per page
- Similarity detection (exact dupes, soft-404, path variants)
- JS file collection + endpoint extraction + source maps
- Wordlist-based directory/file scanner (gobuster-like)
- Security header audit
- Email & subdomain harvesting
- Favicon hash (mmh3) - identifies tech and shared infra
- Consistent descriptive User-Agent and verified TLS certificates
- Matchers/Filters (status code, content length, word count)
- Bounded concurrency (default 5, maximum 20 in the crawler GUI)
- Export to JSON

## Quick Start
    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt
    python main.py

## Legal
Use only on targets you own or have permission to test.
