from gui.report_export import render_text_report


def test_txt_report_includes_core_sections_and_hidden_discovery_results():
    report = {
        "target": "https://example.com",
        "pages": [{"url": "https://example.com/", "status": 200, "title": "Home",
                   "word_count": 10, "content_length": 80, "redirect_chain": []}],
        "filtered_pages": [{"url": "https://example.com/", "status": 200, "title": "Home",
                            "word_count": 10, "content_length": 80, "redirect_chain": []}],
        "matcher_description": "match-status=200",
        "emails": ["security@example.com"],
        "discovered_routes": ["https://example.com/admin"],
        "wordlist_results": [{"url": "https://example.com/robots.txt", "status": 200,
                              "size": 42, "word_count": 5, "potential_hit": True}],
        "wordlist_hits": [{"url": "https://example.com/robots.txt", "status": 200,
                           "size": 42, "word_count": 5}],
        "header_audits": [{"url": "https://example.com/", "present": {"X-Frame-Options": "DENY"},
                           "missing": ["Content-Security-Policy"]}],
        "similarity": {},
    }
    text = render_text_report(report)
    assert "RECON-GUI - RECONNAISSANCE REPORT" in text
    assert "[200] https://example.com/" in text
    assert "security@example.com" in text
    assert "https://example.com/admin" in text
    assert "CONTENT DISCOVERY - ALL RESPONSES" in text
    assert "POTENTIAL CONTENT DISCOVERY HITS" in text
    assert "MISSING  Content-Security-Policy" in text


def test_txt_report_handles_empty_report():
    text = render_text_report({})
    assert "Pages crawled: 0" in text
    assert "(not enabled or no responses)" in text


def test_txt_report_includes_rate_limit_outcomes():
    text = render_text_report({
        "crawler_rate_limited_stop": True,
        "wordlist_rate_limited_stop": False,
    })
    assert "Crawler rate limit: stopped safely" in text
    assert "Content Discovery rate limit: not triggered / resumed after Retry-After" in text




def test_txt_report_explains_429_cooldowns_and_unresolved_paths():
    text = render_text_report({
        "target": "https://example.com/",
        "rate_limit_stopped": False,
        "rate_limit_summary": {
            "stopped": False,
            "cooldowns_applied": 1,
            "consecutive_cooldowns": 0,
            "max_cooldowns": 3,
            "events": [{
                "phase": "Crawler", "url": "https://example.com/admin",
                "delay_seconds": 15, "reason": "fallback backoff (no valid Retry-After)",
            }],
        },
        "rate_limit_attempts": [{
            "url": "https://example.com/admin", "depth": 1, "attempt": 1,
        }],
        "crawler_unresolved_rate_limited_urls": ["https://example.com/admin"],
        "wordlist_unresolved_rate_limited_urls": ["https://example.com/backup"],
    })
    assert "Status: Partial (rate limited)" in text
    assert "HTTP 429 RECOVERY" in text
    assert "Cooldowns applied: 1" in text
    assert "https://example.com/admin" in text
    assert "https://example.com/backup" in text
