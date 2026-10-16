from types import SimpleNamespace

from recon.coverage import CoverageTracker, build_coverage_report
from recon.request_intelligence import merge_observations, normalize_observation


def test_coverage_tracker_deduplicates_sanitized_request_candidates_and_tracks_limits():
    tracker = CoverageTracker()
    assert tracker.add_candidate("https://example.test/a?token=private", "html")
    assert not tracker.add_candidate("https://example.test/a?token=other", "js")
    tracker.add_result(
        url="https://example.test/a?token=private", status=200,
        method="GET", source="http-crawl",
    )
    tracker.mark_pending(1)
    snapshot = tracker.snapshot()
    assert snapshot["discovered"] == 1
    assert snapshot["crawled"] == 1
    assert snapshot["pending"] == 1
    assert snapshot["partial"] is True
    assert snapshot["source_counts"]["html"] == 1
    assert "private" not in repr(snapshot)


def test_build_coverage_report_exposes_sources_and_known_gaps_without_query_values():
    pages = [
        SimpleNamespace(url="https://example.test/?token=very-secret", status=200),
        SimpleNamespace(url="https://example.test/admin", status=403),
        SimpleNamespace(url="https://example.test/error", status=0),
    ]
    report = build_coverage_report(
        page_results=pages,
        endpoint_inventory=[{"sources": ["html-link", "javascript-fetch"]}],
        parameter_inventory=[{"name": "id"}],
        network_observations=[{
            "url": "https://example.test/api/search", "method": "POST",
            "source": "manual-browser", "status": 200,
        }],
        asset_inventory=[{"sources": ["css-url", "html-attribute"]}],
        wordlist_hits=[{"url": "https://example.test/admin"}],
        wordlist_results=[{"url": "https://example.test/nope", "status": 404, "method": "GET"}],
        passive_sources=[{"name": "crt.sh", "status": "queried", "count": 4}],
        passive_errors=["Wayback timed out"],
        historical_urls=["https://example.test/old?apiKey=secret"],
        imported_seed_urls=["https://example.test/orphan?token=secret"],
        wordlist_stats={"enabled": True, "words_loaded": 900, "candidate_count": 2400,
                        "candidate_limit_reached": True},
        request_intelligence=[{"evidence": "observed"}, {"evidence": "inferred"}],
        max_pages=10, max_depth=3, target_url="https://example.test/?auth=secret",
        page_limit_reached=True, depth_limit_reached=True, transport_error_count=1,
        restricted_response_count=1,
    )
    assert report["assessment"] == "partial"
    assert report["pages"]["discovered_and_attempted"] == 3
    assert report["discovery"]["endpoints"] == 1
    assert report["discovery"]["observed_request_methods"] == 1
    assert report["discovery"]["inferred_request_methods"] == 1
    assert report["sources"]["endpoints"]["html-link"] == 1
    assert "The page limit was reached; remaining candidates may not have been crawled." in report["partial_reasons"]
    assert "very-secret" not in repr(report)
    assert "apiKey=secret" not in repr(report)
    assert "auth=secret" not in repr(report)
    assert "secret" not in repr(report["request_accounting"])


def test_normalize_request_strips_credentials_and_query_values_but_keeps_names():
    item = normalize_observation(
        url="https://alice:pass@example.test/api?id=123&token=secret",
        method="post", source="browser", observed=True,
    )
    assert item is not None
    assert item["url"] == "https://example.test/api"
    assert item["method"] == "POST"
    assert item["evidence"] == "observed"
    assert item["parameter_names"] == ["id", "token"]
    assert "alice" not in repr(item)
    assert "secret" not in repr(item)


def test_merge_observations_prefers_observed_evidence_and_merges_names_and_status():
    merged = merge_observations([
        {
            "endpoint": "https://example.test/api/users?id=1",
            "method": "GET", "source": "javascript-static", "evidence": "inferred",
        },
        {
            "url": "https://example.test/api/users", "method": "GET",
            "source": "manual-browser", "observed": True, "status": 200,
            "query_parameters": ["role"], "body_parameters": [],
            "page": "https://example.test/home",
        },
    ])
    assert len(merged) == 1
    assert merged[0]["evidence"] == "observed"
    assert merged[0]["parameter_names"] == ["id", "role"]
    assert merged[0]["status_codes"] == [200]
    assert set(merged[0]["sources"]) == {"javascript-static", "manual-browser"}
