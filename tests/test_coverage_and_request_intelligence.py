from recon.coverage import CoverageTracker
from recon.request_intelligence import merge_observations, normalize_observation


def test_coverage_deduplicates_candidates_and_tracks_sources():
    tracker = CoverageTracker()
    assert tracker.add_candidate("https://example.com/a", "html")
    assert not tracker.add_candidate("https://example.com/a", "js")
    tracker.add_result(url="https://example.com/a", status=200, method="GET", source="html")
    tracker.mark_pending(2)
    assert tracker.discovered == 1
    assert tracker.crawled == 1
    assert tracker.pending == 2
    assert tracker.partial
    assert tracker.source_counts["html"] == 1


def test_coverage_marks_rate_limit_and_truncation_as_partial():
    tracker = CoverageTracker()
    tracker.add_result(
        url="https://example.com/api",
        status=429,
        method="GET",
        source="browser",
        rate_limited=True,
        truncated=True,
    )
    snapshot = tracker.snapshot()
    assert snapshot["rate_limited"] == 1
    assert snapshot["truncated"] == 1
    assert snapshot["status_counts"]["429"] == 1
    assert snapshot["method_counts"]["GET"] == 1
    assert snapshot["partial"] is True


def test_coverage_limit_is_explicit():
    tracker = CoverageTracker()
    tracker.mark_limit("wordlist", 1000)
    assert tracker.partial
    assert "limit:wordlist=1000" in tracker.notes


def test_normalize_request_strips_query_values_but_keeps_names():
    item = normalize_observation(
        url="https://example.com/api?id=123&token=secret",
        method="post",
        source="browser",
        observed=True,
    )
    assert item["url"] == "https://example.com/api"
    assert item["method"] == "POST"
    assert item["evidence"] == "observed"
    assert item["parameter_names"] == ["id", "token"]
    assert "secret" not in str(item)


def test_merge_observations_prefers_observed_evidence_and_merges_parameters():
    merged = merge_observations([
        {
            "endpoint": "https://example.com/api/users?id=1",
            "method": "GET",
            "source": "javascript-static",
            "evidence": "inferred",
        },
        {
            "url": "https://example.com/api/users?role=admin",
            "method": "GET",
            "source": "browser",
            "observed": True,
        },
    ])
    assert len(merged) == 1
    assert merged[0]["evidence"] == "observed"
    assert merged[0]["parameter_names"] == ["id", "role"]
    assert set(merged[0]["sources"]) == {"javascript-static", "browser"}
