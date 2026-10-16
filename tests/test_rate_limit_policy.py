from datetime import datetime, timedelta, timezone

from recon.rate_limit_policy import AdaptiveRateController, CrawlLimits


def test_retry_after_seconds_is_honored():
    controller = AdaptiveRateController(max_delay=60, jitter=0)
    decision = controller.on_rate_limit("7")
    assert decision.should_stop is False
    assert decision.wait_seconds == 7


def test_long_retry_after_is_not_capped_by_internal_backoff_ceiling():
    controller = AdaptiveRateController(max_delay=60, jitter=0)
    decision = controller.on_rate_limit("3600")
    assert decision.should_stop is False
    assert decision.wait_seconds == 3600


def test_retry_after_http_date_is_parsed():
    future = datetime.now(timezone.utc) + timedelta(seconds=4)
    value = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
    parsed = AdaptiveRateController.parse_retry_after(value)
    assert parsed is not None
    assert 0 <= parsed <= 5


def test_missing_retry_after_uses_backoff_and_repeated_limits_stop():
    controller = AdaptiveRateController(max_delay=10, max_consecutive_limits=2, jitter=0)
    first = controller.on_rate_limit(None)
    second = controller.on_rate_limit(None)
    third = controller.on_rate_limit(None)
    assert first.wait_seconds >= 1
    assert second.wait_seconds > first.wait_seconds
    assert third.should_stop is True


def test_unlimited_pages_and_depth_are_explicit():
    limits = CrawlLimits(max_pages=0, max_depth=0)
    assert limits.unlimited_pages
    assert limits.unlimited_depth
    assert limits.allows_page(0)
    assert limits.allows_page(1_000_000)
    assert limits.allows_depth(0)
    assert limits.allows_depth(1_000_000)


def test_finite_page_and_depth_limits_still_work():
    limits = CrawlLimits(max_pages=10, max_depth=3)
    assert limits.allows_page(9)
    assert not limits.allows_page(10)
    assert limits.allows_depth(3)
    assert not limits.allows_depth(4)
