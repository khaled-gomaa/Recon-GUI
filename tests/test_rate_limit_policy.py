from datetime import datetime, timedelta, timezone

from recon.rate_limit_policy import AdaptiveRateController, CrawlLimits


def test_retry_after_seconds_is_honored():
    controller = AdaptiveRateController(max_delay=60, jitter=0, rng=None)
    decision = controller.on_rate_limit("7")
    assert decision.should_stop is False
    assert decision.wait_seconds == 7


def test_retry_after_http_date_is_parsed():
    future = datetime.now(timezone.utc) + timedelta(seconds=4)
    value = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
    parsed = AdaptiveRateController.parse_retry_after(value)
    assert parsed is not None
    assert 0 <= parsed <= 5


def test_repeated_rate_limits_eventually_stop():
    controller = AdaptiveRateController(max_delay=10, max_consecutive_limits=2, jitter=0)
    assert controller.on_rate_limit("1").should_stop is False
    assert controller.on_rate_limit("1").should_stop is False
    assert controller.on_rate_limit("1").should_stop is True


def test_unlimited_pages_is_explicit():
    limits = CrawlLimits(max_pages=0, max_depth=0)
    assert limits.unlimited_pages
    assert limits.allows_page(0)
    assert limits.allows_page(1_000_000)
    assert limits.allows_depth(0)


def test_finite_page_limit_still_works():
    limits = CrawlLimits(max_pages=10, max_depth=3)
    assert limits.allows_page(9)
    assert not limits.allows_page(10)
    assert limits.allows_depth(3)
    assert not limits.allows_depth(4)
