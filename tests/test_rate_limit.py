import asyncio

from recon.rate_limit import RateLimitManager, parse_retry_after


def test_retry_after_parser_supports_seconds_http_date_and_invalid_values():
    assert parse_retry_after("12") == 12
    assert parse_retry_after("bad-value") is None
    assert parse_retry_after(None) is None
    assert parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0


def test_missing_retry_after_uses_bounded_exponential_backoff_and_stops(tmp_path):
    async def scenario():
        manager = RateLimitManager(
            fallback_initial_seconds=0.001,
            fallback_max_seconds=0.004,
            max_pauses=3,
        )
        delays = []
        for expected in (0.001, 0.002, 0.004):
            assert await manager.handle_429(
                {}, "https://example.com/private?token=do-not-log",
                on_log=lambda _message: None,
            )
            delays.append(manager.last_delay_seconds)
            assert manager.last_reason == "fallback backoff (no valid Retry-After)"
        assert delays == [0.001, 0.002, 0.004]
        assert await manager.handle_429(
            {}, "https://example.com/private?token=do-not-log",
            on_log=lambda _message: None,
        ) is False
        assert manager.stopped is True
        assert manager.pause_count == 3
        assert "do-not-log" not in repr(manager.to_dict())
        assert all("?" not in item["url"] for item in manager.events)

    asyncio.run(asyncio.wait_for(scenario(), timeout=3))


def test_retry_after_is_honored_and_long_waits_stop_without_early_retry():
    async def scenario():
        manager = RateLimitManager(fallback_initial_seconds=0)
        assert await manager.handle_429(
            {"Retry-After": "0"}, "https://example.com/page",
            on_log=lambda _message: None,
        )
        assert manager.events[0]["reason"] == "Retry-After"
        assert manager.events[0]["delay_seconds"] == 0.0

        strict = RateLimitManager(fallback_initial_seconds=0)
        assert await strict.handle_429(
            {"Retry-After": "121"}, "https://example.com/page",
            on_log=lambda _message: None,
        ) is False
        assert strict.stopped is True
        assert strict.pause_count == 0

    asyncio.run(asyncio.wait_for(scenario(), timeout=3))


def test_concurrent_429_responses_share_one_cooldown():
    async def scenario():
        manager = RateLimitManager(fallback_initial_seconds=0.03)
        results = await asyncio.gather(*[
            manager.handle_429(
                {}, f"https://example.com/page-{index}",
                on_log=lambda _message: None,
            )
            for index in range(4)
        ])
        assert all(results)
        assert manager.pause_count == 1
        assert manager.stopped is False

    asyncio.run(asyncio.wait_for(scenario(), timeout=3))


def test_successful_response_resets_the_consecutive_429_streak():
    async def scenario():
        manager = RateLimitManager(fallback_initial_seconds=0)
        assert await manager.handle_429(
            {}, "https://example.com/first",
            on_log=lambda _message: None,
        )
        assert manager.consecutive_pauses == 1
        manager.note_success()
        assert manager.consecutive_pauses == 0
        assert manager.pause_count == 1
        # A recovered endpoint doesn't consume the remaining scan-wide burst budget.
        assert await manager.handle_429(
            {}, "https://example.com/second",
            on_log=lambda _message: None,
        )
        manager.note_success()
        assert await manager.handle_429(
            {}, "https://example.com/third",
            on_log=lambda _message: None,
        )
        assert manager.stopped is False
        assert manager.pause_count == 3

    asyncio.run(asyncio.wait_for(scenario(), timeout=3))
