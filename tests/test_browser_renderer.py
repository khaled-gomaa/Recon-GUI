import asyncio

from recon.browser_renderer import render_pages


def test_empty_batch_does_not_require_playwright():
    assert asyncio.run(render_pages([])) == {}


def test_browser_storage_handoff_keeps_only_target_domain_cookies_and_origin_state():
    from recon.browser_renderer import _filter_storage_state_for_target

    state = {
        "cookies": [
            {"name": "session", "domain": ".example.test", "value": "target-session"},
            {"name": "subsession", "domain": "app.example.test", "value": "target-sub"},
            {"name": "idp-session", "domain": ".identity.test", "value": "do-not-transfer"},
        ],
        "origins": [
            {
                "origin": "https://app.example.test",
                "localStorage": [{"name": "auth-token", "value": "private"}],
            },
            {
                "origin": "https://identity.test",
                "localStorage": [{"name": "sso-token", "value": "do-not-transfer"}],
            },
            {
                "origin": "http://app.example.test",
                "localStorage": [{"name": "other-scheme", "value": "do-not-transfer"}],
            },
        ],
    }
    filtered = _filter_storage_state_for_target(state, "https://app.example.test/")
    assert [cookie["name"] for cookie in filtered["cookies"]] == ["session", "subsession"]
    assert [entry["origin"] for entry in filtered["origins"]] == ["https://app.example.test"]
    assert "do-not-transfer" not in repr(filtered)


def test_bounded_scroll_stops_after_lazy_content_stops_growing():
    from recon.browser_renderer import _bounded_scroll_page

    class FakePage:
        def __init__(self):
            self.height = 100
            self.scrolls = 0
            self.top_reset = False

        async def evaluate(self, script):
            if "scrollTo" in script:
                self.scrolls += 1
                if self.scrolls <= 2:
                    self.height += 100
                if "0, 0" in script:
                    self.top_reset = True
                return None
            return self.height

        async def wait_for_timeout(self, _milliseconds):
            return None

    async def scenario():
        page = FakePage()
        steps = await _bounded_scroll_page(page, max_steps=5, settle_ms=0, idle_limit=2)
        assert steps == 4
        assert page.top_reset is True
        assert page.scrolls == 5  # four scroll attempts, plus one reset to the top

    asyncio.run(scenario())


def test_bounded_scroll_honors_stop_callback():
    from recon.browser_renderer import _bounded_scroll_page

    class FakePage:
        async def evaluate(self, script):
            return 100

        async def wait_for_timeout(self, _milliseconds):
            return None

    async def scenario():
        calls = {"count": 0}

        def stop():
            calls["count"] += 1
            return calls["count"] >= 2

        steps = await _bounded_scroll_page(FakePage(), should_stop=stop, max_steps=5, settle_ms=0)
        assert steps <= 1

    asyncio.run(scenario())


def test_async_browser_handler_uses_captured_loop_from_another_thread():
    import threading
    from recon.browser_renderer import _schedule_async_handler

    loop = asyncio.new_event_loop()
    seen = []
    errors = []

    async def handler(value):
        seen.append(value)

    async def scenario():
        thread = threading.Thread(
            target=lambda: _schedule_async_handler(
                loop, handler, "response", errors.append, "Test Browser"
            )
        )
        thread.start()
        thread.join(timeout=2)
        assert not thread.is_alive()
        await asyncio.sleep(0.02)

    try:
        loop.run_until_complete(scenario())
    finally:
        loop.close()

    assert seen == ["response"]
    assert errors == []
