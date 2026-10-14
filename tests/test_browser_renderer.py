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
