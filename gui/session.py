"""Shared in-memory HTTP session helpers."""
from __future__ import annotations

from http.cookies import SimpleCookie

import aiohttp
from yarl import URL


async def create_session_cookie_jar(target_url: str, raw_cookie_header: str = "", on_log=None):
    """Create an aiohttp CookieJar from inside the active event loop.

    Recent aiohttp versions may require a running loop while initializing its
    session state. Call this coroutine via await or loop.run_until_complete().
    Cookie values stay in memory and are never included in log messages.
    """
    log = on_log or (lambda _message: None)
    jar = aiohttp.CookieJar(unsafe=True)
    if raw_cookie_header:
        parsed_cookies = SimpleCookie()
        try:
            parsed_cookies.load(raw_cookie_header)
            if parsed_cookies:
                jar.update_cookies(parsed_cookies, response_url=URL(target_url))
                log("[Session] Imported supplied cookie names into the in-memory session jar.")
        except Exception as exc:
            log(f"[Session] Supplied Cookie header could not be parsed: {type(exc).__name__}.")
    return jar
