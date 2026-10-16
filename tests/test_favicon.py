import asyncio

from aiohttp import web

from recon.rate_limit import RateLimitManager
from recon.favicon_hasher import _favicon_hash, HAS_MMH3, get_favicon_hash


def test_favicon_hash_returns_string():
    data = b"\x00\x01\x02\x03fake-favicon-bytes"
    h = _favicon_hash(data)
    assert isinstance(h, str)
    assert len(h) > 0


def test_favicon_hash_deterministic():
    data = b"consistent-bytes"
    assert _favicon_hash(data) == _favicon_hash(data)


def test_mmh3_available():
    assert isinstance(HAS_MMH3, bool)


def test_favicon_request_retries_after_429_and_uses_shared_cooldown():
    async def scenario():
        counter = {"value": 0}
        icon = b"minimal favicon content"

        async def handler(_request):
            counter["value"] += 1
            if counter["value"] == 1:
                return web.Response(status=429, headers={"Retry-After": "0"})
            return web.Response(status=200, body=icon, content_type="image/x-icon")

        app = web.Application()
        app.router.add_get("/favicon.ico", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            manager = RateLimitManager(fallback_initial_seconds=0)
            async with __import__("aiohttp").ClientSession() as session:
                result = await get_favicon_hash(
                    session, f"http://127.0.0.1:{port}/",
                    rate_limit_manager=manager,
                    on_log=lambda _message: None,
                )
            assert counter["value"] == 2
            assert result == _favicon_hash(icon)
            assert manager.pause_count == 1
            assert manager.stopped is False
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))
