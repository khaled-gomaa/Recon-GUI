import asyncio

from aiohttp import web

from recon.asset_probe import probe_asset_references
from recon.rate_limit import RateLimitManager


def test_asset_probe_uses_head_records_metadata_and_redacts_query_values():
    async def scenario():
        requests = []

        async def handler(request):
            requests.append((request.method, request.path))
            return web.Response(
                status=200,
                headers={
                    "Content-Type": "application/javascript",
                    "Content-Length": "123",
                    "Set-Cookie": "sessionid=secret-cookie-value; HttpOnly; Secure; Path=/",
                },
            )

        app = web.Application()
        app.router.add_route("*", "/{name:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            target = f"http://127.0.0.1:{port}/"
            result = await probe_asset_references(
                target,
                [
                    {
                        "url": target + "app.js",
                        "request_url": target + "app.js?signature=secret-query-value",
                        "kind": "javascript",
                        "extension": ".js",
                    },
                    {
                        "url": target + "app.js",
                        "request_url": target + "app.js?signature=another-secret",
                        "kind": "javascript",
                        "extension": ".js",
                    },
                    {
                        "url": "http://example.invalid/picture.png",
                        "request_url": "http://example.invalid/picture.png",
                        "kind": "image",
                        "extension": ".png",
                    },
                ],
                delay_ms=0,
            )
            assert requests == [("HEAD", "/app.js")]
            assert len(result["results"]) == 1
            record = result["results"][0]
            assert record["method"] == "HEAD"
            assert record["status"] == 200
            assert record["content_type"] == "application/javascript"
            assert record["content_length"] == "123"
            assert record["set_cookie_names"] == ["sessionid"]
            assert record["query_parameter_names"] == ["signature"]
            assert result["summary"]["skipped_out_of_origin"] == 1
            serialized = repr(result)
            assert "secret-cookie-value" not in serialized
            assert "secret-query-value" not in serialized
            assert "another-secret" not in serialized
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))


def test_asset_probe_backoffs_and_stops_after_repeated_429_without_retry_after():
    async def scenario():
        requests = []

        async def handler(request):
            requests.append(request.path)
            return web.Response(status=429, text="rate limited")

        app = web.Application()
        app.router.add_route("*", "/{name:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            target = f"http://127.0.0.1:{port}/"
            manager = RateLimitManager(fallback_initial_seconds=0)
            result = await probe_asset_references(
                target,
                [
                    {"url": target + f"asset-{index}.js", "kind": "javascript"}
                    for index in range(4)
                ],
                delay_ms=0, rate_limit_manager=manager,
            )
            assert requests == ["/asset-0.js", "/asset-1.js", "/asset-2.js", "/asset-3.js"]
            assert result["summary"]["rate_limited_stop"] is True
            assert result["summary"]["partial"] is True
            assert len(result["results"]) == 4
            assert all(item["status"] == 429 for item in result["results"])
            assert manager.stopped is True
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))


def test_asset_probe_cap_marks_coverage_partial():
    async def scenario():
        async def handler(request):
            return web.Response(status=204)

        app = web.Application()
        app.router.add_route("*", "/{name:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            target = f"http://127.0.0.1:{port}/"
            assets = [
                {"url": target + f"asset{i}.js", "kind": "javascript"}
                for i in range(4)
            ]
            result = await probe_asset_references(
                target, assets, max_assets=2, delay_ms=0,
            )
            assert len(result["results"]) == 2
            assert result["summary"]["limit_reached"] is True
            assert result["summary"]["partial"] is True
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))
