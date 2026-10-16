import asyncio

from aiohttp import web

from recon.css_collector import CSSCollector, MAX_CSS_BYTES


def test_css_collector_follows_same_origin_imports_and_redacts_query_values():
    async def scenario():
        requested = []

        async def handler(request):
            requested.append((request.method, request.path))
            if request.path == "/styles/site.css":
                return web.Response(
                    text='''@import url("/styles/base.css");
.logo { background-image: url("/images/logo.svg?signature=private-value"); }
@font-face { src: url("../fonts/site.woff2"); }
/* background: url("/commented-out.png"); */
/*# sourceMappingURL=site.css.map */
@import url("https://cdn.example.invalid/external.css");
''',
                    content_type="text/css",
                )
            if request.path == "/styles/base.css":
                return web.Response(
                    text="body { background: url('/images/pattern.png'); }",
                    content_type="text/css",
                )
            return web.Response(status=404, text="not found")

        app = web.Application()
        app.router.add_route("*", "/{name:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            target = f"http://127.0.0.1:{port}/"
            collector = CSSCollector(target, on_log=lambda _message: None)
            report = await collector.collect(
                [{"url": target + "styles/site.css", "request_url": target + "styles/site.css", "kind": "stylesheet"}],
                delay_ms=0,
            )
            assert requested == [
                ("GET", "/styles/site.css"),
                ("GET", "/styles/base.css"),
            ]
            assert report["css_files_fetched"] == 2
            assets = report["css_assets"]
            by_url = {item["url"].split(target, 1)[-1]: item for item in assets}
            assert "images/logo.svg" in by_url
            assert by_url["images/logo.svg"]["query_parameter_names"] == ["signature"]
            assert "fonts/site.woff2" in by_url
            assert "images/pattern.png" in by_url
            assert "styles/site.css.map" in by_url
            assert "commented-out.png" not in repr(report)
            assert "external.css" in repr(report)  # reported, not fetched
            assert "private-value" not in repr(report)
            assert "private-value" not in repr(collector.to_dict())
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=8))


def test_css_collector_retries_after_429_cooldown():
    async def scenario():
        requested = []

        async def handler(request):
            requested.append(request.path)
            if len(requested) == 1:
                return web.Response(status=429, headers={"Retry-After": "0"}, text="rate limited")
            return web.Response(text="body{color:black}", content_type="text/css")

        app = web.Application()
        app.router.add_route("*", "/{name:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            target = f"http://127.0.0.1:{port}/"
            collector = CSSCollector(target, on_log=lambda _message: None)
            report = await collector.collect(
                [{"url": target + "site.css", "kind": "stylesheet"}],
                delay_ms=0,
            )
            assert requested == ["/site.css", "/site.css"]
            assert report["css_rate_limited_stop"] is False
            assert report["css_files_fetched"] == 1
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))


def test_css_collector_marks_oversized_stylesheets_as_truncated():
    async def scenario():
        async def handler(request):
            return web.Response(text="x" * (MAX_CSS_BYTES + 1), content_type="text/css")

        app = web.Application()
        app.router.add_route("*", "/{name:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            target = f"http://127.0.0.1:{port}/"
            collector = CSSCollector(target, on_log=lambda _message: None)
            report = await collector.collect(
                [{"url": target + "site.css", "kind": "stylesheet"}],
                delay_ms=0,
            )
            assert report["css_files_truncated"] == [target + "site.css"]
            assert report["css_files_fetched"] == 1
        finally:
            await runner.cleanup()

    asyncio.run(asyncio.wait_for(scenario(), timeout=8))


def test_css_collector_rejects_css_urls_with_credentials_and_non_http_schemes():
    collector = CSSCollector("https://example.test/")
    assets = collector._parse_css(
        'a{background:url("javascript:alert(1)")} b{background:url("https://user:secret@example.test/a.png")}',
        "https://example.test/site.css",
    )
    assert assets == []
