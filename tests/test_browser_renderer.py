import asyncio

from recon.browser_renderer import render_pages


def test_empty_batch_does_not_require_playwright():
    assert asyncio.run(render_pages([])) == {}
