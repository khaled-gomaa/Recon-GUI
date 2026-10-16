"""Favicon hashing (mmh3) to fingerprint technology / shared infra."""
import asyncio
import base64
import zlib
import aiohttp
from urllib.parse import urljoin
from crawler.fetcher import build_headers

try:
    import mmh3
    HAS_MMH3 = True
except ImportError:
    HAS_MMH3 = False


def _favicon_hash(data: bytes) -> str:
    b64 = base64.encodebytes(data)
    if HAS_MMH3:
        return str(mmh3.hash(b64))
    crc = zlib.crc32(b64) & 0xFFFFFFFF
    if crc >= 0x80000000:
        crc -= 0x100000000
    return f"crc32:{crc}"


async def get_favicon_hash(
    session, base_url: str, timeout: int = 8,
    rate_limit_manager=None, should_stop=None, on_log=None,
) -> str:
    """Hash the favicon while honoring the scan-wide 429 policy when provided."""
    favicon_url = urljoin(base_url, "/favicon.ico")
    stop = should_stop or (lambda: False)
    log = on_log or (lambda _message: None)
    max_attempts = (rate_limit_manager.max_pauses + 1) if rate_limit_manager else 1
    for _attempt in range(max_attempts):
        if stop():
            return ""
        if rate_limit_manager is not None:
            if not await rate_limit_manager.wait_until_ready(stop):
                return ""
        try:
            async with session.get(
                favicon_url,
                headers=build_headers(),
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=False,
            ) as resp:
                if resp.status == 429:
                    if rate_limit_manager is None:
                        return ""
                    resumed = await rate_limit_manager.handle_429(
                        dict(resp.headers), favicon_url, on_log=log,
                        should_stop=stop, phase="Favicon hashing",
                    )
                    if resumed:
                        continue
                    return ""
                if rate_limit_manager is not None:
                    rate_limit_manager.note_success()
                if resp.status != 200:
                    return ""
                data = await resp.content.read(1024 * 1024 + 1)
                if len(data) > 1024 * 1024:
                    log("[Favicon] Response exceeded 1 MiB; skipping hash.")
                    return ""
                if not data:
                    return ""
                return _favicon_hash(data)
        except Exception as exc:
            log(f"[Favicon] Fetch failed: {type(exc).__name__}")
            return ""
    return ""


async def hash_favicon_simple(base_url: str) -> str:
    connector = aiohttp.TCPConnector(ssl=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        return await get_favicon_hash(session, base_url)
