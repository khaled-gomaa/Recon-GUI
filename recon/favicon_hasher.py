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


async def get_favicon_hash(session, base_url: str, timeout: int = 8) -> str:
    favicon_url = urljoin(base_url, "/favicon.ico")
    try:
        async with session.get(
            favicon_url,
            headers=build_headers(),
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True,
        ) as resp:
            if resp.status != 200:
                return ""
            data = await resp.read()
            if not data:
                return ""
            return _favicon_hash(data)
    except Exception:
        return ""


async def hash_favicon_simple(base_url: str) -> str:
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        return await get_favicon_hash(session, base_url)
