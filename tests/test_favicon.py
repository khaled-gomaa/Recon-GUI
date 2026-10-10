from recon.favicon_hasher import _favicon_hash, HAS_MMH3


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
