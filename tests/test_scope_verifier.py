import asyncio

from recon.scope_verifier import normalize_in_scope_hosts, verify_subdomains


def test_scope_normalizer_keeps_only_valid_subdomains_of_the_inferred_root():
    hosts = normalize_in_scope_hosts(
        "https://www.example.test/",
        [
            "api.example.test",
            "API.EXAMPLE.TEST.",
            "example.test",
            "evil-example.test",
            "outside.invalid",
            "https://api.example.test/path",
            "-bad.example.test",
            "bad..example.test",
            "dev.api.example.test",
        ],
    )
    assert hosts == ["api.example.test", "dev.api.example.test"]


def test_verification_respects_explicit_host_cap_and_reports_unverified_remainder():
    async def scenario():
        selected = [f"node{i}.example.test" for i in range(5)]
        logs = []
        result = await verify_subdomains(
            "https://example.test/",
            selected,
            max_hosts=2,
            timeout=1,
            should_stop=lambda: True,
            on_log=logs.append,
        )
        assert result["candidate_count"] == 5
        assert result["verified_count"] == 0
        assert result["skipped_count"] == 5
        assert result["truncated"] is True
        assert all(item["http_result"] == "stopped" for item in result["results"])
        assert any("first 2" in message for message in logs)

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))


def test_verification_rejects_non_http_target_before_any_network_request():
    async def scenario():
        try:
            await verify_subdomains("javascript:alert(1)", ["api.example.test"])
        except ValueError as exc:
            assert "HTTP(S)" in str(exc)
        else:
            raise AssertionError("non-HTTP targets must be rejected")

    asyncio.run(asyncio.wait_for(scenario(), timeout=3))


def test_verification_blocks_nonpublic_dns_answers_without_http_probe(monkeypatch):
    import socket

    async def scenario():
        async def fake_getaddrinfo(self, host, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 0))
            ]

        monkeypatch.setattr("asyncio.BaseEventLoop.getaddrinfo", fake_getaddrinfo)
        result = await verify_subdomains(
            "https://example.test/",
            ["api.example.test"],
            timeout=1,
        )
        record = result["results"][0]
        assert record["dns_status"] == "resolved"
        assert record["ip_addresses"] == ["127.0.0.1"]
        assert record["http_status"] is None
        assert record["http_result"] == "blocked-nonpublic-address"
        assert "non-public" in record["error"]

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))


def test_pinned_scope_resolver_returns_only_validated_addresses():
    import asyncio
    import socket
    from recon.scope_verifier import _PinnedDNSResolver

    async def scenario():
        resolver = _PinnedDNSResolver()
        resolver.pin("api.example.test", ["192.0.2.1", "2001:db8::1"])
        # Resolver pinning is a separate deterministic helper; verification blocks reserved IPs,
        # but this verifies it does not look up the hostname again.
        result = await resolver.resolve("api.example.test", port=443, family=socket.AF_UNSPEC)
        assert {item["host"] for item in result} == {"192.0.2.1", "2001:db8::1"}
        assert {item["port"] for item in result} == {443}
        await resolver.close()

    asyncio.run(asyncio.wait_for(scenario(), timeout=3))
