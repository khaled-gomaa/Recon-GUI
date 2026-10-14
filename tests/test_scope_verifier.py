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
