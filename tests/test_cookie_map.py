from types import SimpleNamespace

from recon.cookie_map import build_cookie_map


def test_cookie_map_aggregates_repeated_observations_and_strips_query_values():
    pages = [
        SimpleNamespace(
            url="https://example.com/a?session=private-a",
            cookie_events=[{
                "name": "sessionid", "domain": "", "path": "/",
                "secure": True, "httponly": True, "samesite": "Lax",
            }],
        ),
        SimpleNamespace(
            url="https://example.com/b?token=private-b",
            cookie_events=[{
                "name": "sessionid", "domain": "example.com", "path": "/",
                "secure": True, "httponly": True, "samesite": "Lax",
            }],
        ),
    ]
    wordlist = [{
        "url": "https://example.com/admin?password=private-c",
        "set_cookie_names": [{
            "name": "sessionid", "domain": "example.com", "path": "/",
            "secure": True, "httponly": True, "samesite": "Lax",
        }],
    }]
    session_cookies = [{
        "url": "https://example.com/?auth=private-d",
        "name": "sessionid", "domain": ".example.com", "path": "/",
        "secure": True, "httponly": True, "samesite": "Lax",
        "source": "manual-browser",
    }]

    report = build_cookie_map(
        pages, wordlist, session_cookies, target_url="https://example.com/?secret=private-root"
    )

    assert report["cookie_identity_count"] == 1
    assert report["cookie_observation_count"] == 4
    assert report["cookie_url_count"] == 4
    cookie = report["cookie_map"][0]
    assert cookie["name"] == "sessionid"
    assert cookie["observation_count"] == 4
    assert cookie["url_count"] == 4
    assert set(cookie["sources"]) == {"http-response", "content-discovery", "manual-browser"}
    assert len(cookie["sample_urls"]) == 4
    serialized = repr(report)
    for secret in ("private-a", "private-b", "private-c", "private-d", "private-root"):
        assert secret not in serialized
    assert all("?" not in value for value in cookie["sample_urls"])


def test_cookie_map_keeps_different_cookie_attributes_as_distinct_identities():
    pages = [
        SimpleNamespace(
            url="https://example.com/",
            cookie_events=[
                {"name": "prefs", "domain": "example.com", "path": "/", "secure": True},
                {"name": "prefs", "domain": "example.com", "path": "/", "secure": False},
            ],
        )
    ]
    report = build_cookie_map(pages, [], [], target_url="https://example.com/")
    assert report["cookie_identity_count"] == 2
    assert {item["secure"] for item in report["cookie_map"]} == {True, False}
