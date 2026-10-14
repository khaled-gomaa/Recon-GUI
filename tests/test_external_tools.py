import pytest

from recon.external_tools import build_command


def test_historical_url_tool_uses_hostname_not_a_shell_string():
    assert build_command("gau", "https://sub.example.com") == [
        "gau", "--subs", "sub.example.com"
    ]


def test_active_commands_have_conservative_rate_limits():
    nuclei = build_command("nuclei", "https://example.com")
    assert "-rate-limit" in nuclei and nuclei[nuclei.index("-rate-limit") + 1] == "2"
    assert "-retries" in nuclei and nuclei[nuclei.index("-retries") + 1] == "0"


def test_ffuf_requires_a_local_wordlist_and_limits_request_rate(tmp_path):
    with pytest.raises(ValueError):
        build_command("ffuf", "https://example.com")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    command = build_command("ffuf", "https://example.com/app", str(wordlist))
    assert command[command.index("-u") + 1] == "https://example.com/app/FUZZ"
    assert command[command.index("-rate") + 1] == "2"


def test_target_validation_and_unknown_tools_are_rejected():
    with pytest.raises(ValueError):
        build_command("nuclei", "javascript:alert(1)")
    with pytest.raises(ValueError):
        build_command("unknown", "https://example.com")



def test_subfinder_is_available_as_passive_tool_but_nmap_is_rejected():
    assert build_command("subfinder", "https://example.com/app") == [
        "subfinder", "-silent", "-d", "example.com"
    ]
    with pytest.raises(ValueError):
        build_command("nmap", "https://example.com")
