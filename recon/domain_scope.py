"""Public-suffix-aware domain scope helpers.

The bundled Public Suffix List snapshot is used offline; the application does not
contact a suffix-list service at runtime. Private suffixes (for example, blogspot.com)
are included so separate hosted tenants are not treated as one authorized domain.
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache


@lru_cache(maxsize=1)
def _extractor():
    try:
        import tldextract
    except ImportError as exc:  # fail closed rather than broaden active scope
        raise RuntimeError(
            "Public-suffix scope support is unavailable. Install the required "
            "'tldextract' dependency before verifying subdomains."
        ) from exc
    return tldextract.TLDExtract(
        suffix_list_urls=(),
        include_psl_private_domains=True,
        fallback_to_snapshot=True,
    )


def registrable_domain(hostname: str) -> str:
    """Return the registrable root domain, or an empty string for IPs/public suffixes.

    Private PSL rules are applied to prevent different tenants on shared hosting
    platforms from being grouped under the provider's domain.
    """
    host = str(hostname or "").strip().rstrip(".").lower()
    if not host:
        return ""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return ""
    except ValueError:
        pass

    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    extractor = _extractor()
    try:
        extracted = extractor(host)
    except OSError as exc:
        # Frozen Windows builds must carry tldextract's data snapshot. If an older or
        # damaged portable build is missing it, disable optional text-subdomain
        # extraction gracefully instead of terminating the entire crawl. Callers
        # that actively validate a registrable root receive this explicit error and
        # must fail closed rather than guessing a broader domain scope.
        raise RuntimeError(
            "The bundled Public Suffix List snapshot is missing or unreadable. "
            "Download the latest Windows build; subdomain scope verification was not run."
        ) from exc
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()

    # Some private/internal test zones (for example, example.test) are deliberately
    # absent from the public PSL snapshot. Allow a conservative last-two-label fallback
    # only when the full hostname is not itself a known public/private suffix.
    labels = host.split(".")
    try:
        known_suffixes = set(extractor.tlds)
    except Exception:
        known_suffixes = set()
    if len(labels) >= 2 and host not in known_suffixes:
        suffix = ".".join(labels[-2:])
        if suffix not in known_suffixes:
            return suffix
    # A known public suffix itself (e.g. co.uk or blogspot.com) has no registrable root.
    return ""
