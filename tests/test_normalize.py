from neesha.resolve.normalize import (
    canonicalize_domain,
    extract_domains,
    extract_emails,
    extract_ips,
    is_subdomain,
)


def test_canonicalize_domain():
    assert canonicalize_domain("WWW.Example.COM.") == "www.example.com"
    assert canonicalize_domain("*.example.com") == "example.com"


def test_extract_domains():
    text = "subdomains: a.example.com, b.example.com and example.com"
    domains = extract_domains(text)
    assert "a.example.com" in domains
    assert "example.com" in domains


def test_extract_ips():
    assert "1.2.3.4" in extract_ips("hosts 1.2.3.4 and 5.6.7.8")
    assert "2606:4700:10::6814:179a" in extract_ips("AAAA: 2606:4700:10::6814:179a")


def test_extract_emails():
    assert extract_emails("contact Jane@Example.COM now") == ["jane@example.com"]


def test_is_subdomain():
    assert is_subdomain("www.example.com", "example.com")
    assert not is_subdomain("example.com", "example.com")
    assert not is_subdomain("other.org", "example.com")
