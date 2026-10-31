"""Minimal network helpers for TLS and HTTP posture collection.

Passive by nature: a TLS handshake to a public host and a plain GET of its
homepage are what any browser does; no credentials, no login, no probing
beyond standard endpoints.
"""
from __future__ import annotations

import json
import ssl
import urllib.request
from typing import Any, Optional

import certifi
from cryptography import x509
from cryptography.x509 import DNSName
from cryptography.x509.oid import ExtensionOID, NameOID

_UA = "Mozilla/5.0 (compatible; neesha/0.1)"


def _default_context() -> ssl.SSLContext:
    # Use the certifi CA bundle: macOS system Python's default bundle is
    # missing CAs that some OSINT hosts (e.g. OTX, HackerTarget) chain to.
    return ssl.create_default_context(cafile=certifi.where())


def get_tls_cert(host: str, port: int = 443, timeout: int = 8) -> dict[str, Any]:
    """Return {issuer, not_after, san} for the server certificate.

    Uses an unverified handshake (collecting facts, not validating trust) and
    parses the DER certificate via cryptography, which works reliably where
    ``SSLSocket.getpeercert()`` returns an empty dict.
    """
    pem = ssl.get_server_certificate((host, port), timeout=timeout)
    cert = x509.load_pem_x509_certificate(pem.encode())

    issuer = None
    cn_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        issuer = cn_attrs[0].value

    not_after = cert.not_valid_after_utc  # aware datetime (cryptography >= 42)

    san: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = list(ext.value.get_values_for_type(DNSName))
    except x509.ExtensionNotFound:
        pass

    return {"issuer": issuer, "not_after": not_after, "san": san}


def fetch_http(url: str, timeout: int = 8) -> dict[str, Any]:
    """GET a URL and return status, final URL, and lower-cased headers."""
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout, context=_default_context()) as resp:
        return {
            "status": resp.status,
            "final_url": resp.geturl(),
            "headers": {k.lower(): v for k, v in resp.headers.items()},
        }


def http_get(url: str, headers: Optional[dict[str, str]] = None, timeout: int = 20) -> str:
    """GET a URL and return the decoded body text."""
    merged = {"User-Agent": _UA, **(headers or {})}
    req = urllib.request.Request(url, method="GET", headers=merged)
    with urllib.request.urlopen(req, timeout=timeout, context=_default_context()) as resp:
        return resp.read().decode("utf-8", errors="replace")


def http_get_json(url: str, headers: Optional[dict[str, str]] = None, timeout: int = 20) -> Any:
    """GET a URL and parse the body as JSON."""
    return json.loads(http_get(url, headers=headers, timeout=timeout))


def http_post_json(
    url: str,
    payload: dict,
    headers: Optional[dict[str, str]] = None,
    timeout: int = 20,
) -> Any:
    """POST a JSON body and parse the response as JSON."""
    merged = {"User-Agent": _UA, "Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST", headers=merged)
    with urllib.request.urlopen(req, timeout=timeout, context=_default_context()) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))
