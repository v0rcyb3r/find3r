"""Canonicalization and indicator extraction.

Extractors pull domains, IPs, and emails out of arbitrary text (evidence
claims); canonicalizers produce a single stable form per entity so exact
matches group together.
"""
from __future__ import annotations

import ipaddress
import re

_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_CANDIDATE_RE = re.compile(r"[0-9a-fA-F:]{3,}")
_EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE)


def extract_domains(text: str) -> list[str]:
    return [m.group(0).lower().rstrip(".") for m in _DOMAIN_RE.finditer(text)]


def extract_ips(text: str) -> list[str]:
    """Extract valid IPv4 and IPv6 addresses, validating via ipaddress."""
    results: list[str] = []
    seen: set[str] = set()
    for match in _IPV4_RE.finditer(text):
        token = match.group(0)
        try:
            addr = str(ipaddress.IPv4Address(token))
        except ValueError:
            continue
        if addr not in seen:
            seen.add(addr)
            results.append(addr)
    for match in _IPV6_CANDIDATE_RE.finditer(text):
        token = match.group(0)
        if ":" not in token:
            continue
        try:
            addr = str(ipaddress.IPv6Address(token))
        except ValueError:
            continue
        if addr not in seen:
            seen.add(addr)
            results.append(addr)
    return results


def extract_emails(text: str) -> list[str]:
    return [m.group(0).lower() for m in _EMAIL_RE.finditer(text)]


def canonicalize_domain(value: str) -> str:
    return value.strip().lower().rstrip(".").lstrip("*.")


def canonicalize_ip(value: str) -> str:
    return value.strip()


def canonicalize_email(value: str) -> str:
    return value.strip().lower()


def is_subdomain(hostname: str, domain: str) -> bool:
    return hostname != domain and hostname.endswith("." + domain)
