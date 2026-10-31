"""DNS resolution with two backends: the system resolver and DoH.

Cross-resolver validation is a posture requirement: SPF/DMARC TXT that differ
between the system resolver and a DoH resolver means "unstable DNS", which we
flag instead of asserting a single posture.
"""
from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

import dns.exception
import dns.resolver

_RTYPE_NUM = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "DNSKEY": 48,
    "CAA": 257,
}


@dataclass
class Record:
    rtype: str
    value: str


@dataclass
class QueryResult:
    domain: str
    rtype: str
    resolver: str
    status: str = "error"  # ok | nxdomain | noerror-nodata | error
    records: list[Record] = field(default_factory=list)
    ad: Optional[bool] = None  # DNSSEC authenticated-data bit
    error: Optional[str] = None


def parse_txt_data(data: str) -> str:
    """Join the character-strings of a TXT rdata (DoH JSON form).

    DoH returns TXT data with surrounding quotes, e.g. ``"v=spf1 ... ~all"``
    or multiple quoted parts. RFC 7208 concatenates the strings with no
    separator.
    """
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    if parts:
        return "".join(p.replace(r"\"", '"') for p in parts)
    return data.strip('"')


class SystemResolver:
    name = "system"

    def query(self, domain: str, rtype: str) -> QueryResult:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
        except dns.resolver.NXDOMAIN:
            return QueryResult(domain, rtype, self.name, status="nxdomain")
        except dns.resolver.NoAnswer:
            return QueryResult(domain, rtype, self.name, status="noerror-nodata")
        except dns.exception.Timeout:
            return QueryResult(domain, rtype, self.name, status="error", error="timeout")
        except Exception as exc:  # noqa: BLE001 - resolve raises several resolver errors
            return QueryResult(domain, rtype, self.name, status="error", error=str(exc))

        records = [
            Record(rtype=rtype, value=self._normalize(rtype, rdata)) for rdata in answers
        ]
        return QueryResult(domain, rtype, self.name, status="ok", records=records)

    @staticmethod
    def _normalize(rtype: str, rdata) -> str:
        if rtype == "TXT":
            return b"".join(rdata.strings).decode("utf-8", errors="replace")
        if rtype == "MX":
            exchange = rdata.exchange.to_text()
            # Preserve the null MX (RFC 7505) as "0 ." instead of collapsing it.
            host = exchange if exchange == "." else exchange.rstrip(".")
            return f"{rdata.preference} {host}"
        return rdata.to_text()


class DoHResolver:
    def __init__(self, name: str, base_url: str):
        self.name = name
        self.base_url = base_url

    def query(self, domain: str, rtype: str) -> QueryResult:
        url = f"{self.base_url}?name={domain}&type={rtype}&do=1"
        req = urllib.request.Request(
            url, headers={"Accept": "application/dns-json", "User-Agent": "neesha/0.1"}
        )
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())
        except Exception as exc:  # noqa: BLE001 - network failures are collection errors
            return QueryResult(domain, rtype, self.name, status="error", error=str(exc))

        status_code = data.get("Status", 2)
        if status_code == 3:  # NXDOMAIN
            return QueryResult(domain, rtype, self.name, status="nxdomain", ad=data.get("AD"))

        num = _RTYPE_NUM.get(rtype)
        records = []
        for ans in data.get("Answer", []):
            if num is None or ans.get("type") == num:
                records.append(Record(rtype=rtype, value=self._normalize(rtype, ans.get("data", ""))))

        status = "ok" if records else "noerror-nodata"
        return QueryResult(
            domain, rtype, self.name, status=status, records=records, ad=data.get("AD")
        )

    @staticmethod
    def _normalize(rtype: str, data: str) -> str:
        if rtype == "TXT":
            return parse_txt_data(data)
        if rtype == "MX":
            return data.rstrip(".")
        return data


def dnssec_status(resolvers: list[DoHResolver], domain: str) -> tuple[str, Optional[bool], bool]:
    """Derive DNSSEC status from the first DoH resolver that answers DNSKEY.

    Returns (status, ad, keys_present) where status is one of
    validated | signed-not-validated | unsigned | unknown.
    """
    for resolver in resolvers:
        result = resolver.query(domain, "DNSKEY")
        if result.status == "error":
            continue
        keys_present = any("DNSKEY" == rec.rtype or rec.value for rec in result.records)
        keys_present = bool(result.records)
        if result.ad and keys_present:
            return "validated", True, True
        if keys_present:
            return "signed-not-validated", False, True
        return "unsigned", result.ad, False
    return "unknown", None, False
