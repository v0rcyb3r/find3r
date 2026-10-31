"""Pure parsers for SPF/DMARC/MTA-STS/TLS-RPT. No network, no IO."""
from __future__ import annotations

import re

from neesha.posture.facts import DMARCResult, MTASTSResult, SPFResult, TLSRPTResult

_ALL_RE = re.compile(r"^([+~?-])?all$")


def parse_spf(txt_records: list[str], unstable: bool = False) -> SPFResult:
    spf = [r for r in txt_records if r.startswith("v=spf1")]
    if not spf:
        return SPFResult(unstable=unstable)
    record = spf[0]
    qualifier = None
    for token in record.split():
        if _ALL_RE.match(token):
            qualifier = (token[0] if token[0] in "+~?-" else "+") + "all"
    return SPFResult(present=True, record=record, qualifier=qualifier or "unknown", unstable=unstable)


def parse_dmarc(txt_records: list[str], unstable: bool = False) -> DMARCResult:
    dmarc = [r for r in txt_records if r.upper().startswith("V=DMARC1")]
    if not dmarc:
        return DMARCResult(unstable=unstable)
    record = dmarc[0]
    result = DMARCResult(present=True, record=record, unstable=unstable)
    for tag in record.split(";"):
        tag = tag.strip()
        if "=" not in tag:
            continue
        key, value = tag.split("=", 1)
        key, value = key.strip().lower(), value.strip()
        if key == "p":
            result.policy = value
        elif key == "sp":
            result.subdomain_policy = value
        elif key == "pct":
            try:
                result.pct = int(value)
            except ValueError:
                pass
        elif key == "rua":
            result.rua = value
        elif key == "ruf":
            result.ruf = value
    return result


def parse_tlsrpt(txt_records: list[str]) -> TLSRPTResult:
    for r in txt_records:
        if r.upper().startswith("V=TLSRPTV1"):
            return TLSRPTResult(present=True, record=r)
    return TLSRPTResult()


def parse_mtasts(txt_records: list[str]) -> MTASTSResult:
    for r in txt_records:
        if r.upper().startswith("V=STSV1"):
            return MTASTSResult(present=True, record=r)
    return MTASTSResult()
