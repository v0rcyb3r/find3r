"""A-F posture grading with transparent, documented rubrics.

The rubric is deliberately simple and legible so every grade traces to the
checks behind it. Scores are 0-100; letters map A>=90, B>=80, C>=70, D>=60,
else F. Weights: email auth 40%, TLS/transport 25%, web headers 20%,
DNSSEC 15%.
"""
from __future__ import annotations

from neesha.posture.brief import Grade, Trigger
from neesha.posture.facts import (
    DKIMResult,
    DMARCResult,
    DNSSECResult,
    HTTPResult,
    SPFResult,
    TLSResult,
)

_DMARC_SCORE = {"reject": 100, "quarantine": 75, "none": 40}
_SPF_SCORE = {"-all": 100, "~all": 80, "?all": 40, "+all": 0}


def score_to_letter(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def grade_email_auth(spf: SPFResult, dmarc: DMARCResult, dkim: DKIMResult, unstable: bool) -> Grade:
    dmarc_score = _DMARC_SCORE.get(dmarc.policy, 0) if dmarc.present else 0
    spf_score = _SPF_SCORE.get(spf.qualifier, 0) if spf.present else 0
    if dkim.selectors_found:
        dkim_score = 100
    elif dkim.wildcard:
        dkim_score = 50  # absence under a wildcard is not a misconfiguration signal
    else:
        dkim_score = 20

    score = 0.4 * dmarc_score + 0.3 * spf_score + 0.3 * dkim_score
    rationale = (
        f"DMARC {dmarc.policy or 'absent'}, SPF {spf.qualifier or 'absent'}, "
        f"DKIM {'found' if dkim.selectors_found else ('wildcard-neutral' if dkim.wildcard else 'absent')}"
    )
    if unstable:
        rationale += " (unstable across resolvers — provisional)"
    return Grade(letter=score_to_letter(score), score=round(score), rationale=rationale)


def grade_tls_and_transport(tls: TLSResult, hsts: bool) -> Grade:
    cert_score = 0
    if tls.connected and tls.days_remaining is not None and tls.days_remaining > 0:
        cert_score = 60
    elif tls.connected:
        cert_score = 20  # expired or indeterminate
    days = tls.days_remaining
    expiry_score = 25 if days is not None and days > 60 else (
        15 if days is not None and days > 30 else (8 if days is not None and days > 0 else 0)
    )
    hsts_score = 15 if hsts else 0
    score = cert_score + expiry_score + hsts_score
    rationale = (
        f"TLS {'connected' if tls.connected else 'failed'}, "
        f"cert {'expiring soon' if days is not None and days <= 30 else 'healthy'}, "
        f"HSTS {'present' if hsts else 'absent'}"
    )
    return Grade(letter=score_to_letter(score), score=score, rationale=rationale)


def grade_headers(http: HTTPResult) -> Grade:
    score = (
        (30 if http.csp else 0)
        + (25 if http.x_frame_options else 0)
        + (20 if http.x_content_type_options else 0)
        + (15 if http.referrer_policy else 0)
        + (10 if http.permissions_policy else 0)
    )
    rationale = (
        f"CSP {'present' if http.csp else 'absent'}, "
        f"X-Frame-Options {'present' if http.x_frame_options else 'absent'}, "
        f"X-Content-Type-Options {'present' if http.x_content_type_options else 'absent'}"
    )
    return Grade(letter=score_to_letter(score), score=score, rationale=rationale)


def grade_dnssec(dnssec: DNSSECResult) -> Grade:
    score = {"validated": 100, "signed-not-validated": 50}.get(dnssec.status, 0)
    return Grade(letter=score_to_letter(score), score=score, rationale=f"DNSSEC {dnssec.status}")


def build_triggers(
    spf: SPFResult, dmarc: DMARCResult, dkim: DKIMResult, tls: TLSResult, http: HTTPResult, dnssec: DNSSECResult
) -> list[Trigger]:
    triggers: list[Trigger] = []

    if not dmarc.present:
        triggers.append(Trigger(
            signal="No DMARC policy",
            why_now="Domain has no DMARC record; spoofed email can pass SPF-only filtering",
            offering="DMARC enforcement / email auth managed service",
        ))
    elif dmarc.policy == "none":
        triggers.append(Trigger(
            signal="DMARC at p=none",
            why_now="DMARC is monitoring-only; spoofing is not blocked",
            offering="DMARC enforcement / email auth managed service",
        ))
    elif dmarc.policy == "quarantine":
        triggers.append(Trigger(
            signal="DMARC at p=quarantine",
            why_now="Spoofed mail is quarantined, not rejected; tightening to reject is available",
            offering="DMARC enforcement / email auth managed service",
        ))

    if not spf.present:
        triggers.append(Trigger(
            signal="No SPF record",
            why_now="Absent SPF lets anyone send as this domain",
            offering="Email auth managed service",
        ))
    elif spf.qualifier in ("?all", "+all", "unknown"):
        triggers.append(Trigger(
            signal=f"SPF not enforced ({spf.qualifier})",
            why_now="SPF policy does not hard-fail unauthorized senders",
            offering="SPF hardening",
        ))

    if not dkim.selectors_found and not dkim.wildcard:
        triggers.append(Trigger(
            signal="No DKIM signing",
            why_now="No DKIM record found on checked selectors; outgoing mail lacks a signing identity",
            offering="DKIM signing setup",
        ))

    if tls.connected and tls.days_remaining is not None and tls.days_remaining <= 30:
        triggers.append(Trigger(
            signal="TLS certificate expiring",
            why_now=f"Certificate has {tls.days_remaining} days remaining",
            offering="Certificate lifecycle monitoring",
        ))
    if tls.connected and tls.days_remaining is not None and tls.days_remaining < 0:
        triggers.append(Trigger(
            signal="TLS certificate expired",
            why_now="Certificate is past its notAfter date",
            offering="Certificate lifecycle monitoring",
        ))

    if http.fetched and not http.https_available:
        triggers.append(Trigger(
            signal="No HTTPS",
            why_now="Site is reachable only over plaintext HTTP",
            offering="TLS / web security hardening",
        ))
    if http.fetched and not http.hsts:
        triggers.append(Trigger(
            signal="No HSTS",
            why_now="No Strict-Transport-Security; plaintext connections are not prevented",
            offering="Web security hardening",
        ))
    if http.fetched and not http.csp:
        triggers.append(Trigger(
            signal="No Content-Security-Policy",
            why_now="No CSP reduces exposure to injection and data-exfiltration attacks",
            offering="Web application security",
        ))

    if dnssec.status == "unsigned":
        triggers.append(Trigger(
            signal="DNSSEC not signed",
            why_now="Zone is unsigned; responses are not cryptographically authenticated",
            offering="DNSSEC implementation",
        ))

    return triggers


def grade_posture(
    spf: SPFResult,
    dmarc: DMARCResult,
    dkim: DKIMResult,
    tls: TLSResult,
    http: HTTPResult,
    dnssec: DNSSECResult,
    unstable: bool,
) -> tuple[Grade, dict[str, Grade], list[Trigger]]:
    email = grade_email_auth(spf, dmarc, dkim, unstable)
    tls_grade = grade_tls_and_transport(tls, bool(http.hsts))
    headers = grade_headers(http)
    dnssec_grade = grade_dnssec(dnssec)

    overall = 0.4 * email.score + 0.25 * tls_grade.score + 0.2 * headers.score + 0.15 * dnssec_grade.score
    rationale = f"Email auth {email.letter}, TLS/transport {tls_grade.letter}, headers {headers.letter}, DNSSEC {dnssec_grade.letter}"
    overall_grade = Grade(letter=score_to_letter(overall), score=round(overall), rationale=rationale)

    categories = {
        "email_auth": email,
        "tls_transport": tls_grade,
        "web_headers": headers,
        "dnssec": dnssec_grade,
    }
    return overall_grade, categories, build_triggers(spf, dmarc, dkim, tls, http, dnssec)
