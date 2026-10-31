from neesha.posture.facts import (
    DKIMResult,
    DMARCResult,
    DNSSECResult,
    HTTPResult,
    SPFResult,
    TLSResult,
)
from neesha.posture.grader import grade_posture, score_to_letter


def strong_http() -> HTTPResult:
    return HTTPResult(
        fetched=True,
        https_available=True,
        hsts="max-age=31536000",
        csp=True,
        x_frame_options="DENY",
        x_content_type_options="nosniff",
        referrer_policy=True,
        permissions_policy=True,
    )


def test_strong_posture_scores_a():
    spf = SPFResult(present=True, record="v=spf1 -all", qualifier="-all")
    dmarc = DMARCResult(present=True, record="v=DMARC1; p=reject", policy="reject")
    dkim = DKIMResult(selectors_found=["google"])
    tls = TLSResult(connected=True, issuer="R3", days_remaining=80)
    dnssec = DNSSECResult(status="validated", ad=True, keys_present=True)

    overall, categories, triggers = grade_posture(spf, dmarc, dkim, tls, strong_http(), dnssec, False)
    assert overall.letter == "A"
    assert overall.score == 100
    assert not triggers


def test_weak_posture_scores_f_and_triggers():
    spf = SPFResult(present=False)
    dmarc = DMARCResult(present=False)
    dkim = DKIMResult(selectors_found=[], wildcard=False)
    tls = TLSResult(connected=False)
    dnssec = DNSSECResult(status="unsigned")

    overall, categories, triggers = grade_posture(spf, dmarc, dkim, tls, HTTPResult(fetched=False), dnssec, False)
    assert overall.letter == "F"
    signals = {t.signal for t in triggers}
    assert "No DMARC policy" in signals
    assert "No SPF record" in signals
    assert "No DKIM signing" in signals
    assert "DNSSEC not signed" in signals


def test_wildcard_dkim_is_not_a_gap():
    spf = SPFResult(present=True, qualifier="-all")
    dmarc = DMARCResult(present=True, policy="reject")
    dkim = DKIMResult(selectors_found=[], wildcard=True)
    tls = TLSResult(connected=True, days_remaining=80)
    dnssec = DNSSECResult(status="validated")

    overall, categories, triggers = grade_posture(spf, dmarc, dkim, tls, strong_http(), dnssec, False)
    assert not any("DKIM" in t.signal for t in triggers)


def test_score_to_letter():
    assert score_to_letter(95) == "A"
    assert score_to_letter(85) == "B"
    assert score_to_letter(75) == "C"
    assert score_to_letter(65) == "D"
    assert score_to_letter(10) == "F"
