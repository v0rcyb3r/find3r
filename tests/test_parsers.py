from neesha.posture.parsers import parse_dmarc, parse_mtasts, parse_spf, parse_tlsrpt


def test_parse_spf_hardfail():
    result = parse_spf(["v=spf1 include:_spf.google.com -all"])
    assert result.present
    assert result.qualifier == "-all"


def test_parse_spf_softfail():
    result = parse_spf(["v=spf1 ip4:192.0.2.0/24 ~all"])
    assert result.qualifier == "~all"


def test_parse_spf_neutral():
    result = parse_spf(["v=spf1 ?all"])
    assert result.qualifier == "?all"


def test_parse_spf_absent():
    result = parse_spf(["not an spf record"])
    assert not result.present
    assert result.qualifier is None


def test_parse_dmarc_full():
    result = parse_dmarc(["v=DMARC1; p=none; rua=mailto:dmarc@example.com; pct=50"])
    assert result.present
    assert result.policy == "none"
    assert result.pct == 50
    assert result.rua == "mailto:dmarc@example.com"


def test_parse_dmarc_absent():
    assert not parse_dmarc([]).present


def test_parse_tlsrpt():
    result = parse_tlsrpt(["v=TLSRPTv1; rua=mailto:rpt@example.com"])
    assert result.present


def test_parse_mtasts():
    result = parse_mtasts(["v=STSv1; id=20240101"])
    assert result.present
