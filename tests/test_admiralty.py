from neesha.evidence.models import AdmiraltySourceGrade
from neesha.guardrail.admiralty import grade_claim, grade_source


def test_grade_source_table():
    assert grade_source("dns") == AdmiraltySourceGrade.B
    assert grade_source("commercial_api") == AdmiraltySourceGrade.C
    assert grade_source("social") == AdmiraltySourceGrade.D
    assert grade_source("sec_filing") == AdmiraltySourceGrade.A
    assert grade_source("bogus") == AdmiraltySourceGrade.F


def test_grade_claim_corroboration_improves_one_notch():
    assert grade_claim("commercial_api") == 3
    assert grade_claim("commercial_api", corroborated=True) == 2
    assert grade_claim("social") == 4
    assert grade_claim("social", corroborated=True) == 3


def test_grade_claim_inference_floor():
    # A direct observation that is an inference can never be "confirmed"/"probably true".
    assert grade_claim("dns", is_inference=True) == 3
    assert grade_claim("social", is_inference=True) == 4  # already >= 3
