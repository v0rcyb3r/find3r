"""Adapter contract tests."""
from datetime import timedelta

import pytest

from neesha.adapters.base import (
    BaseAdapter,
    Cost,
    FactDraft,
    RawResult,
    Reference,
    Request,
)


class DemoAdapter(BaseAdapter):
    name = "demo"
    tier = "A"
    produces = frozenset({"dns", "email.dmarc"})
    accepts = frozenset({"domain"})
    retention_days = 14


class MeteredAdapter(BaseAdapter):
    name = "metered"
    tier = "B"
    produces = frozenset({"person.business_email"})
    requires_techniques = frozenset({"contact_enrichment"})

    def estimate_cost(self, request: Request) -> Cost:
        return Cost(usd=0.01, basis="per_call")


class GatedAdapter(BaseAdapter):
    name = "username-enum"
    tier = "C"
    produces = frozenset({"person.account"})
    requires_techniques = frozenset({"username_enum"})


# ---- planning: `produces` drives adapter selection ----------------------


def test_can_answer_matches_exact_attribute():
    assert DemoAdapter.can_answer(frozenset({"dns"}))


def test_can_answer_matches_by_prefix():
    """A PIR asks for email.dmarc.policy; the adapter declares email.dmarc."""
    assert DemoAdapter.can_answer(frozenset({"email.dmarc.policy"}))


def test_can_answer_rejects_unrelated_attributes():
    assert not DemoAdapter.can_answer(frozenset({"person.business_email"}))


def test_can_answer_does_not_match_a_partial_segment():
    """'dnssec.status' must not match a 'dns' producer."""
    assert not DemoAdapter.can_answer(frozenset({"dnssec.status"}))


def test_can_answer_is_true_if_any_attribute_matches():
    assert DemoAdapter.can_answer(frozenset({"person.role", "dns.a"}))


# ---- cost and tier ------------------------------------------------------


def test_free_adapter_is_not_metered():
    assert not DemoAdapter().estimate_cost(Request("domain", "acme.com")).is_metered


def test_metered_adapter_reports_a_cost():
    cost = MeteredAdapter().estimate_cost(Request("domain", "acme.com"))
    assert cost.is_metered and cost.usd == 0.01


def test_retention_policy_is_per_adapter():
    assert DemoAdapter().retention_policy() == timedelta(days=14)
    assert MeteredAdapter().retention_policy() == timedelta(days=30)


def test_gated_adapter_declares_the_technique_it_needs():
    """The gate checks this against engagement.permitted_techniques, which is
    what keeps username enumeration off prospect research."""
    assert GatedAdapter.requires_techniques == frozenset({"username_enum"})
    assert DemoAdapter.requires_techniques == frozenset()


# ---- caching ------------------------------------------------------------


def test_cache_key_is_stable_for_the_same_request():
    a = DemoAdapter()
    r1 = Request("domain", "acme.com")
    r2 = Request("domain", "ACME.com")  # canonicalized
    assert a.cache_key(r1) == a.cache_key(r2)


def test_cache_key_differs_by_adapter():
    r = Request("domain", "acme.com")
    assert DemoAdapter().cache_key(r) != MeteredAdapter().cache_key(r)


def test_cache_key_accounts_for_params():
    a = DemoAdapter()
    assert a.cache_key(Request("domain", "x.com", {"page": 1})) != a.cache_key(
        Request("domain", "x.com", {"page": 2})
    )


def test_param_order_does_not_change_the_key():
    a = DemoAdapter()
    k1 = a.cache_key(Request("domain", "x.com", {"a": 1, "b": 2}))
    k2 = a.cache_key(Request("domain", "x.com", {"b": 2, "a": 1}))
    assert k1 == k2


# ---- fact drafts --------------------------------------------------------


def test_attribute_must_be_namespaced():
    with pytest.raises(ValueError, match="dotted"):
        FactDraft(attribute="policy", value="none")


def test_unknown_sensitivity_is_rejected():
    with pytest.raises(ValueError, match="sensitivity"):
        FactDraft(attribute="dns.a", value="1.2.3.4", sensitivity="public")


def test_valid_draft_defaults_to_business_sensitivity():
    draft = FactDraft(attribute="dns.a", value="1.2.3.4")
    assert draft.sensitivity == "business"
    assert draft.is_inference is False


def test_raw_result_hashes_its_payload():
    raw = RawResult(payload=b"abc", request_url="https://x.example")
    assert raw.sha256 == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_reference_carries_origin_separately_from_request_url():
    """Circular reporting detection needs the canonical origin, not the URL
    we happened to fetch."""
    ref = Reference(url="https://outlet-b.example/story", origin_url="https://wire.example/1")
    assert ref.origin_url != ref.url
