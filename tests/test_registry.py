from neesha.collectors.registry import PASSIVE_COLLECTORS, get_collector, list_collectors


def test_registry_contains_native_collectors():
    assert "crt.sh" in PASSIVE_COLLECTORS
    assert "otx" in PASSIVE_COLLECTORS
    assert "wayback" in PASSIVE_COLLECTORS
    assert "urlscan" in PASSIVE_COLLECTORS
    assert "hackertarget" in PASSIVE_COLLECTORS


def test_get_collector_unknown_returns_none():
    assert get_collector("bogus") is None


def test_list_collectors_returns_name_tier_description():
    rows = {name: description for name, _tier, description in list_collectors()}
    assert rows["crt.sh"]
    assert rows["wayback"]


# ---- AUDIT.md S1: the default path must not spend money ------------------

from neesha.collectors.registry import (  # noqa: E402
    ALL_COLLECTORS,
    DEFAULT_COLLECTORS,
    RUNNABLE_COLLECTORS,
    is_metered,
)


def test_default_set_is_free_tier_only():
    assert DEFAULT_COLLECTORS, "there must be a usable free default"
    for name, cls in DEFAULT_COLLECTORS.items():
        assert cls.tier == "A", f"{name} is tier {cls.tier} but runs by default"


def test_no_metered_collector_runs_by_default():
    assert not [n for n in DEFAULT_COLLECTORS if is_metered(n)]


def test_hunter_is_metered_and_not_default():
    assert is_metered("hunter")
    assert "hunter" not in DEFAULT_COLLECTORS


def test_contract_gated_collectors_are_not_runnable():
    assert "zoominfo" in ALL_COLLECTORS
    assert ALL_COLLECTORS["zoominfo"].tier == "D"
    assert "zoominfo" not in RUNNABLE_COLLECTORS
    assert "zoominfo" not in DEFAULT_COLLECTORS
