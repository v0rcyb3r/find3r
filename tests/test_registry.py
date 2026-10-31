from neesha.collectors.registry import PASSIVE_COLLECTORS, get_collector, list_collectors


def test_registry_contains_native_collectors():
    assert "crt.sh" in PASSIVE_COLLECTORS
    assert "otx" in PASSIVE_COLLECTORS
    assert "wayback" in PASSIVE_COLLECTORS
    assert "urlscan" in PASSIVE_COLLECTORS
    assert "hackertarget" in PASSIVE_COLLECTORS


def test_get_collector_unknown_returns_none():
    assert get_collector("bogus") is None


def test_list_collectors_returns_name_description():
    rows = dict(list_collectors())
    assert rows["crt.sh"]
    assert rows["wayback"]
