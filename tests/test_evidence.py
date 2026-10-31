from neesha.evidence.crypto import FernetCipher, derive_key
from neesha.evidence.models import CollectionMode, Evidence
from neesha.evidence.store import EvidenceStore


def make_evidence(**overrides):
    defaults = dict(
        target_id="acme.com",
        claim="DMARC p=none",
        source_type="dns",
        collection_mode=CollectionMode.PASSIVE,
        collector="posture",
        agent="posture",
        scope_id="scope-1",
    )
    defaults.update(overrides)
    return Evidence(**defaults)


def test_insert_and_list_roundtrip(tmp_path):
    store = EvidenceStore(tmp_path / "e.db")
    store.insert(make_evidence())
    rows = store.list_by_target("acme.com")
    assert len(rows) == 1
    assert rows[0].claim == "DMARC p=none"
    assert rows[0].collection_mode == CollectionMode.PASSIVE


def test_sensitive_columns_encrypted_at_rest(tmp_path):
    store = EvidenceStore(
        tmp_path / "e.db", cipher=FernetCipher(derive_key("test-passphrase"))
    )
    store.insert(
        make_evidence(
            claim="vendor uses FooFirewall", source_url="https://example.com/case-study"
        )
    )
    store.close()

    raw = (tmp_path / "e.db").read_bytes()
    assert b"FooFirewall" not in raw
    assert b"example.com/case-study" not in raw


def test_encrypted_roundtrip_decrypts(tmp_path):
    cipher = FernetCipher(derive_key("test-passphrase"))
    store = EvidenceStore(tmp_path / "e.db", cipher=cipher)
    store.insert(make_evidence(claim="sensitive claim", source_url="https://x.example"))
    rows = store.list_by_target("acme.com")
    assert rows[0].claim == "sensitive claim"
    assert rows[0].source_url == "https://x.example"
