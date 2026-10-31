import pytest

from neesha.evidence.crypto import StoreEncryptionError
from neesha.evidence.models import CollectionMode, Evidence
from neesha.evidence.store import EvidenceStore
from tests.helpers import make_store


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
    store = make_store(tmp_path / "e.db")
    store.insert(make_evidence())
    rows = store.list_by_target("acme.com")
    assert len(rows) == 1
    assert rows[0].claim == "DMARC p=none"
    assert rows[0].collection_mode == CollectionMode.PASSIVE


def test_sensitive_columns_encrypted_at_rest(tmp_path):
    store = make_store(tmp_path / "e.db")
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
    store = make_store(tmp_path / "e.db")
    store.insert(make_evidence(claim="sensitive claim", source_url="https://x.example"))
    rows = store.list_by_target("acme.com")
    assert rows[0].claim == "sensitive claim"
    assert rows[0].source_url == "https://x.example"


# ---- AUDIT.md D1: no silent plaintext ------------------------------------


def test_plaintext_refused_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("NEESHA_STORE_KEY", raising=False)
    monkeypatch.delenv("NEESHA_ALLOW_PLAINTEXT", raising=False)
    with pytest.raises(StoreEncryptionError) as exc:
        EvidenceStore(tmp_path / "e.db")
    assert "NEESHA_STORE_KEY" in str(exc.value)


def test_plaintext_requires_explicit_opt_in(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("NEESHA_STORE_KEY", raising=False)
    store = EvidenceStore(tmp_path / "e.db", allow_plaintext=True)
    store.insert(make_evidence(claim="visible"))
    assert b"visible" in (tmp_path / "e.db").read_bytes()
    assert "UNENCRYPTED" in capsys.readouterr().err


def test_env_var_opts_in_to_plaintext(tmp_path, monkeypatch):
    monkeypatch.delenv("NEESHA_STORE_KEY", raising=False)
    monkeypatch.setenv("NEESHA_ALLOW_PLAINTEXT", "1")
    store = EvidenceStore(tmp_path / "e.db")
    store.insert(make_evidence())
    assert store.count() == 1


def test_encrypted_store_without_key_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("NEESHA_STORE_KEY", "a-real-passphrase")
    EvidenceStore(tmp_path / "e.db").close()

    monkeypatch.delenv("NEESHA_STORE_KEY", raising=False)
    monkeypatch.delenv("NEESHA_ALLOW_PLAINTEXT", raising=False)
    with pytest.raises(StoreEncryptionError) as exc:
        EvidenceStore(tmp_path / "e.db")
    assert "encrypted" in str(exc.value)


def test_wrong_key_fails_loudly_not_silently(tmp_path, monkeypatch):
    monkeypatch.setenv("NEESHA_STORE_KEY", "first-passphrase")
    store = EvidenceStore(tmp_path / "e.db")
    store.insert(make_evidence(claim="secret"))
    store.close()

    monkeypatch.setenv("NEESHA_STORE_KEY", "second-passphrase")
    store = EvidenceStore(tmp_path / "e.db")
    with pytest.raises(StoreEncryptionError):
        store.list_by_target("acme.com")


def test_legacy_plaintext_store_refuses_a_key(tmp_path, monkeypatch):
    monkeypatch.delenv("NEESHA_STORE_KEY", raising=False)
    store = EvidenceStore(tmp_path / "e.db", allow_plaintext=True)
    store.insert(make_evidence())
    store.close()

    monkeypatch.setenv("NEESHA_STORE_KEY", "a-passphrase")
    with pytest.raises(StoreEncryptionError) as exc:
        EvidenceStore(tmp_path / "e.db")
    assert "plaintext" in str(exc.value)


def test_salt_is_per_store(tmp_path, monkeypatch):
    monkeypatch.setenv("NEESHA_STORE_KEY", "same-passphrase")
    a = EvidenceStore(tmp_path / "a.db")
    b = EvidenceStore(tmp_path / "b.db")
    assert a._meta_get("salt") != b._meta_get("salt")
    assert a._meta_get("kdf") == "scrypt-fernet-v1"
