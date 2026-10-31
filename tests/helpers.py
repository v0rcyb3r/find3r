"""Shared test helpers."""
from neesha.evidence.crypto import FernetCipher, derive_key
from neesha.evidence.store import EvidenceStore

# Fixed salt so test key derivation is deterministic and cheap to reason about.
TEST_SALT = bytes(range(16))
TEST_PASSPHRASE = "test-passphrase"


def cipher_for_tests() -> FernetCipher:
    return FernetCipher(derive_key(TEST_PASSPHRASE, TEST_SALT))


def make_store(path, **kwargs) -> EvidenceStore:
    """An encrypted store, so tests exercise the real at-rest path."""
    return EvidenceStore(path, cipher=cipher_for_tests(), **kwargs)
