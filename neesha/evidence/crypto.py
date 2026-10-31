"""At-rest encryption for sensitive evidence columns.

The store encrypts ``claim`` and ``source_url`` with an injectable Cipher.
The key is derived from a passphrase (``NEESHA_STORE_KEY``) via scrypt with a
per-store random salt, so a stolen database file cannot be attacked with a
precomputed table and each guess costs real memory and time.

Plaintext operation still exists for development, but it is now explicit:
callers must opt in, and the store refuses by default rather than degrading
silently. See ``EvidenceStore`` and AUDIT.md D1/D2.
"""
from __future__ import annotations

import base64
import os
from typing import Optional

# scrypt parameters. n=2**15 with r=8/p=1 is the interactive-use tier: ~32 MiB
# of memory per derivation, a fraction of a second on a laptop, and painful at
# scale for anyone brute-forcing a stolen store. Recorded in store_meta so a
# store written under one parameter set stays readable if these change.
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16

KDF_ID = "scrypt-fernet-v1"


class StoreEncryptionError(Exception):
    """Raised when a store cannot be opened safely with the given key material."""


class Cipher:
    def encrypt(self, plaintext: str) -> str:
        raise NotImplementedError

    def decrypt(self, token: str) -> str:
        raise NotImplementedError


class PlaintextCipher(Cipher):
    """No-op cipher. Development only, and only with an explicit opt-in."""

    def encrypt(self, plaintext: str) -> str:
        return plaintext

    def decrypt(self, token: str) -> str:
        return token


class FernetCipher(Cipher):
    def __init__(self, key: bytes):
        from cryptography.fernet import Fernet

        self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        from cryptography.fernet import InvalidToken

        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken as exc:
            raise StoreEncryptionError(
                "could not decrypt a stored value: NEESHA_STORE_KEY does not "
                "match the key this store was written with"
            ) from exc


def new_salt() -> bytes:
    return os.urandom(SALT_BYTES)


def derive_key(
    passphrase: str,
    salt: bytes,
    n: int = SCRYPT_N,
    r: int = SCRYPT_R,
    p: int = SCRYPT_P,
) -> bytes:
    """Derive a urlsafe-b64 Fernet key from a passphrase via scrypt."""
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    if not passphrase:
        raise StoreEncryptionError("refusing to derive a key from an empty passphrase")
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def make_cipher(passphrase: str, salt: bytes, **kdf_params) -> Cipher:
    """Build a Fernet cipher from a passphrase and the store's salt."""
    return FernetCipher(derive_key(passphrase, salt, **kdf_params))


def store_key_from_env() -> Optional[str]:
    key = os.environ.get("NEESHA_STORE_KEY")
    return key or None


def plaintext_allowed_by_env() -> bool:
    return os.environ.get("NEESHA_ALLOW_PLAINTEXT", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
