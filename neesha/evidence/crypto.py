"""At-rest encryption for sensitive evidence columns.

The store encrypts claim and source_url with an injectable Cipher. Without a
passphrase (NEESHA_STORE_KEY) it degrades to plaintext and the caller warns.
Fernet is used when the optional ``crypto`` extra is installed.
"""
from __future__ import annotations

import base64
import hashlib
import os
from typing import Optional


class Cipher:
    def encrypt(self, plaintext: str) -> str:
        raise NotImplementedError

    def decrypt(self, token: str) -> str:
        raise NotImplementedError


class PlaintextCipher(Cipher):
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
        return self._fernet.decrypt(token.encode()).decode()


def derive_key(passphrase: str) -> bytes:
    """Derive a 32-byte urlsafe-b64 Fernet key from an arbitrary passphrase."""
    digest = hashlib.sha256(passphrase.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def make_cipher(passphrase: Optional[str] = None) -> Cipher:
    """Build a cipher from a passphrase or NEESHA_STORE_KEY, else plaintext."""
    passphrase = passphrase or os.environ.get("NEESHA_STORE_KEY")
    if not passphrase:
        return PlaintextCipher()
    try:
        return FernetCipher(derive_key(passphrase))
    except ImportError:
        return PlaintextCipher()
