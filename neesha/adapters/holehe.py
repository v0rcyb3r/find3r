"""Holehe account-enumeration runner (Tier C, gated, aggregate-only).

Holehe checks an email against many services' sign-up/recovery endpoints.
Only the names of services where an account was found are kept; Holehe's
recovery-email and phone hints are discarded in fetch. See account_enum.py.

Reference: https://github.com/megadose/holehe
"""
from __future__ import annotations

from typing import ClassVar

from neesha.adapters.account_enum import AccountEnumAdapter
from neesha.adapters.base import FactDraft, RawResult, Reference, Request
from neesha.adapters.email_public import normalize_email


class HoleheAdapter(AccountEnumAdapter):
    name: ClassVar[str] = "holehe"
    binary_name: ClassVar[str] = "holehe"
    description: ClassVar[str] = "Email account-existence enumeration via Holehe (client engagement only)"
    produces: ClassVar[frozenset[str]] = frozenset({"public.account"})

    def fetch(self, reference: Reference) -> RawResult:
        subject = normalize_email(reference.label)
        with self._temp_cwd() as cwd:
            # --only-used limits noise; --no-color keeps stdout machine-parseable.
            args = [self.binary(), "--only-used", "--no-color", subject]
            output = self._run(args, cwd)
        return self._sanitized(subject, self._parse_stdout(output), reference)

    @staticmethod
    def _parse_stdout(output: bytes) -> list[str]:
        """Extract only the services Holehe marked as used ('[+] domain').

        Everything else — not-found, rate-limited, and the recovery hints that
        can follow a used entry — is ignored, so no recovery data is retained.
        """
        found = []
        for raw_line in output.decode("utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line.startswith("[+]"):
                continue
            token = line[3:].strip().split()[0] if line[3:].strip() else ""
            # Keep a plain service domain/name token only.
            if token and all(c.isalnum() or c in ".-_" for c in token):
                found.append(token.lower())
        return found

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        return super().parse(raw, request)
