"""Maigret username enumeration (Tier C, gated, aggregate-only).

Maigret resolves a username across many sites. Only the names of sites where
an account was found are kept; everything else (URLs, scraped profile detail)
is discarded. See account_enum.py for the gating and isolation contract.

Reference: https://github.com/soxoj/maigret
"""
from __future__ import annotations

from typing import ClassVar

from neesha.adapters.account_enum import PROJECT_ROOT, AccountEnumAdapter, normalize_subject
from neesha.adapters.base import FactDraft, RawResult, Reference, Request
from neesha.adapters.sherlock import parse_found_sites


class MaigretAdapter(AccountEnumAdapter):
    name: ClassVar[str] = "maigret"
    binary_name: ClassVar[str] = "maigret"
    description: ClassVar[str] = "Username account enumeration via Maigret (client engagement only)"
    produces: ClassVar[frozenset[str]] = frozenset({"public.account"})
    accepts: ClassVar[frozenset[str]] = frozenset({"username"})
    subject_entity_kind: ClassVar[str] = "username"

    def fetch(self, reference: Reference) -> RawResult:
        subject = normalize_subject("username", reference.label)
        with self._temp_cwd() as cwd:
            # --no-recursion / --no-extracting keep the run to the one authorized
            # username: Maigret must not pivot to identifiers it discovers, since
            # any such pivot is a new gated step, not a free extension of scope.
            # --no-color keeps stdout parseable; reports land in the throwaway
            # dir and are removed with it.
            args = [self.binary(), "--no-color", "--no-recursion", "--no-extracting",
                    "--timeout", "10", "--folderoutput", str(cwd), subject]
            output = self._run(args, cwd)
        return self._sanitized(subject, parse_found_sites(output, self.max_services), reference)

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        return super().parse(raw, request)
