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
        work_dir = PROJECT_ROOT / ".tools" / "maigret"
        work_dir.mkdir(parents=True, exist_ok=True)
        # --no-color keeps stdout parseable; -T limits per-site time. Reports are
        # written under the isolated work dir and never read back for detail.
        args = [self.binary(), "--no-color", "--timeout", "10", "--folderoutput", str(work_dir), subject]
        output = self._run(args, work_dir)
        return self._sanitized(subject, parse_found_sites(output, self.max_services), reference)

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        return super().parse(raw, request)
