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
from neesha.adapters.sherlock import parse_found_sites, parse_found_urls


class MaigretAdapter(AccountEnumAdapter):
    name: ClassVar[str] = "maigret"
    binary_name: ClassVar[str] = "maigret"
    description: ClassVar[str] = "Username account enumeration via Maigret"
    produces: ClassVar[frozenset[str]] = frozenset({"public.account"})
    accepts: ClassVar[frozenset[str]] = frozenset({"username"})
    subject_entity_kind: ClassVar[str] = "username"

    def fetch(self, reference: Reference) -> RawResult:
        subject = normalize_subject("username", reference.label)
        with self._temp_cwd() as cwd:
            args = [self.binary(), "--no-color", "--no-recursion", "--no-extracting",
                    "--top-sites", "50", "--timeout", "5", "--folderoutput", str(cwd), subject]
            output = self._run(args, cwd)
        return self._sanitized(
            subject,
            parse_found_sites(output, self.max_services),
            reference,
            found_urls=parse_found_urls(output, self.max_services),
        )

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        return super().parse(raw, request)
