"""Socialscan account-enumeration runner (Tier C, gated, aggregate-only).

Socialscan reports whether an email (or username) is already registered on a
set of platforms. Only the platforms where the address is in use are kept.
See account_enum.py for the gating and isolation contract.

Reference: https://github.com/iojw/socialscan
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

from neesha.adapters.account_enum import PROJECT_ROOT, AccountEnumAdapter
from neesha.adapters.base import AdapterError, FactDraft, RawResult, Reference, Request
from neesha.adapters.email_public import normalize_email


class SocialscanAdapter(AccountEnumAdapter):
    name: ClassVar[str] = "socialscan"
    binary_name: ClassVar[str] = "socialscan"
    description: ClassVar[str] = "Email registration enumeration via Socialscan (client engagement only)"
    produces: ClassVar[frozenset[str]] = frozenset({"public.account"})

    def fetch(self, reference: Reference) -> RawResult:
        subject = normalize_email(reference.label)
        work_dir = PROJECT_ROOT / ".tools" / "socialscan"
        work_dir.mkdir(parents=True, exist_ok=True)
        report = work_dir / "report.json"
        # Write JSON to a controlled temp path inside the isolated work dir.
        args = [self.binary(), subject, "--json", str(report)]
        try:
            self._run(args, work_dir)
            raw = report.read_bytes()[: self.max_output_bytes + 1] if report.exists() else b"[]"
        finally:
            try:
                report.unlink(missing_ok=True)
            except OSError:
                pass
        return self._sanitized(subject, self._parse_json(raw), reference)

    @staticmethod
    def _parse_json(raw: bytes) -> list[str]:
        """Keep only platforms where the address is in use ('available' False).

        Socialscan reports per (query, platform): available/valid/success. An
        existing account is `available == False and success and valid`.
        """
        try:
            data = json.loads(raw.decode("utf-8", errors="replace") or "[]")
        except (ValueError, UnicodeError):
            raise AdapterError("Socialscan returned invalid JSON") from None
        rows = data if isinstance(data, list) else data.get("results", []) if isinstance(data, dict) else []
        found = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            platform = row.get("platform")
            if (isinstance(platform, str) and row.get("success") is True
                    and row.get("valid") is True and row.get("available") is False):
                found.append(platform.strip().lower())
        return found

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        return super().parse(raw, request)
