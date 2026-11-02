"""Sherlock username enumeration (Tier C, gated, aggregate-only).

Sherlock looks a username up across many sites. Only the names of sites where
an account was found are kept; profile URLs and other detail are discarded.
See account_enum.py for the gating and isolation contract.

Reference: https://github.com/sherlock-project/sherlock
"""
from __future__ import annotations

from typing import ClassVar

from neesha.adapters.account_enum import PROJECT_ROOT, AccountEnumAdapter, normalize_subject
from neesha.adapters.base import FactDraft, RawResult, Reference, Request


def parse_found_sites(output: bytes, max_services: int) -> list[str]:
    """Site names from '[+] Site: url' / '[+] Site' lines; nothing else kept."""
    found = []
    for raw_line in output.decode("utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line.startswith("[+]"):
            continue
        rest = line[3:].strip()
        name = rest.split(":", 1)[0].strip() if ":" in rest else rest.split()[0] if rest else ""
        if name and len(name) <= 64:
            found.append(name.lower())
        if len(found) >= max_services:
            break
    return found


class SherlockAdapter(AccountEnumAdapter):
    name: ClassVar[str] = "sherlock"
    binary_name: ClassVar[str] = "sherlock"
    description: ClassVar[str] = "Username account enumeration via Sherlock (client engagement only)"
    produces: ClassVar[frozenset[str]] = frozenset({"public.account"})
    accepts: ClassVar[frozenset[str]] = frozenset({"username"})
    subject_entity_kind: ClassVar[str] = "username"

    def fetch(self, reference: Reference) -> RawResult:
        subject = normalize_subject("username", reference.label)
        work_dir = PROJECT_ROOT / ".tools" / "sherlock"
        work_dir.mkdir(parents=True, exist_ok=True)
        args = [self.binary(), "--print-found", "--no-color", "--timeout", "10",
                "--folderoutput", str(work_dir), subject]
        output = self._run(args, work_dir)
        return self._sanitized(subject, parse_found_sites(output, self.max_services), reference)

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        return super().parse(raw, request)
