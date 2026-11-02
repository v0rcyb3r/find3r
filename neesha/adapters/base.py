"""The adapter contract.

One interface for every source, free or paid, so the policy gate and the
ledger can reason about all of them identically. Five things each adapter
must be able to say about itself — what it costs, how long its output may be
kept, what it can produce, what techniques it needs permission for, and how
to key its cache — plus three it must be able to do: search, fetch, parse.

Two properties of this shape matter more than the method list:

- ``produces`` is what makes planning deterministic. A Priority Intelligence
  Requirement names the attributes that would answer it; the planner selects
  adapters whose ``produces`` intersects that set and orders them by tier,
  then cost. No model call, and it is a table test.
- ``parse()`` is separate from ``fetch()``. A raw payload can be re-parsed
  without re-paying for the call, which is what lets the cache and the
  retention purge work on different clocks.

Adapters are never invoked directly. The executor is the sole caller and acts
only on gate-approved steps; a pivot is a new gated call. See CLAUDE.md
principle 3.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar, Optional, Protocol, runtime_checkable


class AdapterError(Exception):
    """A collection attempt failed.

    Raised, logged, and recorded as a gap. Never turned into evidence: a
    failed collection is an absence of fact, not a fact about absence.
    """


@dataclass(frozen=True)
class Request:
    """What an adapter is being asked to look at."""

    entity_kind: str  # company | domain | host | person | ...
    value: str  # the canonical identifier, e.g. "acme.com"
    params: dict[str, Any] = field(default_factory=dict)

    def canonical(self) -> str:
        value = self.value.strip()
        if self.entity_kind == 'email' and '@' in value:
            local, domain = value.rsplit('@', 1)
            value = local + '@' + domain.lower()
        else:
            value = value.lower()
        parts = [self.entity_kind, value]
        parts += [f"{k}={self.params[k]!r}" for k in sorted(self.params)]
        return "|".join(parts)


@dataclass(frozen=True)
class Cost:
    """An estimate, before the call. ``usd`` may be zero for Tier A."""

    usd: float = 0.0
    credits: int = 0
    basis: str = "free"  # free | per_call | per_credit | per_result | tokens

    @property
    def is_metered(self) -> bool:
        return self.usd > 0 or self.credits > 0


@dataclass(frozen=True)
class Reference:
    """Something search() found and fetch() can retrieve."""

    url: str
    origin_url: Optional[str] = None
    label: str = ""
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RawResult:
    """An unparsed response, as collected.

    ``request_url`` must already be credential-redacted: it is persisted to
    ``source_record`` and can reach an exported report. See AUDIT.md P1.
    """

    payload: bytes
    request_url: str
    origin_url: Optional[str] = None
    http_status: Optional[int] = None
    content_type: Optional[str] = None

    # When this was actually collected. A cache hit replays an older
    # collection, and the source record must say so rather than claiming the
    # data is as fresh as the run that reused it.
    collected_at: Optional[datetime] = None

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()

    def to_envelope(self) -> bytes:
        """Serialize for the cache, preserving provenance alongside the body.

        Caching the payload alone would lose the request URL, the origin and
        the original collection time, and a replayed result has to carry all
        three to stay honest.
        """
        when = self.collected_at or datetime.now(timezone.utc)
        return json.dumps(
            {
                "payload_b64": base64.b64encode(self.payload).decode(),
                "request_url": self.request_url,
                "origin_url": self.origin_url,
                "http_status": self.http_status,
                "content_type": self.content_type,
                "collected_at": when.isoformat(),
            }
        ).encode()

    @classmethod
    def from_envelope(cls, blob: bytes) -> "RawResult":
        data = json.loads(blob.decode())
        collected_at = data.get("collected_at")
        return cls(
            payload=base64.b64decode(data["payload_b64"]),
            request_url=data["request_url"],
            origin_url=data.get("origin_url"),
            http_status=data.get("http_status"),
            content_type=data.get("content_type"),
            collected_at=(
                datetime.fromisoformat(collected_at) if collected_at else None
            ),
        )


@dataclass(frozen=True)
class FactDraft:
    """A typed assertion, before it is written or graded.

    The adapter states what it observed and how sensitive it is. Admiralty
    grading, corroboration, and confidence ceilings are the guardrail's job,
    not the adapter's — a collector must not be able to grade its own output
    above what its source warrants.
    """

    attribute: str  # dotted, e.g. "email.dmarc.policy"
    value: str
    entity_kind: str = "domain"
    entity_name: Optional[str] = None  # defaults to the request subject
    value_type: str = "str"
    unit: Optional[str] = None
    is_inference: bool = False
    sensitivity: str = "business"
    identity_key: Optional[str] = None  # explicit stable identifier, never a name match

    def __post_init__(self) -> None:
        if not self.attribute or "." not in self.attribute:
            raise ValueError(
                f"attribute must be dotted and namespaced, got {self.attribute!r}"
            )
        segments = self.attribute.lower().replace('-', '_').split('.')
        if any(segment in {'password', 'passwd', 'password_hash', 'api_key', 'secret',
                           'access_token', 'credential', 'credentials'} for segment in segments):
            raise ValueError('Credential material cannot be stored as an intelligence fact.')
        inspected = re.sub(r'\b(?:password|passwd|api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*REDACTED(?=$|[&#;\s])', '', self.value, flags=re.I)
        if re.search(r'\b(?:password|passwd|api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]', inspected, re.I):
            raise ValueError('Credential-like values cannot be stored as intelligence facts.')
        if self.sensitivity not in ("business", "personal", "restricted"):
            raise ValueError(f"unknown sensitivity {self.sensitivity!r}")


@runtime_checkable
class Adapter(Protocol):
    """The contract. Every source implements exactly this."""

    name: ClassVar[str]
    tier: ClassVar[str]  # A free | B metered | C authority-gated | D contract
    collection_mode: ClassVar[str]  # third_party_passive | direct_contact | active
    description: ClassVar[str]

    # Attribute namespaces this adapter can emit. Drives planning.
    produces: ClassVar[frozenset[str]]
    # Entity kinds it accepts as input.
    accepts: ClassVar[frozenset[str]]
    # Techniques it needs an engagement to permit, e.g. {"username_enum"}.
    # Checked against engagement.permitted_techniques by the gate.
    requires_techniques: ClassVar[frozenset[str]]

    def estimate_cost(self, request: Request) -> Cost: ...

    def retention_policy(self) -> timedelta: ...

    def cache_key(self, request: Request) -> str: ...

    def search(self, request: Request) -> list[Reference]: ...

    def fetch(self, reference: Reference) -> RawResult: ...

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]: ...


class BaseAdapter:
    """Shared defaults. Subclasses override what differs.

    Deliberately not an ABC on ``search``: most adapters have exactly one
    deterministic URL per request, so the default is a single self-reference
    and only adapters that genuinely enumerate need to override it.
    """

    name: ClassVar[str] = "adapter"
    tier: ClassVar[str] = "A"
    collection_mode: ClassVar[str] = "third_party_passive"
    description: ClassVar[str] = ""
    produces: ClassVar[frozenset[str]] = frozenset()
    accepts: ClassVar[frozenset[str]] = frozenset({"domain"})
    requires_techniques: ClassVar[frozenset[str]] = frozenset()
    default_enabled: ClassVar[bool] = True
    retention_days: ClassVar[int] = 30

    def estimate_cost(self, request: Request) -> Cost:
        return Cost()

    def retention_policy(self) -> timedelta:
        return timedelta(days=self.retention_days)

    def cache_key(self, request: Request) -> str:
        return hashlib.sha256(
            f"{self.name}|{request.canonical()}".encode()
        ).hexdigest()

    def search(self, request: Request) -> list[Reference]:
        raise NotImplementedError

    def fetch(self, reference: Reference) -> RawResult:
        raise NotImplementedError

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        raise NotImplementedError

    @classmethod
    def can_answer(cls, attributes: frozenset[str]) -> bool:
        """True if any requested attribute falls in this adapter's namespace.

        Matching is by prefix so a PIR can ask for ``email.dmarc.policy`` and
        reach an adapter that declares ``email.dmarc``.
        """
        for wanted in attributes:
            for produced in cls.produces:
                if wanted == produced or wanted.startswith(produced + "."):
                    return True
        return False
