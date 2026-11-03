"""DeHashed API v2 / v1 breach & exposure intelligence adapter.

Queries DeHashed (`https://api.dehashed.com/v2/search` with `DeHashed-Api-Key`
header, or v1 Basic Auth fallback when `DEHASHED_EMAIL` is set) across domain,
company, email, username, IP, phone, and person selectors.

Security & Privacy Contract:
- Raw cleartext passwords (`password`), password hashes (`hashed_password`),
  vehicle identification numbers (`vin`), and physical street addresses (`address`)
  are NEVER persisted in `RawResult`, the SQLite cache, or `FactDraft` records.
- In-memory sanitization extracts breach dataset names (`database_name`),
  aggregate record and credential-exposure counts (`secret_exposure_count`,
  `hash_exposure_count`), exposed field classes, hash algorithm types, and
  associated OSINT selectors (emails, usernames, IPs, phones, names, companies).
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import ipaddress
import json
import os
import re
import threading
import time
from typing import Any, ClassVar
import urllib.parse
import urllib.request

from neesha.adapters.base import (
    AdapterError,
    BaseAdapter,
    Cost,
    FactDraft,
    RawResult,
    Reference,
    Request,
)
from neesha.collectors.network import _default_context
from neesha.resolve.intake import resolve_seed

API_V2_URL = "https://api.dehashed.com/v2/search"
API_V1_URL = "https://api.dehashed.com/search"
API_DOCUMENTATION = "https://app.dehashed.com/documentation/api"

_RATE_LOCK = threading.Lock()
_LAST_CALL = 0.0
_EMAIL_RE = re.compile(r"^[^@\s\"'<>]+@[a-z0-9.-]+\.[a-z]{2,24}$", re.IGNORECASE)
_USER_RE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9 .,'_-]{2,120}$")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _domain(value: str) -> str:
    value = (value or "").strip().lower().rstrip(".")
    if (
        len(value) > 253
        or len(value.split(".")) < 2
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
            for part in value.split(".")
        )
    ):
        raise AdapterError("DeHashed domain search requires a valid domain")
    return value


def _normalize_target(entity_kind: str, raw_value: str) -> tuple[str, str, str]:
    """Return `(canonical_kind, normalized_value, dehashed_query)` or raise `AdapterError`."""
    kind = (entity_kind or "domain").strip().lower()
    val = (raw_value or "").strip()
    if not val or any(c in val for c in ("\r", "\n", "\x00", '"', "'")):
        raise AdapterError("Invalid selector for DeHashed query")
    if re.search(r"\b(?:OR|AND|NOT)\b", val):
        raise AdapterError("Boolean operators are not permitted in DeHashed selector")

    if kind in ("domain", "company"):
        d = _domain(val)
        return "domain", d, f"domain:{d}"
    if kind == "email":
        try:
            norm = resolve_seed(val, "email")["normalized"]
        except ValueError as exc:
            raise AdapterError(f"DeHashed email search requires a valid email: {exc}") from None
        return "email", norm, f"email:{norm}"
    if kind == "username":
        try:
            norm = resolve_seed(val, "username")["normalized"]
        except ValueError as exc:
            raise AdapterError(f"DeHashed username search requires a valid username: {exc}") from None
        return "username", norm, f"username:{norm}"
    if kind == "ip":
        try:
            norm = resolve_seed(val, "ip")["normalized"]
        except ValueError as exc:
            raise AdapterError(f"DeHashed IP search requires a valid IP address: {exc}") from None
        return "ip", norm, f"ip_address:{norm}"
    if kind == "phone":
        try:
            norm = resolve_seed(val, "phone")["normalized"]
        except ValueError as exc:
            raise AdapterError(f"DeHashed phone search requires a valid phone number: {exc}") from None
        digits = re.sub(r"[^\d+]", "", norm)
        return "phone", norm, f"phone:{digits}"
    if kind == "person":
        try:
            norm = resolve_seed(val, "person")["normalized"]
        except ValueError as exc:
            raise AdapterError(f"DeHashed person search requires a valid person name: {exc}") from None
        if not _SAFE_NAME_RE.fullmatch(norm):
            raise AdapterError("DeHashed person search requires a valid person name")
        return "person", norm, f'name:"{norm}"'

    raise AdapterError(f"Unsupported entity kind for DeHashed: {kind}")


def _clean_list(val: Any) -> list[str]:
    """DeHashed v2 fields may be a string or a list of strings; normalize to clean strings."""
    if isinstance(val, str):
        s = val.strip()
        return [s] if s else []
    if isinstance(val, list):
        out = []
        for item in val:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
        return out
    return []


class DeHashedAdapter(BaseAdapter):
    name: ClassVar[str] = "dehashed"
    tier: ClassVar[str] = "C"
    default_enabled: ClassVar[bool] = False
    collection_mode: ClassVar[str] = "third_party_passive"
    source_type: ClassVar[str] = "commercial_api"
    description: ClassVar[str] = (
        "DeHashed API v2/v1 breach & exposure intelligence (dataset attribution, "
        "credential exposure counts, and correlated OSINT selectors; secrets sanitized)"
    )
    produces: ClassVar[frozenset[str]] = frozenset({
        "dehashed.search",
        "dehashed.breach",
        "public.dehashed",
    })
    accepts: ClassVar[frozenset[str]] = frozenset({
        "company",
        "domain",
        "email",
        "username",
        "ip",
        "phone",
        "person",
    })
    requires_techniques: ClassVar[frozenset[str]] = frozenset({"breach_metadata"})
    retention_days: ClassVar[int] = 14
    max_results: ClassVar[int] = 100
    max_response_bytes: ClassVar[int] = 1024 * 1024
    timeout: ClassVar[int] = 12

    def estimate_cost(self, request: Request) -> Cost:
        raw_price = os.environ.get("DEHASHED_ESTIMATED_USD_PER_SEARCH", "0.05")
        try:
            amount = Decimal(raw_price)
        except InvalidOperation:
            amount = Decimal("NaN")
        if not amount.is_finite() or not Decimal("0.0001") <= amount <= Decimal("1000000"):
            raise AdapterError(
                "Configure a positive DEHASHED_ESTIMATED_USD_PER_SEARCH covering the bounded search before collection"
            )
        return Cost(usd=float(amount), basis="per_call")

    def _key(self) -> str:
        key = (os.environ.get("DEHASHED_API_KEY") or os.environ.get("DEHASHED_KEY") or "").strip()
        if not key:
            raise AdapterError("DeHashed API key is not configured")
        return key

    def _email(self) -> str:
        return (os.environ.get("DEHASHED_EMAIL") or "").strip()

    def availability(self) -> dict:
        try:
            self._key()
            self.estimate_cost(Request("domain", "example.com"))
        except AdapterError as exc:
            return {"available": False, "reason": str(exc)}
        mode = "v2 + v1 Basic Auth" if self._email() else "v2 DeHashed-Api-Key"
        return {
            "available": True,
            "reason": f"Configured ({mode}); sanitizes passwords and hashes in memory before storage.",
        }

    def search(self, request: Request) -> list[Reference]:
        canonical_kind, norm_val, _ = _normalize_target(request.entity_kind, request.value)
        return [
            Reference(
                url=API_V2_URL,
                origin_url="https://app.dehashed.com/",
                label=f"{canonical_kind}:{norm_val}",
            )
        ]

    def _parse_reference_label(self, label: str) -> tuple[str, str, str]:
        if ":" in (label or ""):
            prefix, rest = label.split(":", 1)
            if prefix in ("domain", "company", "email", "username", "ip", "phone", "person"):
                return _normalize_target(prefix, rest)
        return _normalize_target("domain", label or "")

    def _request_json(self, query: str) -> dict[str, Any]:
        global _LAST_CALL
        api_key = self._key()
        account_email = self._email()

        with _RATE_LOCK:
            delay = 0.25 - (time.monotonic() - _LAST_CALL)
            if delay > 0:
                time.sleep(delay)
            _LAST_CALL = time.monotonic()

            opener = urllib.request.build_opener(
                _NoRedirect(),
                urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=_default_context()),
            )

            # 1. Primary: Official DeHashed v2 POST endpoint
            v2_payload = {
                "query": query,
                "page": 1,
                "size": self.max_results,
                "wildcard": False,
                "regex": False,
                "de_dupe": True,
            }
            v2_headers = {
                "DeHashed-Api-Key": api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "Find3r-OSINT/0.2",
            }
            req_v2 = urllib.request.Request(
                API_V2_URL,
                data=json.dumps(v2_payload).encode("utf-8"),
                headers=v2_headers,
                method="POST",
            )
            try:
                with opener.open(req_v2, timeout=self.timeout) as resp:
                    body = resp.read(self.max_response_bytes + 1)
                if len(body) > self.max_response_bytes:
                    raise AdapterError("DeHashed response exceeds the metadata size limit")
                parsed = json.loads(body.decode("utf-8", errors="replace"))
                if not isinstance(parsed, dict):
                    raise AdapterError("DeHashed returned an unexpected response shape")
                return parsed
            except AdapterError:
                raise
            except urllib.error.HTTPError as exc:
                # Optional fallback to DeHashed v1 GET endpoint if DEHASHED_EMAIL is configured
                if account_email and exc.code in (400, 401, 404, 405):
                    try:
                        basic = base64.b64encode(f"{account_email}:{api_key}".encode("utf-8")).decode("ascii")
                        params = urllib.parse.urlencode({"query": query, "size": self.max_results})
                        req_v1 = urllib.request.Request(
                            f"{API_V1_URL}?{params}",
                            headers={
                                "Authorization": f"Basic {basic}",
                                "Accept": "application/json",
                                "User-Agent": "Find3r-OSINT/0.2",
                            },
                            method="GET",
                        )
                        with opener.open(req_v1, timeout=self.timeout) as resp_v1:
                            body_v1 = resp_v1.read(self.max_response_bytes + 1)
                        if len(body_v1) > self.max_response_bytes:
                            raise AdapterError("DeHashed response exceeds the metadata size limit")
                        parsed_v1 = json.loads(body_v1.decode("utf-8", errors="replace"))
                        if isinstance(parsed_v1, dict):
                            return parsed_v1
                    except AdapterError:
                        raise
                    except Exception:
                        pass
                raise AdapterError("DeHashed metadata request failed") from None
            except Exception:
                raise AdapterError("DeHashed metadata request failed") from None

    def fetch(self, reference: Reference) -> RawResult:
        if reference is None or reference.url not in (API_V2_URL, API_V1_URL):
            raise AdapterError("DeHashed reference URL does not match official endpoint")
        canonical_kind, norm_val, query = self._parse_reference_label(reference.label)
        self._key()
        self.estimate_cost(Request(canonical_kind, norm_val))

        response = self._request_json(query)
        raw_entries = response.get("entries")
        if raw_entries is None:
            raw_entries = []
        if not isinstance(raw_entries, list):
            raise AdapterError("DeHashed returned invalid entries list")

        sampled_entries = raw_entries[: self.max_results]
        raw_total = response.get("total")
        total_results = int(raw_total) if isinstance(raw_total, int) and raw_total >= 0 else len(sampled_entries)

        db_counts: dict[str, int] = {}
        exposed_fields: set[str] = set()
        hash_types: set[str] = set()
        emails: list[str] = []
        usernames: list[str] = []
        ips: list[str] = []
        phones: list[str] = []
        names: list[str] = []
        companies: list[str] = []

        secret_exposure_count = 0
        hash_exposure_count = 0

        for entry in sampled_entries:
            if not isinstance(entry, dict):
                continue

            # 1. Breach dataset / source attribution
            db_name = entry.get("database_name") or entry.get("obtained_from")
            for db in _clean_list(db_name):
                clean_db = re.sub(r"[\r\n\t]+", " ", db).strip()[:100]
                if clean_db:
                    db_counts[clean_db] = db_counts.get(clean_db, 0) + 1

            # 2. Check credential presence WITHOUT storing password or hash strings
            pw_list = _clean_list(entry.get("password"))
            if pw_list:
                secret_exposure_count += 1
                exposed_fields.add("auth_secret_present")

            hpw_list = _clean_list(entry.get("hashed_password"))
            if hpw_list:
                hash_exposure_count += 1
                exposed_fields.add("auth_hash_present")

            for ht in _clean_list(entry.get("hash_type")):
                clean_ht = re.sub(r"[^A-Za-z0-9._+-]", "", ht.lower())[:32]
                if clean_ht:
                    hash_types.add(clean_ht)

            # 3. Emails
            for em in _clean_list(entry.get("email")):
                em_low = em.lower()
                if _EMAIL_RE.fullmatch(em_low):
                    exposed_fields.add("email")
                    if canonical_kind == "domain":
                        if not (em_low.endswith("@" + norm_val) or em_low.endswith("." + norm_val)):
                            continue
                    if em_low not in emails and len(emails) < 25:
                        emails.append(em_low)

            # 4. Usernames
            for un in _clean_list(entry.get("username")):
                if _USER_RE.fullmatch(un):
                    exposed_fields.add("username")
                    if un not in usernames and len(usernames) < 25:
                        usernames.append(un)

            # 5. IP addresses
            for ip_val in _clean_list(entry.get("ip_address")):
                try:
                    ip_obj = ipaddress.ip_address(ip_val)
                    ip_s = str(ip_obj)
                    exposed_fields.add("ip_address")
                    if ip_s not in ips and len(ips) < 20:
                        ips.append(ip_s)
                except ValueError:
                    continue

            # 6. Phones
            for ph in _clean_list(entry.get("phone")):
                digits = re.sub(r"[^\d+]", "", ph)
                if 7 <= len(re.sub(r"\D", "", digits)) <= 15:
                    exposed_fields.add("phone")
                    if digits not in phones and len(phones) < 15:
                        phones.append(digits)

            # 7. Names & Companies
            for nm in _clean_list(entry.get("name")):
                if _SAFE_NAME_RE.fullmatch(nm):
                    exposed_fields.add("name")
                    if nm not in names and len(names) < 20:
                        names.append(nm)

            for co in _clean_list(entry.get("company")):
                if _SAFE_NAME_RE.fullmatch(co):
                    exposed_fields.add("company")
                    if co not in companies and len(companies) < 15:
                        companies.append(co)

            # 8. Presence-only flags for sensitive PII (never persist values)
            if _clean_list(entry.get("address")):
                exposed_fields.add("address_present")
            if _clean_list(entry.get("vin")):
                exposed_fields.add("vin_present")

        sanitized = {
            "subject": norm_val,
            "subject_kind": canonical_kind,
            "total_results": total_results,
            "sample_count": len(sampled_entries),
            "secret_exposure_count": secret_exposure_count,
            "hash_exposure_count": hash_exposure_count,
            "database_counts": {k: db_counts[k] for k in sorted(db_counts)[:30]},
            "exposed_fields": sorted(exposed_fields),
            "hash_types": sorted(hash_types)[:10],
            "emails": emails,
            "usernames": usernames,
            "ips": ips,
            "phones": phones,
            "names": names,
            "companies": companies,
        }
        return RawResult(
            payload=json.dumps(sanitized, sort_keys=True).encode("utf-8"),
            request_url=API_V2_URL,
            origin_url="https://app.dehashed.com/",
            http_status=200,
            content_type="application/json",
            collected_at=datetime.now(timezone.utc),
        )

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        canonical_kind, norm_val, _ = _normalize_target(request.entity_kind, request.value)
        try:
            data = json.loads(raw.payload)
        except (ValueError, UnicodeError):
            raise AdapterError("Invalid sanitized DeHashed metadata") from None
        if (
            not isinstance(data, dict)
            or data.get("subject") != norm_val
            or data.get("subject_kind") != canonical_kind
        ):
            raise AdapterError("DeHashed metadata does not match the requested selector")

        total_results = data.get("total_results")
        sample_count = data.get("sample_count")
        secret_count = data.get("secret_exposure_count", 0)
        hash_count = data.get("hash_exposure_count", 0)
        db_counts = data.get("database_counts") or {}
        exposed_fields = data.get("exposed_fields") or []

        if (
            type(total_results) is not int
            or total_results < 0
            or type(sample_count) is not int
            or not 0 <= sample_count <= self.max_results
            or type(secret_count) is not int
            or secret_count < 0
            or type(hash_count) is not int
            or hash_count < 0
            or not isinstance(db_counts, dict)
            or not isinstance(exposed_fields, list)
        ):
            raise AdapterError("Invalid sanitized DeHashed metadata")

        is_company_scope = canonical_kind == "domain"
        ent_kind = "company" if is_company_scope else canonical_kind
        sensitivity = "business" if canonical_kind in ("domain", "ip") else "personal"
        id_key = None if is_company_scope else f"{canonical_kind}:{norm_val.lower()}"

        facts: list[FactDraft] = []

        def add(attr: str, val: str, value_type: str = "str"):
            if val is not None and str(val).strip():
                facts.append(
                    FactDraft(
                        attribute=attr,
                        value=str(val).strip()[:500],
                        value_type=value_type,
                        entity_kind=ent_kind,
                        entity_name=norm_val,
                        identity_key=id_key,
                        sensitivity=sensitivity,
                    )
                )

        add("dehashed.search.total_count", str(total_results), value_type="int")
        add("dehashed.search.sample_count", str(sample_count), value_type="int")
        add("dehashed.breach.secret_exposure_count", str(secret_count), value_type="int")
        add("dehashed.breach.hash_exposure_count", str(hash_count), value_type="int")

        if exposed_fields:
            add("dehashed.breach.exposed_fields", ", ".join(str(f) for f in exposed_fields))

        for db_name, count in sorted(db_counts.items()):
            add("dehashed.breach.database", f"{db_name} ({count})" if count > 1 else str(db_name))
            if not is_company_scope:
                add("public.dehashed.breach_database", str(db_name))

        for ht in data.get("hash_types") or []:
            add("dehashed.breach.hash_type", str(ht))

        for em in data.get("emails") or []:
            add("dehashed.breach.email", str(em))

        for un in data.get("usernames") or []:
            add("dehashed.breach.username", str(un))

        for ip_s in data.get("ips") or []:
            add("dehashed.breach.ip_address", str(ip_s))

        for ph in data.get("phones") or []:
            add("dehashed.breach.phone", str(ph))

        for nm in data.get("names") or []:
            add("dehashed.breach.name", str(nm))

        for co in data.get("companies") or []:
            add("dehashed.breach.company", str(co))

        return facts
