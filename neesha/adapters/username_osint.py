"""Built-in keyless username OSINT adapter.

Performs concurrent public profile checks across major developer, social,
and package-registry platforms without requiring external CLI binaries
(sherlock, maigret). Emits ``public.account.*`` observations for every
verified profile match as well as a summary observation so username runs
never end with zero facts.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
from typing import Any, Callable, ClassVar, Optional
import urllib.error
import urllib.parse
import urllib.request

from neesha.adapters.account_enum import normalize_subject
from neesha.adapters.base import AdapterError, BaseAdapter, FactDraft, RawResult, Reference, Request
from neesha.collectors.network import _default_context

DEFAULT_TIMEOUT = 6.0
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) NEESHA-OSINT/0.2"


def _http_json(url: str, timeout: float = DEFAULT_TIMEOUT) -> tuple[int, Any]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_default_context()) as resp:
            status = getattr(resp, "status", 200)
            raw = resp.read(512 * 1024).decode("utf-8", errors="replace")
            try:
                return status, json.loads(raw)
            except ValueError:
                return status, None
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except Exception:
        return 0, None


def _check_github(u: str, timeout: float) -> Optional[dict[str, str]]:
    q = urllib.parse.quote(u, safe="")
    status, data = _http_json(f"https://api.github.com/users/{q}", timeout=timeout)
    if status == 200 and isinstance(data, dict) and data.get("login"):
        login = str(data["login"])
        url = str(data.get("html_url") or f"https://github.com/{login}")
        return {"service": "github.com", "url": url, "handle": login}
    return None


def _check_gitlab(u: str, timeout: float) -> Optional[dict[str, str]]:
    q = urllib.parse.quote(u, safe="")
    status, data = _http_json(f"https://gitlab.com/api/v4/users?username={q}", timeout=timeout)
    if status == 200 and isinstance(data, list) and data and isinstance(data[0], dict):
        uname = str(data[0].get("username") or u)
        url = str(data[0].get("web_url") or f"https://gitlab.com/{uname}")
        return {"service": "gitlab.com", "url": url, "handle": uname}
    return None


def _check_reddit(u: str, timeout: float) -> Optional[dict[str, str]]:
    q = urllib.parse.quote(u, safe="")
    status, data = _http_json(f"https://www.reddit.com/user/{q}/about.json", timeout=timeout)
    if status == 200 and isinstance(data, dict):
        inner = data.get("data")
        if isinstance(inner, dict) and inner.get("name") and not inner.get("is_suspended"):
            uname = str(inner["name"])
            return {"service": "reddit.com", "url": f"https://www.reddit.com/user/{uname}", "handle": uname}
    return None


def _check_hackernews(u: str, timeout: float) -> Optional[dict[str, str]]:
    q = urllib.parse.quote(u, safe="")
    status, data = _http_json(f"https://hacker-news.firebaseio.com/v0/user/{q}.json", timeout=timeout)
    if status == 200 and isinstance(data, dict) and data.get("id"):
        uid = str(data["id"])
        return {"service": "news.ycombinator.com", "url": f"https://news.ycombinator.com/user?id={uid}", "handle": uid}
    return None


def _check_keybase(u: str, timeout: float) -> Optional[dict[str, str]]:
    q = urllib.parse.quote(u, safe="")
    status, data = _http_json(
        f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={q}",
        timeout=timeout,
    )
    if status == 200 and isinstance(data, dict):
        them = data.get("them")
        if isinstance(them, list) and them and isinstance(them[0], dict):
            basics = them[0].get("basics") or {}
            if isinstance(basics, dict) and basics.get("username"):
                uname = str(basics["username"])
                return {"service": "keybase.io", "url": f"https://keybase.io/{uname}", "handle": uname}
    return None


def _check_chess(u: str, timeout: float) -> Optional[dict[str, str]]:
    q = urllib.parse.quote(u.lower(), safe="")
    status, data = _http_json(f"https://api.chess.com/pub/player/{q}", timeout=timeout)
    if status == 200 and isinstance(data, dict) and data.get("username"):
        uname = str(data["username"])
        url = str(data.get("url") or f"https://www.chess.com/member/{uname}")
        return {"service": "chess.com", "url": url, "handle": uname}
    return None


def _check_duolingo(u: str, timeout: float) -> Optional[dict[str, str]]:
    q = urllib.parse.quote(u, safe="")
    status, data = _http_json(
        f"https://www.duolingo.com/2017-06-30/users?username={q}",
        timeout=timeout,
    )
    if status == 200 and isinstance(data, dict):
        users = data.get("users")
        if isinstance(users, list) and users and isinstance(users[0], dict):
            uname = str(users[0].get("username") or u)
            return {"service": "duolingo.com", "url": f"https://www.duolingo.com/profile/{uname}", "handle": uname}
    return None


def _check_devto(u: str, timeout: float) -> Optional[dict[str, str]]:
    q = urllib.parse.quote(u, safe="")
    status, data = _http_json(f"https://dev.to/api/users/by_username?url={q}", timeout=timeout)
    if status == 200 and isinstance(data, dict) and data.get("username"):
        uname = str(data["username"])
        return {"service": "dev.to", "url": f"https://dev.to/{uname}", "handle": uname}
    return None


def _check_crates(u: str, timeout: float) -> Optional[dict[str, str]]:
    q = urllib.parse.quote(u, safe="")
    status, data = _http_json(f"https://crates.io/api/v1/users/{q}", timeout=timeout)
    if status == 200 and isinstance(data, dict) and isinstance(data.get("user"), dict):
        login = str(data["user"].get("login") or u)
        return {"service": "crates.io", "url": f"https://crates.io/users/{login}", "handle": login}
    return None


PLATFORM_CHECKS: tuple[tuple[str, Callable[[str, float], Optional[dict[str, str]]]], ...] = (
    ("github.com", _check_github),
    ("gitlab.com", _check_gitlab),
    ("reddit.com", _check_reddit),
    ("news.ycombinator.com", _check_hackernews),
    ("keybase.io", _check_keybase),
    ("chess.com", _check_chess),
    ("duolingo.com", _check_duolingo),
    ("dev.to", _check_devto),
    ("crates.io", _check_crates),
)


class UsernameOsintAdapter(BaseAdapter):
    """Built-in keyless multi-platform username presence scanner."""

    name: ClassVar[str] = "username-osint"
    tier: ClassVar[str] = "A"
    default_enabled: ClassVar[bool] = False
    collection_mode: ClassVar[str] = "third_party_passive"
    source_type: ClassVar[str] = "osint"
    description: ClassVar[str] = (
        "Keyless username OSINT across GitHub, GitLab, Reddit, HackerNews, Keybase, "
        "Chess.com, Duolingo, DEV Community, and Crates.io"
    )
    produces: ClassVar[frozenset[str]] = frozenset({"public.account"})
    accepts: ClassVar[frozenset[str]] = frozenset({"username"})
    retention_days: ClassVar[int] = 14
    timeout: ClassVar[float] = DEFAULT_TIMEOUT

    def search(self, request: Request) -> list[Reference]:
        subject = normalize_subject("username", request.value)
        return [
            Reference(
                url="osint://username-osint/" + urllib.parse.quote(subject, safe=""),
                origin_url="https://api.github.com/",
                label=subject,
            )
        ]

    def fetch(self, reference: Reference) -> RawResult:
        subject = normalize_subject("username", reference.label)
        found: list[dict[str, str]] = []
        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = {
                pool.submit(fn, subject, self.timeout): site_name
                for site_name, fn in PLATFORM_CHECKS
            }
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                    if res:
                        found.append(res)
                except Exception:
                    continue

        payload = {
            "subject": subject,
            "checked_platforms": [name for name, _ in PLATFORM_CHECKS],
            "matches": sorted(found, key=lambda item: item.get("service", "")),
        }
        return RawResult(
            payload=json.dumps(payload, sort_keys=True).encode("utf-8"),
            request_url=reference.url,
            origin_url=reference.origin_url,
            http_status=200,
            content_type="application/json",
            collected_at=datetime.now(timezone.utc),
        )

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        subject = normalize_subject("username", request.value)
        try:
            data = json.loads(raw.payload)
        except Exception as exc:
            raise AdapterError("Invalid username-osint payload") from exc
        if not isinstance(data, dict) or data.get("subject") != subject:
            raise AdapterError("username-osint payload does not match subject")

        matches = data.get("matches") or []
        facts: list[FactDraft] = []

        def add(attr: str, val: str, value_type: str = "str"):
            if val and str(val).strip():
                sval = str(val).strip()[:500]
                if attr == "public.account.url" and not sval.lower().startswith(("https://", "http://")):
                    return
                facts.append(
                    FactDraft(
                        attribute=attr,
                        value=sval,
                        value_type=value_type,
                        entity_kind="username",
                        entity_name=subject,
                        identity_key="username:" + subject,
                        sensitivity="personal",
                    )
                )

        add("public.account.summary.count", str(len(matches)), value_type="int")
        for m in matches:
            if not isinstance(m, dict):
                continue
            svc = m.get("service", "")
            url = m.get("url", "")
            if svc:
                add("public.account.found", svc)
            if url:
                add("public.account.url", url)

        return facts
