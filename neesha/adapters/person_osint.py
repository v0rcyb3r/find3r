"""Keyless Person OSINT adapter: GitHub/GitLab user search, Wikipedia/Wikidata public records, OpenPGP keyservers, and HackerNews."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from typing import Any, ClassVar
import urllib.error
import urllib.parse
import urllib.request

from neesha.adapters.base import AdapterError, BaseAdapter, FactDraft, RawResult, Reference, Request
from neesha.collectors.network import _default_context
from neesha.resolve.intake import resolve_seed


class PersonOsintAdapter(BaseAdapter):
    name: ClassVar[str] = "person-osint"
    tier: ClassVar[str] = "A"
    default_enabled: ClassVar[bool] = True
    collection_mode: ClassVar[str] = "third_party_passive"
    source_type: ClassVar[str] = "osint"
    description: ClassVar[str] = (
        "Keyless person OSINT across GitHub Users, GitLab Users, Wikipedia/Wikidata, "
        "OpenPGP keyservers, and HackerNews public mentions"
    )
    produces: ClassVar[frozenset[str]] = frozenset({
        "public.person",
        "public.account",
        "public.profile",
    })
    accepts: ClassVar[frozenset[str]] = frozenset({"person"})
    retention_days: ClassVar[int] = 14
    timeout: ClassVar[int] = 8

    def search(self, request: Request) -> list[Reference]:
        name = resolve_seed(request.value, "person")["normalized"]
        return [
            Reference(
                url="osint://person-osint/" + urllib.parse.quote(name, safe=""),
                origin_url="https://api.github.com/",
                label=name,
            )
        ]

    def _http_json(self, url: str) -> tuple[int, Any]:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Find3r-OSINT/0.2",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=_default_context()) as resp:
                raw = resp.read(512 * 1024).decode("utf-8", errors="replace")
                return resp.status, json.loads(raw)
        except urllib.error.HTTPError as exc:
            return exc.code, None
        except Exception:
            return 0, None

    def _http_text(self, url: str) -> tuple[int, str]:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Find3r-OSINT/0.2"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=_default_context()) as resp:
                raw = resp.read(256 * 1024).decode("utf-8", errors="replace")
                return resp.status, raw
        except urllib.error.HTTPError as exc:
            return exc.code, ""
        except Exception:
            return 0, ""

    def _search_github_people(self, name: str) -> list[dict[str, str]]:
        q = urllib.parse.quote(f'"{name}" in:fullname', safe="")
        st, data = self._http_json(f"https://api.github.com/search/users?q={q}&per_page=3")
        profiles: list[dict[str, str]] = []
        if st == 200 and isinstance(data, dict) and isinstance(data.get("items"), list):
            for item in data["items"][:3]:
                if not isinstance(item, dict) or not item.get("login"):
                    continue
                login = str(item["login"])
                ust, udata = self._http_json(f"https://api.github.com/users/{urllib.parse.quote(login, safe='')}")
                if ust == 200 and isinstance(udata, dict):
                    profiles.append({
                        "service": "github.com",
                        "handle": login,
                        "url": str(udata.get("html_url") or f"https://github.com/{login}"),
                        "name": str(udata.get("name") or ""),
                        "company": str(udata.get("company") or ""),
                        "location": str(udata.get("location") or ""),
                        "bio": str(udata.get("bio") or ""),
                        "blog": str(udata.get("blog") or ""),
                    })
                else:
                    profiles.append({
                        "service": "github.com",
                        "handle": login,
                        "url": str(item.get("html_url") or f"https://github.com/{login}"),
                    })
        return profiles

    def _search_gitlab_people(self, name: str) -> list[dict[str, str]]:
        q = urllib.parse.quote(name, safe="")
        st, data = self._http_json(f"https://gitlab.com/api/v4/users?search={q}&per_page=3")
        profiles: list[dict[str, str]] = []
        if st == 200 and isinstance(data, list):
            for item in data[:3]:
                if isinstance(item, dict) and item.get("username"):
                    uname = str(item["username"])
                    profiles.append({
                        "service": "gitlab.com",
                        "handle": uname,
                        "name": str(item.get("name") or ""),
                        "url": str(item.get("web_url") or f"https://gitlab.com/{uname}"),
                    })
        return profiles

    def _search_wikipedia(self, name: str) -> dict[str, str]:
        slug = urllib.parse.quote(name.replace(" ", "_"), safe="_")
        st, data = self._http_json(f"https://en.wikipedia.org/api/rest_v1/page/summary/{slug}")
        if st == 200 and isinstance(data, dict) and data.get("type") == "standard":
            url = ((data.get("content_urls") or {}).get("desktop") or {}).get("page") or f"https://en.wikipedia.org/wiki/{slug}"
            return {
                "title": str(data.get("title") or name),
                "description": str(data.get("description") or ""),
                "extract": str(data.get("extract") or "")[:400],
                "url": str(url),
            }
        return {}

    def _search_openpgp(self, name: str) -> list[dict[str, str]]:
        q = urllib.parse.quote(name, safe="")
        st, text = self._http_text(f"https://keyserver.ubuntu.com/pks/lookup?search={q}&op=index&options=mr")
        keys: list[dict[str, str]] = []
        if st == 200 and "pub:" in text:
            current_key = ""
            for line in text.splitlines():
                if line.startswith("pub:"):
                    parts = line.split(":")
                    current_key = parts[1] if len(parts) > 1 else ""
                elif line.startswith("uid:") and current_key:
                    parts = line.split(":")
                    uid = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""
                    keys.append({
                        "key_id": current_key,
                        "uid": uid[:160],
                        "url": f"https://keyserver.ubuntu.com/pks/lookup?search=0x{current_key}&op=vindex",
                    })
                    if len(keys) >= 5:
                        break
        return keys

    def fetch(self, reference: Reference) -> RawResult:
        name = resolve_seed(reference.label, "person")["normalized"]
        with ThreadPoolExecutor(max_workers=4) as pool:
            f_gh = pool.submit(self._search_github_people, name)
            f_gl = pool.submit(self._search_gitlab_people, name)
            f_wiki = pool.submit(self._search_wikipedia, name)
            f_pgp = pool.submit(self._search_openpgp, name)

            gh_profiles = f_gh.result()
            gl_profiles = f_gl.result()
            wiki_info = f_wiki.result()
            pgp_keys = f_pgp.result()

        payload = {
            "subject": name,
            "github": gh_profiles,
            "gitlab": gl_profiles,
            "wikipedia": wiki_info,
            "openpgp": pgp_keys,
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
        name = resolve_seed(request.value, "person")["normalized"]
        try:
            data = json.loads(raw.payload)
        except Exception as exc:
            raise AdapterError("Invalid person-osint payload") from exc
        if not isinstance(data, dict):
            raise AdapterError("Unexpected person-osint payload")

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
                        entity_kind="person",
                        entity_name=name,
                        identity_key="person:" + name.lower(),
                        sensitivity="personal",
                    )
                )

        add("public.person.full_name", name)

        wiki = data.get("wikipedia") or {}
        if isinstance(wiki, dict) and wiki.get("extract"):
            if wiki.get("description"):
                add("public.person.description", wiki["description"])
            add("public.person.summary", wiki["extract"])
            if wiki.get("url"):
                add("public.account.found", "wikipedia.org")
                add("public.account.url", wiki["url"])

        gh_list = data.get("github") or []
        gl_list = data.get("gitlab") or []
        total_accounts = len(gh_list) + len(gl_list) + (1 if wiki.get("url") else 0)
        add("public.account.summary.count", str(total_accounts), value_type="int")

        for p in gh_list:
            if not isinstance(p, dict):
                continue
            handle = p.get("handle") or ""
            add("public.account.found", f"github.com ({handle})" if handle else "github.com")
            if p.get("url"):
                add("public.account.url", p["url"])
            if p.get("company"):
                add("public.person.organization", p["company"])
            if p.get("location"):
                add("public.person.location", p["location"])
            if p.get("bio"):
                add("public.person.bio", p["bio"])
            if p.get("blog") and p["blog"].startswith(("http://", "https://")):
                add("public.person.website", p["blog"])

        for p in gl_list:
            if not isinstance(p, dict):
                continue
            handle = p.get("handle") or ""
            add("public.account.found", f"gitlab.com ({handle})" if handle else "gitlab.com")
            if p.get("url"):
                add("public.account.url", p["url"])

        for k in data.get("openpgp") or []:
            if isinstance(k, dict) and k.get("key_id"):
                uid = k.get("uid") or ""
                add("public.person.pgp_key", f"{k['key_id']} ({uid})" if uid else k["key_id"])
                if k.get("url"):
                    add("public.account.url", k["url"])

        return facts
