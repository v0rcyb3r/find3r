"""Native keyless Email OSINT, mail-server posture, PGP keyserver, and multi-platform account-presence adapter."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, ClassVar
import urllib.error
import urllib.parse
import urllib.request

from neesha.adapters.base import AdapterError, BaseAdapter, FactDraft, RawResult, Reference, Request
from neesha.adapters.dns_posture import SystemResolver
from neesha.adapters.email_public import normalize_email
from neesha.collectors.network import _default_context
from neesha.posture.parsers import parse_dmarc, parse_spf

FREEMAIL_PROVIDERS = {
    "gmail.com": "Gmail / Google",
    "googlemail.com": "Gmail / Google",
    "outlook.com": "Outlook / Microsoft",
    "hotmail.com": "Hotmail / Microsoft",
    "live.com": "Microsoft Live",
    "msn.com": "MSN / Microsoft",
    "yahoo.com": "Yahoo Mail",
    "ymail.com": "Yahoo Mail",
    "icloud.com": "Apple iCloud Mail",
    "me.com": "Apple iCloud Mail",
    "mac.com": "Apple iCloud Mail",
    "protonmail.com": "ProtonMail",
    "proton.me": "ProtonMail",
    "pm.me": "ProtonMail",
    "aol.com": "AOL Mail",
    "zoho.com": "Zoho Mail",
    "fastmail.com": "Fastmail",
    "gmx.com": "GMX Mail",
    "mail.com": "Mail.com",
}

ROLE_LOCAL_PARTS = frozenset({
    "admin", "administrator", "billing", "compliance", "contact", "help",
    "hr", "info", "it", "legal", "mail", "marketing", "noc", "office",
    "ops", "postmaster", "press", "privacy", "root", "sales", "security",
    "soc", "support", "team", "webmaster",
})


class EmailOsintAdapter(BaseAdapter):
    name: ClassVar[str] = "email-osint"
    tier: ClassVar[str] = "A"
    default_enabled: ClassVar[bool] = False
    collection_mode: ClassVar[str] = "third_party_passive"
    source_type: ClassVar[str] = "osint"
    description: ClassVar[str] = (
        "Keyless email OSINT: MX/SPF/DMARC deliverability, OpenPGP keyservers, "
        "exact-email account presence (Firefox, WordPress, Duolingo, Spotify, Gravatar, GitHub, GitLab), "
        "and handle correlation"
    )
    produces: ClassVar[frozenset[str]] = frozenset({
        "public.email",
        "public.account",
        "public.profile",
    })
    accepts: ClassVar[frozenset[str]] = frozenset({"email"})
    retention_days: ClassVar[int] = 14
    timeout: ClassVar[int] = 8

    def search(self, request: Request) -> list[Reference]:
        email = normalize_email(request.value)
        return [
            Reference(
                url="osint://email-osint/" + urllib.parse.quote(email, safe="@"),
                origin_url="https://keys.openpgp.org/",
                label=email,
            )
        ]

    def _http_json(self, url: str, headers: dict[str, str] | None = None) -> tuple[int, Any]:
        req_headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) NEESHA-OSINT/0.2",
            "Accept": "application/json",
        }
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, headers=req_headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=_default_context()) as resp:
                raw = resp.read(512 * 1024)
                return resp.status, json.loads(raw.decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(128 * 1024)
                return exc.code, json.loads(body.decode("utf-8", errors="replace"))
            except Exception:
                return exc.code, None
        except Exception:
            return 0, None

    def _http_text(self, url: str) -> tuple[int, str]:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) NEESHA-OSINT/0.2"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=_default_context()) as resp:
                raw = resp.read(256 * 1024)
                return resp.status, raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, ""
        except Exception:
            return 0, ""

    def _check_dns(self, domain: str) -> dict[str, Any]:
        resolver = SystemResolver(timeout=4.0)
        mx_res = resolver.query(domain, "MX")
        txt_res = resolver.query(domain, "TXT")
        dmarc_res = resolver.query("_dmarc." + domain, "TXT")

        mx_hosts = []
        if mx_res.status == "ok":
            for r in mx_res.records:
                parts = r.value.strip().split()
                host = parts[-1].rstrip(".").lower() if parts else ""
                if host:
                    mx_hosts.append(host)

        spf_qual = "absent"
        if txt_res.status == "ok":
            spf_candidates = [r.value for r in txt_res.records if r.value.lower().startswith("v=spf1")]
            if spf_candidates:
                spf_qual = parse_spf(spf_candidates).qualifier

        dmarc_pol = "absent"
        if dmarc_res.status == "ok":
            dmarc_candidates = [r.value for r in dmarc_res.records if r.value.lower().startswith("v=dmarc1")]
            if dmarc_candidates:
                dmarc_pol = parse_dmarc(dmarc_candidates).policy

        return {
            "mx_hosts": sorted(set(mx_hosts))[:10],
            "spf_qualifier": spf_qual,
            "dmarc_policy": dmarc_pol,
        }

    def _probe_firefox(self, email: str) -> dict[str, Any]:
        q = urllib.parse.quote(email, safe="")
        status, data = self._http_json(f"https://api.accounts.firefox.com/v1/account/status?email={q}")
        if status == 200 and isinstance(data, dict):
            return {"service": "firefox.com", "checked": True, "found": bool(data.get("exists"))}
        return {"service": "firefox.com", "checked": False, "found": False}

    def _probe_wordpress(self, email: str) -> dict[str, Any]:
        q = urllib.parse.quote(email, safe="")
        status, data = self._http_json(f"https://public-api.wordpress.com/rest/v1.1/users/{q}/auth-options")
        if status == 200 and isinstance(data, dict):
            return {"service": "wordpress.com", "checked": True, "found": True}
        if status == 404:
            return {"service": "wordpress.com", "checked": True, "found": False}
        return {"service": "wordpress.com", "checked": False, "found": False}

    def _probe_duolingo(self, email: str) -> dict[str, Any]:
        q = urllib.parse.quote(email, safe="")
        status, data = self._http_json(f"https://www.duolingo.com/2017-06-30/users?email={q}")
        if status == 200 and isinstance(data, dict) and isinstance(data.get("users"), list):
            users = data["users"]
            if users and isinstance(users[0], dict):
                uname = users[0].get("username")
                url = f"https://www.duolingo.com/profile/{uname}" if uname else "https://www.duolingo.com/"
                return {"service": "duolingo.com", "checked": True, "found": True, "url": url, "username": uname}
            return {"service": "duolingo.com", "checked": True, "found": False}
        return {"service": "duolingo.com", "checked": False, "found": False}

    def _probe_spotify(self, email: str) -> dict[str, Any]:
        q = urllib.parse.quote(email, safe="")
        status, data = self._http_json(f"https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={q}")
        if status == 200 and isinstance(data, dict) and "status" in data:
            # Spotify status 20 = email already registered; status 1 = available
            return {"service": "spotify.com", "checked": True, "found": data.get("status") == 20}
        return {"service": "spotify.com", "checked": False, "found": False}

    def _probe_gravatar_md5(self, email: str) -> dict[str, Any]:
        md5_hash = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
        status, data = self._http_json(f"https://en.gravatar.com/{md5_hash}.json")
        if status == 200 and isinstance(data, dict) and isinstance(data.get("entry"), list) and data["entry"]:
            entry = data["entry"][0]
            return {
                "service": "gravatar.com",
                "checked": True,
                "found": True,
                "url": entry.get("profileUrl") or f"https://gravatar.com/{md5_hash}",
                "display_name": entry.get("displayName") or entry.get("preferredUsername"),
                "location": entry.get("currentLocation"),
                "about": entry.get("aboutMe"),
                "accounts": [
                    a.get("url") for a in (entry.get("accounts") or [])
                    if isinstance(a, dict) and isinstance(a.get("url"), str)
                ][:10],
            }
        if status == 404:
            return {"service": "gravatar.com", "checked": True, "found": False}
        return {"service": "gravatar.com", "checked": False, "found": False}

    def _probe_openpgp(self, email: str) -> dict[str, Any]:
        q = urllib.parse.quote(email, safe="")
        status, text = self._http_text(
            f"https://keyserver.ubuntu.com/pks/lookup?search={q}&op=index&options=mr"
        )
        if status == 200 and "pub:" in text:
            for line in text.splitlines():
                if line.startswith("pub:"):
                    parts = line.split(":")
                    key_id = parts[1] if len(parts) > 1 else ""
                    return {
                        "service": "openpgp-keyserver",
                        "checked": True,
                        "found": True,
                        "key_id": key_id,
                        "url": f"https://keyserver.ubuntu.com/pks/lookup?search={q}&op=vindex",
                    }
        if status in (200, 404):
            return {"service": "openpgp-keyserver", "checked": True, "found": False}
        return {"service": "openpgp-keyserver", "checked": False, "found": False}

    def _probe_gitlab_email(self, email: str) -> dict[str, Any]:
        q = urllib.parse.quote(email, safe="")
        status, data = self._http_json(f"https://gitlab.com/api/v4/users?search={q}")
        if status == 200 and isinstance(data, list):
            if data and isinstance(data[0], dict):
                u = data[0]
                return {
                    "service": "gitlab.com",
                    "checked": True,
                    "found": True,
                    "url": u.get("web_url") or f"https://gitlab.com/{u.get('username', '')}",
                    "username": u.get("username"),
                }
            return {"service": "gitlab.com", "checked": True, "found": False}
        return {"service": "gitlab.com", "checked": False, "found": False}

    def _probe_github_user_search(self, email: str) -> dict[str, Any]:
        q = urllib.parse.quote(f"{email} in:email", safe="")
        status, data = self._http_json(
            f"https://api.github.com/search/users?q={q}&per_page=3",
            headers={"Accept": "application/vnd.github+json"},
        )
        if status == 200 and isinstance(data, dict) and isinstance(data.get("items"), list):
            items = data["items"]
            if items and isinstance(items[0], dict):
                u = items[0]
                return {
                    "service": "github.com",
                    "checked": True,
                    "found": True,
                    "url": u.get("html_url") or f"https://github.com/{u.get('login', '')}",
                    "username": u.get("login"),
                }
            return {"service": "github.com", "checked": True, "found": False}
        return {"service": "github.com", "checked": False, "found": False}

    def _probe_xposedornot(self, email: str) -> dict[str, Any]:
        q = urllib.parse.quote(email, safe="")
        status, data = self._http_json(f"https://api.xposedornot.com/v1/check-email/{q}")
        if status == 200 and isinstance(data, dict):
            raw_breaches = data.get("breaches")
            breaches: list[str] = []
            if isinstance(raw_breaches, list):
                for entry in raw_breaches:
                    if isinstance(entry, list):
                        breaches.extend(str(b) for b in entry if b)
                    elif isinstance(entry, str) and entry:
                        breaches.append(entry)
            if breaches:
                return {
                    "service": "xposedornot.com",
                    "checked": True,
                    "found": True,
                    "breaches": breaches[:25],
                }
            return {"service": "xposedornot.com", "checked": True, "found": False}
        if status == 404:
            return {"service": "xposedornot.com", "checked": True, "found": False}
        return {"service": "xposedornot.com", "checked": False, "found": False}

    def _probe_handle(self, handle: str) -> list[dict[str, str]]:
        """Check whether the email's local-part handle exists on public developer/social platforms."""
        if len(handle) < 4 or handle.lower() in ROLE_LOCAL_PARTS or not re.fullmatch(r"[a-zA-Z0-9._-]{4,39}", handle):
            return []
        clean = handle.split("+")[0].replace(".", "") if len(handle.split("+")[0]) >= 4 else handle
        candidates = list(dict.fromkeys([handle.split("+")[0], clean]))[:1]
        h = candidates[0]
        q = urllib.parse.quote(h, safe="")
        matches: list[dict[str, str]] = []

        # GitHub user
        st, gh = self._http_json(f"https://api.github.com/users/{q}")
        if st == 200 and isinstance(gh, dict) and gh.get("html_url"):
            matches.append({"platform": "github.com", "handle": h, "url": gh["html_url"], "name": gh.get("name") or ""})

        # Reddit user
        st, rd = self._http_json(f"https://www.reddit.com/user/{q}/about.json")
        if st == 200 and isinstance(rd, dict) and isinstance(rd.get("data"), dict) and not rd["data"].get("is_suspended"):
            matches.append({"platform": "reddit.com", "handle": h, "url": f"https://www.reddit.com/user/{h}"})

        # HackerNews user
        st, hn = self._http_json(f"https://hacker-news.firebaseio.com/v0/user/{q}.json")
        if st == 200 and isinstance(hn, dict) and hn.get("id"):
            matches.append({"platform": "news.ycombinator.com", "handle": h, "url": f"https://news.ycombinator.com/user?id={h}"})

        # Keybase user
        st, kb = self._http_json(f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={q}")
        if st == 200 and isinstance(kb, dict) and isinstance(kb.get("them"), list) and kb["them"] and kb["them"][0]:
            matches.append({"platform": "keybase.io", "handle": h, "url": f"https://keybase.io/{h}"})

        return matches

    def fetch(self, reference: Reference) -> RawResult:
        email = normalize_email(reference.label)
        local_part, domain = email.rsplit("@", 1)
        base_local = local_part.split("+", 1)[0]

        with ThreadPoolExecutor(max_workers=10) as pool:
            f_dns = pool.submit(self._check_dns, domain)
            f_ff = pool.submit(self._probe_firefox, email)
            f_wp = pool.submit(self._probe_wordpress, email)
            f_duo = pool.submit(self._probe_duolingo, email)
            f_sp = pool.submit(self._probe_spotify, email)
            f_grav = pool.submit(self._probe_gravatar_md5, email)
            f_pgp = pool.submit(self._probe_openpgp, email)
            f_gl = pool.submit(self._probe_gitlab_email, email)
            f_gh = pool.submit(self._probe_github_user_search, email)
            f_xon = pool.submit(self._probe_xposedornot, email)
            f_handle = pool.submit(self._probe_handle, base_local)

            dns_info = f_dns.result()
            probes = [
                f_ff.result(),
                f_wp.result(),
                f_duo.result(),
                f_sp.result(),
                f_grav.result(),
                f_pgp.result(),
                f_gl.result(),
                f_gh.result(),
                f_xon.result(),
            ]
            handle_matches = f_handle.result()

        payload = {
            "email": email,
            "local_part": local_part,
            "base_local": base_local,
            "domain": domain,
            "dns": dns_info,
            "probes": probes,
            "handle_matches": handle_matches,
        }
        return RawResult(
            payload=json.dumps(payload).encode("utf-8"),
            request_url=reference.url,
            origin_url=reference.origin_url,
            http_status=200,
            content_type="application/json",
            collected_at=datetime.now(timezone.utc),
        )

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        try:
            data = json.loads(raw.payload)
        except Exception as exc:
            raise AdapterError("Invalid email-osint payload") from exc
        if not isinstance(data, dict):
            raise AdapterError("Unexpected email-osint payload")

        email = normalize_email(request.value)
        local_part, domain = email.rsplit("@", 1)
        base_local = local_part.split("+", 1)[0]

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
                        entity_kind="email",
                        entity_name=email,
                        identity_key="email:" + email,
                        sensitivity="personal",
                    )
                )

        # 1. Syntax, handle, and mail provider classification
        add("public.email.syntax", "valid")
        add("public.email.local_part", base_local)
        inbox_type = "role_account" if base_local.lower() in ROLE_LOCAL_PARTS else "individual_mailbox"
        add("public.email.mailbox_type", inbox_type)

        provider = FREEMAIL_PROVIDERS.get(domain.lower(), f"Custom / Corporate Domain ({domain})")
        add("public.email.provider", provider)

        # 2. Mail server MX / SPF / DMARC deliverability
        dns_info = data.get("dns") or {}
        mx_hosts = dns_info.get("mx_hosts") or []
        add("public.email.deliverable_mx", "true" if mx_hosts else "false", value_type="bool")
        for mx in mx_hosts[:5]:
            add("public.email.mx_host", mx)
        if dns_info.get("spf_qualifier"):
            add("public.email.domain_spf", dns_info["spf_qualifier"])
        if dns_info.get("dmarc_policy"):
            add("public.email.domain_dmarc", dns_info["dmarc_policy"])

        # 3. Exact-email service probes
        probes = data.get("probes") or []
        checked_services = []
        found_services = []
        for p in probes:
            if not isinstance(p, dict):
                continue
            svc = p.get("service", "")
            if p.get("checked"):
                checked_services.append(svc)
            if p.get("found"):
                found_services.append(svc)
                add("public.account.found", svc)
                if p.get("url"):
                    add("public.account.url", p["url"])
                if p.get("display_name"):
                    add("public.profile.gravatar.display_name", p["display_name"])
                if p.get("location"):
                    add("public.profile.gravatar.location", p["location"])
                if p.get("about"):
                    add("public.profile.gravatar.bio", p["about"])
                if p.get("key_id"):
                    add("public.email.pgp_key", p["key_id"])
                for breach_name in p.get("breaches") or []:
                    add("public.email.breach_exposure", str(breach_name))
                for acct_url in p.get("accounts") or []:
                    add("public.account.url", acct_url)

        add("public.account.summary.count", str(len(found_services)), value_type="int")
        if checked_services:
            add("public.email.checked_services", ", ".join(sorted(checked_services)))

        # 4. Handle / username correlation across public platforms
        for hm in data.get("handle_matches") or []:
            if isinstance(hm, dict) and hm.get("platform") and hm.get("url"):
                label = f"{hm['platform']} ({hm.get('handle', base_local)})"
                if hm.get("name"):
                    label += f" — {hm['name']}"
                add("public.email.handle_correlation", label)
                add("public.account.url", hm["url"])

        return facts
