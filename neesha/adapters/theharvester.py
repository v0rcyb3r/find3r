"""Passive domain & email discovery via theHarvester."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import ClassVar
from urllib.parse import quote

from neesha.adapters.base import AdapterError, BaseAdapter, FactDraft, RawResult, Reference, Request
from neesha.adapters.tool_installer import ensure_tool_paths_in_env

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MAX_JSON_BYTES = 4 * 1024 * 1024


def _domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise AdapterError("theHarvester requires a valid company domain")
    return domain


class TheHarvesterAdapter(BaseAdapter):
    name: ClassVar[str] = "theHarvester"
    tier: ClassVar[str] = "A"
    default_enabled: ClassVar[bool] = False
    collection_mode: ClassVar[str] = "third_party_passive"
    source_type: ClassVar[str] = "osint_aggregate"
    description: ClassVar[str] = "Passive domain, subdomain & email harvesting via theHarvester"
    produces: ClassVar[frozenset[str]] = frozenset({"discovery.subdomain", "company.business_email"})
    accepts: ClassVar[frozenset[str]] = frozenset({"company", "domain"})
    retention_days: ClassVar[int] = 7
    timeout: ClassVar[int] = 60

    @staticmethod
    def binary() -> str | None:
        ensure_tool_paths_in_env()
        return shutil.which("theHarvester")

    def availability(self) -> dict:
        if not self.binary():
            return {"available": False, "reason": "theHarvester is not installed. Click Install to set it up."}
        return {"available": True, "reason": "theHarvester is installed and ready for passive OSINT."}

    def search(self, request: Request) -> list[Reference]:
        domain = _domain(request.value)
        return [
            Reference(
                url="tool://theHarvester/" + quote(domain, safe=""),
                origin_url="tool://theHarvester/",
                label=domain,
            )
        ]

    def fetch(self, reference: Reference) -> RawResult:
        status = self.availability()
        if not status["available"]:
            raise AdapterError(status["reason"])
        domain = _domain(reference.label)
        base = PROJECT_ROOT / ".tools" / "theHarvester"
        base.mkdir(parents=True, exist_ok=True)
        ensure_tool_paths_in_env()
        env = {
            k: v
            for k, v in os.environ.items()
            if k in ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT", "SSL_CERT_FILE", "SSL_CERT_DIR")
        }
        with tempfile.TemporaryDirectory(dir=base) as tmp:
            try:
                os.chmod(tmp, 0o700)
            except OSError:
                pass
            out_prefix = Path(tmp) / "harvest"
            args = [
                self.binary(),
                "-d",
                domain,
                "-b",
                "crtsh,rapiddns,urlscan,otx,hackertarget",
                "-f",
                str(out_prefix),
            ]
            try:
                subprocess.run(
                    args,
                    cwd=tmp,
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=self.timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise AdapterError("theHarvester reached its collection time limit") from exc
            except OSError as exc:
                raise AdapterError("theHarvester could not run") from exc

            json_file = Path(str(out_prefix) + ".json")
            data = {"hosts": [], "emails": []}
            if json_file.is_file():
                try:
                    if json_file.stat().st_size <= MAX_JSON_BYTES:
                        parsed = json.loads(json_file.read_text(encoding="utf-8", errors="replace"))
                        if isinstance(parsed, dict):
                            data["hosts"] = [str(h) for h in (parsed.get("hosts") or []) if isinstance(h, str)][:500]
                            data["emails"] = [str(e) for e in (parsed.get("emails") or []) if isinstance(e, str)][:200]
                except Exception:
                    pass

        return RawResult(
            payload=json.dumps(data).encode("utf-8"),
            request_url=reference.url,
            origin_url=reference.origin_url,
            content_type="application/json",
            collected_at=datetime.now(timezone.utc),
        )

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        domain = _domain(request.value)
        try:
            data = json.loads(raw.payload)
        except Exception as exc:
            raise AdapterError("Invalid theHarvester output") from exc
        if not isinstance(data, dict):
            return []

        facts: list[FactDraft] = []
        hosts: set[str] = set()
        for raw_host in data.get("hosts") or []:
            if not isinstance(raw_host, str):
                continue
            host = raw_host.split(":", 1)[0].strip().lower().rstrip(".")
            if host and host != domain and host.endswith("." + domain):
                if all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", lbl) for lbl in host.split(".")):
                    hosts.add(host)

        for h in sorted(hosts):
            facts.append(
                FactDraft(
                    attribute="discovery.subdomain",
                    value=h,
                    entity_kind="domain",
                    entity_name=domain,
                    value_type="domain",
                )
            )

        emails: set[str] = set()
        for raw_email in data.get("emails") or []:
            if isinstance(raw_email, str) and "@" in raw_email:
                em = raw_email.strip().lower()
                if em.endswith("@" + domain) or em.endswith("." + domain):
                    emails.add(em)
        for em in sorted(emails)[:100]:
            facts.append(
                FactDraft(
                    attribute="company.business_email",
                    value=em,
                    entity_kind="domain",
                    entity_name=domain,
                    sensitivity="business",
                )
            )
        return facts
