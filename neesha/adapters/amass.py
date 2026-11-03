"""Passive Amass subdomain discovery wrapper."""
from __future__ import annotations

import os
import re
import selectors
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar
from urllib.parse import quote

from neesha.adapters.base import AdapterError, BaseAdapter, FactDraft, RawResult, Reference, Request

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise AdapterError("Amass requires a valid company domain")
    return domain


class AmassAdapter(BaseAdapter):
    name: ClassVar[str] = "amass"
    tier: ClassVar[str] = "A"
    default_enabled: ClassVar[bool] = False
    collection_mode: ClassVar[str] = "third_party_passive"
    source_type: ClassVar[str] = "osint_aggregate"
    description: ClassVar[str] = "OWASP Amass passive subdomain enumeration"
    produces: ClassVar[frozenset[str]] = frozenset({"discovery.subdomain"})
    accepts: ClassVar[frozenset[str]] = frozenset({"company", "domain"})
    max_output_bytes: ClassVar[int] = 4 * 1024 * 1024
    max_results: ClassVar[int] = 1000
    timeout: ClassVar[int] = 45
    retention_days: ClassVar[int] = 7

    @staticmethod
    def binary() -> str | None:
        from neesha.adapters.tool_installer import ensure_tool_paths_in_env
        ensure_tool_paths_in_env()
        return shutil.which("amass")

    def availability(self) -> dict:
        if not self.binary():
            return {"available": False, "reason": "Amass is not installed."}
        return {"available": True, "reason": "Installed and ready for passive subdomain enumeration."}

    def search(self, request: Request) -> list[Reference]:
        domain = _domain(request.value)
        return [Reference(url="tool://amass/" + quote(domain, safe=""), origin_url="tool://amass/", label=domain)]

    def fetch(self, reference: Reference) -> RawResult:
        status = self.availability()
        if not status["available"]:
            raise AdapterError(status["reason"])
        domain = _domain(reference.label)
        work_dir = PROJECT_ROOT / ".tools" / "amass"
        work_dir.mkdir(parents=True, exist_ok=True)
        env = {
            k: v
            for k, v in os.environ.items()
            if k in ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT", "SSL_CERT_FILE", "SSL_CERT_DIR")
        }
        args = [self.binary(), "enum", "-passive", "-norecursive", "-noalts", "-timeout", "1", "-d", domain]
        try:
            with tempfile.TemporaryFile(dir=work_dir) as output:
                self._execute(args, env, output)
                output.seek(0)
                payload = output.read(self.max_output_bytes + 1)
        except AdapterError:
            raise
        except (OSError, ValueError) as exc:
            raise AdapterError("Amass could not run") from exc
        return RawResult(
            payload=payload,
            request_url=reference.url,
            origin_url=reference.origin_url,
            content_type="text/plain",
            collected_at=datetime.now(timezone.utc),
        )

    def _execute(self, args, env, output):
        process = subprocess.Popen(
            args, cwd=PROJECT_ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True
        )
        total = 0
        deadline = time.monotonic() + self.timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise AdapterError("Amass reached its collection time limit")
                    for key, _ in selector.select(min(remaining, 0.2)):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > self.max_output_bytes:
                            raise AdapterError("Amass output exceeds size limit")
                        output.write(chunk)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            if process.stdout:
                process.stdout.close()

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        domain = _domain(request.value)
        hosts = set()
        for line in raw.payload.decode("utf-8", errors="replace").splitlines()[: self.max_results]:
            token = line.strip().split()[0].lower().rstrip(".") if line.strip() else ""
            if token and token != domain and token.endswith("." + domain):
                if all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in token.split(".")):
                    hosts.add(token)
        return [
            FactDraft(attribute="discovery.subdomain", value=h, entity_kind="domain", entity_name=domain, value_type="domain")
            for h in sorted(hosts)
        ]
