"""Shared base for account-enumeration tools (Holehe, Socialscan, …).

These tools check, service by service, whether an account exists for an exact
identifier by interacting with third-party sign-up and recovery endpoints.
That enumerates an individual's personal footprint, so every such adapter is:

- **Tier C** — never automatic, gated to a ``client_engagement`` whose scope
  authorizes the exact subject and lists the ``account_enumeration`` technique,
  with per-step analyst approval. Operator self-authorization (prospect /
  public research) never reaches these.
- **Aggregate only** — the raw tool output can carry partially-obscured
  recovery emails and phone fragments. Those never leave ``fetch``: only the
  per-service *existence* booleans and a count are kept, so the cache, the
  source record and any export hold no recovery hints or record contents.
- **Bounded and isolated** — the binary runs with a stripped environment, no
  shell, no inherited provider credentials, capped output and a wall-clock
  deadline, exactly like the Subfinder runner.

A found account is sensitivity ``personal`` and lives under ``public.account.*``;
it is an observation that an account exists, not proof of identity, ownership,
or current control of that account.
"""
from __future__ import annotations

import json
import os
import selectors
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar
from urllib.parse import quote

from neesha.adapters.base import AdapterError, BaseAdapter, Cost, FactDraft, RawResult, Reference, Request
from neesha.adapters.email_public import normalize_email

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ACCOUNT_ENUMERATION = "account_enumeration"


class AccountEnumAdapter(BaseAdapter):
    """Base for a gated, aggregate-only account-enumeration tool runner."""

    tier: ClassVar[str] = "C"
    collection_mode: ClassVar[str] = "third_party_passive"
    source_type: ClassVar[str] = "osint"
    default_enabled: ClassVar[bool] = False
    requires_techniques: ClassVar[frozenset[str]] = frozenset({ACCOUNT_ENUMERATION})
    accepts: ClassVar[frozenset[str]] = frozenset({"email"})
    retention_days: ClassVar[int] = 7

    binary_name: ClassVar[str] = ""
    max_services: ClassVar[int] = 200
    max_output_bytes: ClassVar[int] = 4 * 1024 * 1024
    timeout: ClassVar[int] = 120

    def estimate_cost(self, request: Request) -> Cost:
        return Cost()

    @classmethod
    def binary(cls) -> str | None:
        return shutil.which(cls.binary_name)

    def availability(self) -> dict:
        if not self.binary():
            return {"available": False,
                    "reason": f"{self.binary_name} is not installed; this account-enumeration tool is unavailable."}
        return {"available": True,
                "reason": ("Account-enumeration tool: requires a client engagement authorizing the exact "
                           "subject, the account_enumeration technique, analyst approval, and budget.")}

    def search(self, request: Request) -> list[Reference]:
        subject = normalize_email(request.value)
        return [Reference(url=f"tool://{self.name}/" + quote(subject, safe=""),
                          origin_url=f"tool://{self.name}/", label=subject)]

    # ---- subprocess, hardened like the Subfinder runner ------------------

    def _run(self, args: list[str], work_dir: Path) -> bytes:
        status = self.availability()
        if not status["available"]:
            raise AdapterError(status["reason"])
        # Preserve only process necessities; never pass ambient provider keys.
        env = {k: v for k, v in os.environ.items() if k in (
            "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT",
            "SSL_CERT_FILE", "SSL_CERT_DIR",
        )}
        try:
            with tempfile.TemporaryFile(dir=work_dir) as output:
                self._drain(args, env, output)
                output.seek(0)
                return output.read(self.max_output_bytes + 1)
        except AdapterError:
            raise
        except (OSError, ValueError) as exc:
            raise AdapterError(f"{self.name} could not run; inspect the local tool installation") from exc

    def _drain(self, args, env, output) -> None:
        process = subprocess.Popen(
            args, cwd=env.get("HOME", str(PROJECT_ROOT)), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
        )
        total = 0
        deadline = time.monotonic() + self.timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise AdapterError(f"{self.name} reached its collection time limit")
                    for key, _ in selector.select(min(remaining, 0.2)):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > self.max_output_bytes:
                            raise AdapterError(f"{self.name} output exceeds the collection size limit")
                        output.write(chunk)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AdapterError(f"{self.name} reached its collection time limit")
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired as exc:
                    raise AdapterError(f"{self.name} reached its collection time limit") from exc
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            if process.stdout:
                process.stdout.close()

    # ---- sanitization and facts ------------------------------------------

    def _sanitized(self, subject: str, found: list[str], reference: Reference) -> RawResult:
        """Persist only the found-service names, never raw tool output.

        Recovery emails, phone fragments and per-service detail in the tool's
        output are discarded here so they never reach the cache, the source
        record, or an export.
        """
        services = sorted({s for s in found if isinstance(s, str) and s.strip()})[: self.max_services]
        payload = {"subject": subject, "tool": self.name, "found_services": services}
        return RawResult(payload=json.dumps(payload, sort_keys=True).encode(),
                         request_url=reference.url, origin_url=reference.origin_url,
                         content_type="application/json",
                         collected_at=datetime.now(timezone.utc))

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        subject = normalize_email(request.value)
        try:
            data = json.loads(raw.payload)
        except (ValueError, UnicodeError):
            raise AdapterError(f"Invalid sanitized {self.name} metadata") from None
        if not isinstance(data, dict) or data.get("subject") != subject:
            raise AdapterError(f"{self.name} metadata does not match the subject")
        services = data.get("found_services")
        if not isinstance(services, list) or any(not isinstance(s, str) for s in services):
            raise AdapterError(f"Invalid sanitized {self.name} metadata")
        services = sorted({s for s in services if s.strip()})[: self.max_services]

        def account_fact(attribute: str, value: str) -> FactDraft:
            return FactDraft(attribute=attribute, value=value, entity_kind="email",
                             entity_name=subject, identity_key="email:" + subject,
                             sensitivity="personal")

        facts = [account_fact("public.account.summary.count", str(len(services)))]
        facts += [account_fact("public.account.found", service) for service in services]
        return facts
