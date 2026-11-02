"""Optional Subfinder discovery with workspace-only process output.

Subfinder aggregates upstream sources; its results intentionally use a separate
namespace so an aggregate replay cannot corroborate a direct upstream adapter.
The installed binary can initialize files in the user's home directory despite
explicit config flags. Execution is therefore disabled until external-write
permission is separately granted, not silently enabled by binary discovery.
"""
from __future__ import annotations

import json
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
    domain = value.strip().lower().rstrip('.')
    labels = domain.split('.')
    if len(domain) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
        for label in labels
    ):
        raise AdapterError('Subfinder requires a valid company domain')
    return domain


class SubfinderAdapter(BaseAdapter):
    name: ClassVar[str] = 'subfinder'
    tier: ClassVar[str] = 'A'
    default_enabled: ClassVar[bool] = False
    collection_mode: ClassVar[str] = 'third_party_passive'
    source_type: ClassVar[str] = 'osint_aggregate'
    description: ClassVar[str] = 'Optional keyless passive discovery through Subfinder'
    produces: ClassVar[frozenset[str]] = frozenset({'discovery.subdomain', 'discovery.source'})
    accepts: ClassVar[frozenset[str]] = frozenset({'company', 'domain'})
    sources: ClassVar[tuple[str, ...]] = ('crtsh', 'commoncrawl', 'rapiddns')
    max_output_bytes: ClassVar[int] = 4 * 1024 * 1024
    max_results: ClassVar[int] = 1000
    timeout: ClassVar[int] = 45
    retention_days: ClassVar[int] = 7

    @staticmethod
    def binary() -> str | None:
        return shutil.which('subfinder')

    def availability(self) -> dict:
        binary = self.binary()
        if not binary:
            return {'available': False, 'reason': 'Subfinder is not installed.'}
        if os.environ.get('NEESHA_ALLOW_TOOL_HOME_WRITES') != '1':
            return {'available': False, 'reason': (
                'Subfinder is installed but disabled: its dependency may initialize '
                'configuration outside NEESHA. Explicit permission is required.'
            )}
        return {'available': True, 'reason': 'Optional keyless passive sources only.'}

    def search(self, request: Request) -> list[Reference]:
        domain = _domain(request.value)
        return [Reference(url='tool://subfinder/' + quote(domain, safe=''),
                          origin_url='tool://subfinder/', label=domain)]

    def fetch(self, reference: Reference) -> RawResult:
        status = self.availability()
        if not status['available']:
            raise AdapterError(status['reason'])
        domain = _domain(reference.label)
        work_dir = PROJECT_ROOT / '.tools' / 'subfinder'
        work_dir.mkdir(parents=True, exist_ok=True)
        config = work_dir / 'config.yaml'
        providers = work_dir / 'provider-config.yaml'
        for path in (config, providers):
            if not path.exists():
                path.write_text('{}\n')
        # Preserve normal process necessities, never ambient provider keys.
        env = {key: value for key, value in os.environ.items() if key in (
            'PATH', 'HOME', 'LANG', 'LC_ALL', 'LC_CTYPE', 'SYSTEMROOT',
            'SSL_CERT_FILE', 'SSL_CERT_DIR',
        )}
        env['SUBFINDER_CONFIG'] = str(config)
        env['SUBFINDER_PROVIDER_CONFIG'] = str(providers)
        args = [self.binary(), '-d', domain, '-s', ','.join(self.sources),
                '-json', '-cs', '-silent', '-duc', '-config', str(config), '-pc', str(providers),
                '-timeout', '10', '-max-time', '1', '-mr', str(self.max_results),
                '-rsr', str(2 * 1024 * 1024), '-rl', '3']
        try:
            with tempfile.TemporaryFile(dir=work_dir) as output:
                self._execute(args, env, output)
                output.seek(0)
                payload = output.read(self.max_output_bytes + 1)
        except AdapterError:
            raise
        except (OSError, ValueError) as exc:
            raise AdapterError('Subfinder could not run; inspect the local tool installation') from exc
        return RawResult(payload=payload, request_url=reference.url,
                         origin_url=reference.origin_url, content_type='application/x-ndjson',
                         collected_at=datetime.now(timezone.utc))

    def _execute(self, args, env, output):
        """Drain stdout into a capped file; never buffer unbounded communicate()."""
        process = subprocess.Popen(args, cwd=PROJECT_ROOT, env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   start_new_session=True)
        total = 0
        deadline = time.monotonic() + self.timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise AdapterError('Subfinder reached its collection time limit')
                    for key, _ in selector.select(min(remaining, 0.2)):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > self.max_output_bytes:
                            raise AdapterError('Subfinder output exceeds the collection size limit')
                        output.write(chunk)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AdapterError('Subfinder reached its collection time limit')
                try:
                    code = process.wait(timeout=remaining)
                except subprocess.TimeoutExpired as exc:
                    raise AdapterError('Subfinder reached its collection time limit') from exc
                if code != 0:
                    raise AdapterError('Subfinder collection failed')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            if process.stdout:
                process.stdout.close()

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        if len(raw.payload) > self.max_output_bytes:
            raise AdapterError('Subfinder output exceeds the collection size limit')
        domain = _domain(request.value)
        hosts: dict[str, set[str]] = {}
        for line in raw.payload.splitlines()[:self.max_results]:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except (ValueError, UnicodeError) as exc:
                raise AdapterError('Subfinder returned invalid JSONL') from exc
            if not isinstance(row, dict) or not isinstance(row.get('host'), str):
                continue
            try:
                host = _domain(row['host'])
            except AdapterError:
                continue
            if host == domain or not host.endswith('.' + domain):
                continue
            values = row.get('sources', [])
            if not isinstance(values, list):
                values = []
            if isinstance(row.get('source'), str):
                values = values + [row['source']]
            sources = {s.lower() for s in values if isinstance(s, str) and s.lower() in self.sources}
            hosts.setdefault(host, set()).update(sources)
        facts = []
        for host, sources in sorted(hosts.items()):
            facts.append(FactDraft(attribute='discovery.subdomain', value=host,
                                   entity_kind='domain', entity_name=domain, value_type='domain'))
            for source in sorted(sources):
                facts.append(FactDraft(attribute='discovery.source', value=source,
                                       entity_kind='domain', entity_name=host))
        return facts
