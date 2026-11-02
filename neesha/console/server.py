"""Loopback-only workspace. No third-party frontend assets or arbitrary file access."""
from __future__ import annotations

import ipaddress
import json
import secrets
import threading
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import sqlalchemy as sa

from neesha.db import schema
from neesha.adapters import registry
from neesha.harness.brief import build_brief
from neesha.harness.gate import EngagementView, PolicyGate, RunCaps
from neesha.harness.run import execute_run
from neesha.ledger.ledger import Ledger
from neesha.harness.scoring import score_brief
from neesha.runtime.providers import provider_readiness
from neesha.resolve.intake import resolve_seed

STATIC = Path(__file__).parent / 'static'


def canonical_domain(value: str) -> str:
    value = value.strip()
    if '://' in value:
        parsed = urlparse(value)
        if parsed.scheme not in ('http', 'https') or parsed.username or parsed.password:
            raise ValueError('Enter a domain or an HTTP(S) website.')
        value = parsed.hostname or ''
    value = value.rstrip('.').lower()
    try:
        value = value.encode('idna').decode('ascii')
        ipaddress.ip_address(value)
    except UnicodeError:
        raise ValueError('Enter a valid domain.') from None
    except ValueError:
        pass
    else:
        raise ValueError('IP investigations are not connected yet. Start with a domain.')
    labels = value.split('.')
    if len(labels) < 2 or len(value) > 253 or any(
        not label or len(label) > 63 or label.startswith('-') or label.endswith('-')
        or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in label)
        for label in labels
    ):
        raise ValueError('Enter a valid company domain, such as example.com.')
    return value


def _aware(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


class Workspace:
    def __init__(self, engine: sa.Engine, sources: set[str] | None = None, profile_path: Path | None = None,
                 reports_root: Path | None = None):
        self.engine = engine
        self.sources = sources
        self.profile_path = profile_path or (Path(__file__).resolve().parents[2] / "config" / "service-profile.json")
        self.reports_root = reports_root or (Path(__file__).resolve().parents[2] / 'reports')
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.job = {'state': 'idle'}
        self.analyzing: set[str] = set()

    def snapshot(self):
        with self.engine.connect() as conn:
            runs = conn.execute(sa.select(
                schema.run.c.id, schema.run.c.status, schema.run.c.started_at,
                schema.run.c.stop_reason, schema.entity.c.canonical_name.label('company'),
                schema.entity.c.kind.label('subject_kind')
            ).join(schema.entity, schema.run.c.company_id == schema.entity.c.id)
              .order_by(schema.run.c.started_at.desc()).limit(100)).mappings().all()
        with self.lock:
            job = dict(self.job)
        budget = Ledger(self.engine).summary()
        return {
            'runs': [dict(r) for r in runs],
            'budget': {'cap': str(budget.cap_usd), 'committed': str(budget.committed_usd),
                       'remaining': str(budget.remaining_usd), 'period': budget.period},
            'job': job,
            'sources': registry.catalog(),
            'runtime_providers': provider_readiness(),
            'service_profile_configured': self.profile_path.exists(),
        }

    def profile(self):
        if not self.profile_path.exists():
            return None
        try:
            if self.profile_path.stat().st_size > 16384:
                raise ValueError('Service profile is too large.')
            profile = json.loads(self.profile_path.read_text())
            score_brief([], profile)
            return profile
        except (OSError, ValueError):
            raise ValueError('Service profile is invalid; update it using the profile settings API.') from None

    def save_profile(self, payload):
        score_brief([], payload)
        self.profile_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock:
            temporary = self.profile_path.with_suffix('.json.tmp')
            temporary.write_text(json.dumps(payload, indent=2) + '\n')
            temporary.replace(self.profile_path)
        return {'configured': True}

    def brief(self, run_id):
        brief = build_brief(self.engine, run_id, self.profile())
        path = self._analysis_path(run_id)
        if path.exists():
            try:
                if path.stat().st_size > 1_000_000:
                    raise ValueError('Stored model report is too large.')
                brief['model_analysis'] = json.loads(path.read_text())
            except (OSError, ValueError):
                brief['analysis_error'] = 'Stored model report could not be read.'
        return brief

    def _analysis_path(self, run_id):
        if len(run_id) != 32 or any(c not in '0123456789abcdef' for c in run_id):
            raise ValueError('Invalid investigation ID.')
        path = self.reports_root / 'runtime' / (run_id + '.json')
        if any(p.is_symlink() for p in (self.reports_root, path.parent, path)):
            raise ValueError('Model report storage must not contain symbolic links.')
        return path

    def analyze(self, run_id, mode, providers):
        from neesha.runtime.investigation import analyze_brief
        with self.lock:
            if run_id in self.analyzing:
                raise ValueError('Analysis is already running for this investigation.')
            self.analyzing.add(run_id)
        try:
            brief = self.brief(run_id)
            try:
                result = analyze_brief(self.engine, brief, mode, providers)
            except ValueError as exc:
                self._save_analysis(run_id, {'status': 'failed', 'mode': mode,
                    'run_id': run_id, 'claims': [], 'reports': [], 'reason': str(exc),
                    'created_at': datetime.now(timezone.utc).isoformat()})
                raise
            self._save_analysis(run_id, result)
            return result
        finally:
            with self.lock:
                self.analyzing.discard(run_id)

    def _save_analysis(self, run_id, result):
        from neesha.config import harden_path
        path = self._analysis_path(run_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        harden_path(self.reports_root)
        harden_path(path.parent)
        temporary = path.with_suffix('.json.tmp')
        if temporary.is_symlink():
            raise ValueError('Model report storage must not contain symbolic links.')
        temporary.write_text(json.dumps(result, indent=2) + '\n')
        temporary.replace(path)
        harden_path(path)

    def delete(self, run_id):
        from neesha.harness.deletion import delete_investigation
        with self.lock:
            if self.job['state'] == 'running' or self.analyzing:
                raise ValueError('Wait for collection and model analysis to finish before deleting an investigation.')
            result = delete_investigation(self.engine, run_id, self.reports_root)
            if self.job.get('run_id') == run_id:
                self.job = {'state': 'idle'}
            return result

    def launch(self, payload):
        seed = resolve_seed(payload.get('seed', payload.get('domain', '')), payload.get('kind', 'auto'))
        is_email = seed['kind'] == 'email'
        if seed['requires_resolution'] or (not is_email and not seed.get('domain')):
            raise ValueError(seed['reason'])
        domain = seed['normalized'] if is_email else canonical_domain(seed['domain'])
        mode = payload.get('analysis_mode', 'deterministic')
        providers = payload.get('providers', [])
        if mode not in ('deterministic', 'single', 'multi'):
            raise ValueError('Choose deterministic, single, or multi agent mode.')
        if mode != 'deterministic':
            from neesha.runtime.investigation import analyze_brief
            # Empty facts validates configuration without a model call or charge.
            analyze_brief(self.engine, {'facts': []}, mode, providers)
        # Public company research needs no setup ceremony. Persist a scoped
        # research context for provenance; it grants no active techniques.
        now = datetime.now(timezone.utc)
        engagement_id = uuid4().hex
        engagement = EngagementView(
            id=engagement_id, authority_basis='public_research' if is_email else 'prospect_company',
            authorized_domains=() if is_email else (domain,),
            authorized_emails=(domain,) if is_email else (), permitted_techniques=frozenset(),
            starts_at=now, expires_at=now + timedelta(days=1),
        )
        contacts = payload.get('contacts') is True
        website = payload.get('website') is not False
        with self.lock:
            if self.job['state'] == 'running':
                raise ValueError('An investigation is already running. Wait for it to finish.')
            with self.engine.begin() as conn:
                conn.execute(schema.engagement.insert().values(
                    id=engagement_id, authority_basis=engagement.authority_basis,
                    authorized_domains=list(engagement.authorized_domains),
                    authorized_emails=list(engagement.authorized_emails), permitted_techniques=[],
                    authorized_by='local-workspace:public-research',
                    starts_at=engagement.starts_at, expires_at=engagement.expires_at,
                    created_at=now,
                ))
            self.job = {'state': 'running', 'domain': domain, 'seed_kind': seed['kind'],
                        'seed_reason': seed['reason'], 'analysis_mode': mode}
        threading.Thread(target=self._run, args=(domain, engagement, contacts, website,
                         'email' if is_email else 'domain', mode, providers), daemon=True).start()
        return {'state': 'running', 'domain': domain}

    def _run(self, domain, engagement, contacts, website=True, subject_kind='domain',
             analysis_mode='deterministic', providers=None):
        try:
            ledger = Ledger(self.engine)
            available = {s['name'] for s in registry.catalog()
                         if s['integrated'] and s['ready'] and (s['tier'] == 'A' or (contacts and s['tier'] == 'B'))}
            if not website:
                available.discard('company-web')
            if self.sources is not None:
                available &= self.sources
            available = {name for name in available if subject_kind in registry.get(name).accepts}

            def progress(update):
                with self.lock:
                    self.job.update(update)

            report = execute_run(
                engine=self.engine, ledger=ledger, gate=PolicyGate(self.engine, ledger),
                company=domain, engagement=engagement, analyst='local-workspace',
                pir_templates=(('email-public-presence',) if subject_kind == 'email' else
                    ('attack-surface', 'company-contacts', 'email-posture', 'public-history',
                     'web-response', 'tool-discovery') + (('who-to-contact',) if contacts else ())),
                tiers={'A', 'B'} if contacts else {'A'},
                caps=RunCaps(max_steps=12, max_spend_usd=Decimal('1'), max_wall_secs=300),
                sources=available, progress=progress, subject_kind=subject_kind,
            )
            job = {'state': 'complete', 'domain': domain, 'run_id': report.run_id,
                   'analysis_mode': analysis_mode,
                   'observations': report.facts_written,
                   'sources_completed': len(report.steps),
                   'sources_with_gaps': len(report.skipped)}
            if analysis_mode != 'deterministic':
                progress({'phase': 'analysis', 'run_id': report.run_id})
                try:
                    analysis = self.analyze(report.run_id, analysis_mode, providers)
                    job['analysis_status'] = analysis['status']
                except ValueError as exc:
                    job['analysis_status'] = 'failed'
                    job['analysis_error'] = str(exc)
        except Exception:
            # Provider exceptions may contain secrets: never return them to the browser.
            job = {'state': 'failed', 'domain': domain,
                   'error': 'Investigation could not finish. Review the local run records before retrying.'}
        with self.lock:
            self.job = job


def make_handler(workspace: Workspace):
    class Handler(BaseHTTPRequestHandler):
        def _local_request(self):
            host = self.headers.get('Host', '')
            return host in (f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}')

        def _send(self, status, body, content_type='application/json'):
            data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if not self._local_request():
                return self._send(403, {'error': 'Local access only.'})
            path = urlparse(self.path).path
            assets = {'/': ('index.html', 'text/html; charset=utf-8'),
                      '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                      '/style.css': ('style.css', 'text/css; charset=utf-8')}
            if path in assets:
                filename, mime = assets[path]
                return self._send(200, (STATIC / filename).read_bytes(), mime)
            if path == '/api/session':
                return self._send(200, {'token': workspace.token})
            if path == '/api/profile':
                try:
                    return self._send(200, {'profile': workspace.profile()})
                except ValueError as exc:
                    return self._send(400, {'error': str(exc)})
            if path == '/api/workspace':
                return self._send(200, workspace.snapshot())
            if path.startswith('/api/runs/'):
                run_id = path.removeprefix('/api/runs/')
                if len(run_id) != 32 or any(c not in '0123456789abcdef' for c in run_id):
                    return self._send(404, {'error': 'Run not found.'})
                try:
                    return self._send(200, workspace.brief(run_id))
                except sa.exc.NoResultFound:
                    return self._send(404, {'error': 'Run not found.'})
                except ValueError as exc:
                    return self._send(400, {'error': str(exc)})
            return self._send(404, {'error': 'Not found.'})

        def do_POST(self):
            if not self._local_request():
                return self._send(403, {'error': 'Local access only.'})
            expected_origin = f'http://{self.headers.get("Host", "")}'
            if self.headers.get('Origin') != expected_origin or not secrets.compare_digest(
                self.headers.get('X-Workspace-Token', ''), workspace.token
            ):
                return self._send(403, {'error': 'Invalid workspace session.'})
            analysis_path = self.path.startswith('/api/runs/') and self.path.endswith('/analysis')
            if self.path not in ('/api/investigations', '/api/profile', '/api/resolve') and not analysis_path:
                return self._send(404, {'error': 'Not found.'})
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 16384:
                    raise ValueError('Request must be between 1 and 16384 bytes.')
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError('Expected a JSON object.')
                if self.path == '/api/resolve':
                    result = resolve_seed(payload.get('seed', ''), payload.get('kind', 'auto'))
                elif self.path == '/api/profile':
                    result = workspace.save_profile(payload)
                elif analysis_path:
                    run_id = self.path.split('/')[3]
                    if len(run_id) != 32 or any(c not in '0123456789abcdef' for c in run_id):
                        raise ValueError('Invalid investigation ID.')
                    result = workspace.analyze(run_id, payload.get('mode'), payload.get('providers'))
                else:
                    result = workspace.launch(payload)
            except (ValueError, UnicodeError, sa.exc.NoResultFound) as exc:
                return self._send(400, {'error': str(exc)})
            return self._send(202, result)

        def do_DELETE(self):
            if not self._local_request():
                return self._send(403, {'error': 'Local access only.'})
            if self.headers.get('Origin') != f'http://{self.headers.get("Host", "")}' or not secrets.compare_digest(
                    self.headers.get('X-Workspace-Token', ''), workspace.token):
                return self._send(403, {'error': 'Invalid workspace session.'})
            if not self.path.startswith('/api/runs/'):
                return self._send(404, {'error': 'Not found.'})
            run_id = self.path.removeprefix('/api/runs/')
            if len(run_id) != 32 or any(c not in '0123456789abcdef' for c in run_id):
                return self._send(404, {'error': 'Run not found.'})
            try:
                result = workspace.delete(run_id)
            except sa.exc.NoResultFound:
                return self._send(404, {'error': 'Run not found.'})
            except ValueError as exc:
                return self._send(409, {'error': str(exc)})
            except (OSError, sa.exc.SQLAlchemyError):
                return self._send(409, {'error': 'Deletion could not complete. Check storage permissions and database access.'})
            return self._send(200, result)

        def log_message(self, *args):
            pass
    return Handler


def serve(engine: sa.Engine, port: int = 8765):
    if not sa.inspect(engine).has_table('engagement'):
        raise ValueError('Initialize the harness database with alembic upgrade head first.')
    workspace = Workspace(engine)
    # Reports hold personal data and are not encrypted at rest: keep the tree
    # owner-only so other local users cannot read exported briefings.
    from neesha.config import harden_path
    if workspace.reports_root.exists():
        harden_path(workspace.reports_root)
    server = ThreadingHTTPServer(('127.0.0.1', port), make_handler(workspace))
    print(f'NEESHA workspace: http://127.0.0.1:{server.server_port} (Ctrl-C to stop)')
    try:
        server.serve_forever()
    finally:
        server.server_close()
