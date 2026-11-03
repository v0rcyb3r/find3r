"""Loopback-only workspace. No third-party frontend assets or arbitrary file access."""
from __future__ import annotations

import ipaddress
import json
import os
import secrets
import threading
import time
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

ALLOWED_SETTING_KEYS = (
    'VULTR_API_KEY',
    'SHODAN_API_KEY',
    'HUNTER_API_KEY',
    'EMAILREP_API_KEY',
    'INTELX_API_KEY',
    'OPENAI_API_KEY',
    'ANTHROPIC_API_KEY',
    'GEMINI_API_KEY',
    'DEEPSEEK_API_KEY',
)

DEFAULT_MODELS = {
    'openai': 'gpt-4o-mini',
    'anthropic': 'claude-3-5-sonnet-latest',
    'google': 'gemini-2.5-flash',
    'deepseek': 'deepseek-chat',
    'ollama': 'llama3.1:8b',
}


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
                 reports_root: Path | None = None, settings_path: Path | None = None):
        self.engine = engine
        self.sources = sources
        self.profile_path = profile_path or (Path(__file__).resolve().parents[2] / "config" / "service-profile.json")
        self.settings_path = settings_path or (self.profile_path.parent / "runtime-settings.json")
        self.reports_root = reports_root or (Path(__file__).resolve().parents[2] / 'reports')
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.job = {'state': 'idle'}
        self.analyzing: set[str] = set()
        self._catalog_cache: tuple[float, list[dict]] | None = None
        self._brief_cache: dict[str, tuple[float, dict]] = {}
        self._load_saved_settings()
        from neesha.cloud.vultr import VultrManager
        from neesha.harness.operations import OperationsManager
        self.vultr = VultrManager(self.profile_path.parent)
        self.operations = OperationsManager(self.profile_path.parent / "operations-store.json")

    def _load_saved_settings(self):
        if not self.settings_path.exists():
            return
        try:
            data = json.loads(self.settings_path.read_text())
            if not isinstance(data, dict):
                return
            for k, v in (data.get('keys') or {}).items():
                if k in ALLOWED_SETTING_KEYS and isinstance(v, str) and v.strip():
                    os.environ[k] = v.strip()
            for p, m in (data.get('models') or {}).items():
                if p in DEFAULT_MODELS and isinstance(m, str) and m.strip():
                    os.environ[f'NEESHA_{p.upper()}_MODEL'] = m.strip()
            for p, c in (data.get('call_caps') or {}).items():
                if p in DEFAULT_MODELS and isinstance(c, str) and c.strip():
                    os.environ[f'NEESHA_{p.upper()}_CALL_CAP_USD'] = c.strip()
        except Exception:
            pass

    def _catalog(self, force: bool = False) -> list[dict]:
        now = time.monotonic()
        if not force and self._catalog_cache and (now - self._catalog_cache[0]) < 5.0:
            return self._catalog_cache[1]
        cat = registry.catalog()
        self._catalog_cache = (now, cat)
        return cat

    def refresh_tools(self) -> dict:
        cat = self._catalog(force=True)
        return {'sources': cat, 'ready_count': sum(1 for s in cat if s.get('ready'))}

    def install_tool(self, tool_name: str) -> dict:
        from neesha.adapters.tool_installer import install_tool
        result = install_tool(str(tool_name or '').strip())
        self._catalog_cache = None
        result['sources'] = self._catalog(force=True)
        return result

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
        from neesha.adapters.tool_installer import detect_os_platform
        from neesha.runtime.ollama import ollama_status
        return {
            'runs': [dict(r) for r in runs],
            'budget': {'cap': str(budget.cap_usd), 'committed': str(budget.committed_usd),
                       'remaining': str(budget.remaining_usd), 'period': budget.period},
            'job': job,
            'sources': self._catalog(),
            'runtime_providers': provider_readiness(),
            'ollama': ollama_status(),
            'service_profile_configured': self.profile_path.exists(),
            'cloud': self.vultr.list_nodes(sync_remote=False),
            'operations': self.operations.snapshot(),
            'host_os': detect_os_platform(),
        }

    def settings(self) -> dict:
        budget = Ledger(self.engine).summary()
        keys_info = {}
        for k in ALLOWED_SETTING_KEYS:
            val = os.environ.get(k, '').strip()
            keys_info[k] = {
                'configured': bool(val),
                'masked': ('••••' + val[-4:]) if len(val) > 4 else ('••••' if val else ''),
            }
        models_info = {
            p: os.environ.get(f'NEESHA_{p.upper()}_MODEL', DEFAULT_MODELS[p])
            for p in DEFAULT_MODELS
        }
        caps_info = {
            p: os.environ.get(f'NEESHA_{p.upper()}_CALL_CAP_USD', '0.05')
            for p in DEFAULT_MODELS
        }
        return {
            'keys': keys_info,
            'models': models_info,
            'call_caps': caps_info,
            'monthly_budget_usd': str(budget.cap_usd),
        }

    def select_ollama_model(self, model: str) -> dict:
        from neesha.runtime.ollama import ollama_status, valid_ollama_model
        cleaned = valid_ollama_model(model)
        self.save_settings({'models': {'ollama': cleaned}})
        return ollama_status()

    def pull_ollama(self, model: str) -> dict:
        from neesha.runtime.ollama import pull_ollama_model, valid_ollama_model
        cleaned = valid_ollama_model(model)
        status = pull_ollama_model(cleaned)
        self.save_settings({'models': {'ollama': cleaned}})
        return status

    def create_ollama(self, name: str, source: str) -> dict:
        from neesha.runtime.ollama import create_custom_ollama_model
        status = create_custom_ollama_model(name, source)
        self.save_settings({'models': {'ollama': status['selected_model']}})
        return status

    def install_ollama(self) -> dict:
        from neesha.adapters.tool_installer import install_tool
        from neesha.runtime.ollama import ensure_ollama_running, ollama_status
        res = install_tool('ollama')
        ensure_ollama_running(wait_seconds=3.0)
        status = ollama_status()
        status['install_result'] = res
        return status

    def save_settings(self, payload: dict) -> dict:
        from neesha.config import harden_path
        if not isinstance(payload, dict):
            raise ValueError('Expected settings object.')
        with self.lock:
            existing = {}
            if self.settings_path.exists():
                try:
                    existing = json.loads(self.settings_path.read_text())
                    if not isinstance(existing, dict):
                        existing = {}
                except Exception:
                    existing = {}
            saved_keys = dict(existing.get('keys') or {})
            saved_models = dict(existing.get('models') or {})
            saved_caps = dict(existing.get('call_caps') or {})

            if isinstance(payload.get('keys'), dict):
                for k, v in payload['keys'].items():
                    if k not in ALLOWED_SETTING_KEYS:
                        continue
                    if v is None or v == '':
                        continue
                    if not isinstance(v, str) or any(ch in v for ch in ('\r', '\n', ' ')):
                        raise ValueError(f'Invalid format for {k}.')
                    os.environ[k] = v.strip()
                    saved_keys[k] = v.strip()
                    # Populate default model and call cap when an LLM key is configured
                    provider_map = {
                        'OPENAI_API_KEY': 'openai',
                        'ANTHROPIC_API_KEY': 'anthropic',
                        'GEMINI_API_KEY': 'google',
                        'DEEPSEEK_API_KEY': 'deepseek',
                    }
                    if k in provider_map:
                        p = provider_map[k]
                        if not os.environ.get(f'NEESHA_{p.upper()}_MODEL'):
                            os.environ[f'NEESHA_{p.upper()}_MODEL'] = DEFAULT_MODELS[p]
                            saved_models[p] = DEFAULT_MODELS[p]
                        if not os.environ.get(f'NEESHA_{p.upper()}_CALL_CAP_USD'):
                            os.environ[f'NEESHA_{p.upper()}_CALL_CAP_USD'] = '0.05'
                            saved_caps[p] = '0.05'

            if isinstance(payload.get('clear_keys'), list):
                for k in payload['clear_keys']:
                    if k in ALLOWED_SETTING_KEYS:
                        os.environ.pop(k, None)
                        saved_keys.pop(k, None)

            if isinstance(payload.get('models'), dict):
                from neesha.runtime.ollama import valid_ollama_model
                from neesha.runtime.providers import MODEL_ID
                for p, m in payload['models'].items():
                    if p in DEFAULT_MODELS and isinstance(m, str) and m.strip():
                        cleaned_m = m.strip()
                        if p == 'ollama':
                            cleaned_m = valid_ollama_model(cleaned_m)
                        elif not MODEL_ID.fullmatch(cleaned_m):
                            raise ValueError(f'Invalid model identifier for {p}.')
                        os.environ[f'NEESHA_{p.upper()}_MODEL'] = cleaned_m
                        saved_models[p] = cleaned_m

            if isinstance(payload.get('call_caps'), dict):
                for p, c in payload['call_caps'].items():
                    if p in DEFAULT_MODELS and c is not None and str(c).strip():
                        val = Decimal(str(c).strip())
                        if val <= 0 or val > Decimal('100'):
                            raise ValueError(f'Call cap for {p} must be between 0.01 and 100.00 USD.')
                        os.environ[f'NEESHA_{p.upper()}_CALL_CAP_USD'] = str(val)
                        saved_caps[p] = str(val)

            if payload.get('monthly_budget_usd') is not None and str(payload['monthly_budget_usd']).strip() != '':
                cap_val = Decimal(str(payload['monthly_budget_usd']).strip())
                if cap_val < 0 or cap_val > Decimal('100000'):
                    raise ValueError('Monthly budget cap must be between 0 and 100000 USD.')
                Ledger(self.engine).set_cap(cap_val)

            self.settings_path.parent.mkdir(parents=True, exist_ok=True)
            harden_path(self.settings_path.parent)
            tmp = self.settings_path.with_suffix('.json.tmp')
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as fh:
                fh.write(json.dumps({
                    'keys': saved_keys,
                    'models': saved_models,
                    'call_caps': saved_caps,
                }, indent=2) + '\n')
            tmp.replace(self.settings_path)
            harden_path(self.settings_path)
            self._catalog_cache = None
        return self.settings()

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
        from neesha.config import harden_path
        score_brief([], payload)
        self.profile_path.parent.mkdir(parents=True, exist_ok=True)
        harden_path(self.profile_path.parent)
        with self.lock:
            temporary = self.profile_path.with_suffix('.json.tmp')
            temporary.write_text(json.dumps(payload, indent=2) + '\n')
            temporary.replace(self.profile_path)
            harden_path(self.profile_path)
            self._brief_cache.clear()
        return {'configured': True}

    def brief(self, run_id):
        now = time.monotonic()
        cached = self._brief_cache.get(run_id)
        if cached and (now - cached[0]) < 15.0 and self.job.get('run_id') != run_id:
            brief = dict(cached[1])
        else:
            brief = build_brief(self.engine, run_id, self.profile())
            if brief.get('status') in ('complete', 'stopped'):
                self._brief_cache[run_id] = (now, dict(brief))
        path = self._analysis_path(run_id)
        if path.exists():
            try:
                if path.stat().st_size > 1_000_000:
                    raise ValueError('Stored model report is too large.')
                brief['model_analysis'] = json.loads(path.read_text())
            except (OSError, ValueError):
                brief['analysis_error'] = 'Stored model report could not be read.'
        ops_snap = self.operations.snapshot(run_id=run_id)
        ops_snap['hypotheses'] = self.operations.score_hypotheses(
            ops_snap.get('hypotheses') or [],
            brief.get('facts') or [],
        )
        brief['operations'] = ops_snap
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
            self._brief_cache.pop(run_id, None)
            if self.job.get('run_id') == run_id:
                self.job = {'state': 'idle'}
            return result

    def launch(self, payload):
        seed = resolve_seed(payload.get('seed', payload.get('domain', '')), payload.get('kind', 'auto'))
        seed_kind = seed['kind']
        if seed['requires_resolution']:
            raise ValueError(seed['reason'])
        if seed_kind in ('domain', 'website'):
            if not seed.get('domain'):
                raise ValueError(seed['reason'])
            domain = canonical_domain(seed['domain'])
            subject_kind = 'domain'
        elif seed_kind in ('email', 'username', 'ip', 'phone', 'company', 'person'):
            domain = seed['normalized']
            subject_kind = seed_kind
        else:
            raise ValueError(seed['reason'])

        mode = payload.get('analysis_mode', 'deterministic')
        providers = payload.get('providers', [])
        if mode not in ('deterministic', 'single', 'multi'):
            raise ValueError('Choose deterministic, single, or multi agent mode.')
        if mode != 'deterministic':
            from neesha.runtime.investigation import analyze_brief
            # Empty facts validates configuration without a model call or charge.
            analyze_brief(self.engine, {'facts': []}, mode, providers)

        now = datetime.now(timezone.utc)
        engagement_id = uuid4().hex
        is_personal_kind = subject_kind in ('email', 'username')
        techniques = frozenset({'account_enumeration'}) if is_personal_kind else frozenset()
        engagement = EngagementView(
            id=engagement_id,
            authority_basis='public_research' if is_personal_kind else 'prospect_company',
            authorized_domains=() if is_personal_kind else (domain,),
            authorized_emails=(domain,) if subject_kind == 'email' else (),
            authorized_usernames=(domain,) if subject_kind == 'username' else (),
            permitted_techniques=techniques,
            starts_at=now, expires_at=now + timedelta(days=1),
        )
        contacts = payload.get('contacts') is True
        website = payload.get('website') is not False
        run_id = uuid4().hex
        with self.lock:
            if self.job['state'] == 'running':
                raise ValueError('An investigation is already running. Wait for it to finish.')
            with self.engine.begin() as conn:
                conn.execute(schema.engagement.insert().values(
                    id=engagement_id, authority_basis=engagement.authority_basis,
                    authorized_domains=list(engagement.authorized_domains),
                    authorized_emails=list(engagement.authorized_emails),
                    authorized_usernames=list(engagement.authorized_usernames),
                    permitted_techniques=list(engagement.permitted_techniques),
                    authorized_by='local-workspace:public-research',
                    starts_at=engagement.starts_at, expires_at=engagement.expires_at,
                    created_at=now,
                ))
            self.job = {'state': 'running', 'domain': domain, 'run_id': run_id,
                        'seed_kind': seed_kind, 'subject_kind': subject_kind,
                        'seed_reason': seed['reason'], 'analysis_mode': mode}
        threading.Thread(target=self._run, args=(domain, engagement, contacts, website,
                         subject_kind, mode, providers, run_id), daemon=True).start()
        return {'state': 'running', 'domain': domain, 'run_id': run_id, 'subject_kind': subject_kind}

    def _run(self, domain, engagement, contacts, website=True, subject_kind='domain',
             analysis_mode='deterministic', providers=None, run_id=None):
        try:
            def progress(update):
                with self.lock:
                    self.job.update(update)

            remote_node = self.vultr.get_active_remote_node() if self.sources is None else None
            if remote_node is not None:
                rem = self.vultr.execute_remote_investigation(
                    engine=self.engine,
                    node=remote_node,
                    target=domain,
                    subject_kind=subject_kind,
                    engagement_id=engagement.id,
                    run_id=run_id,
                    contacts=contacts,
                    website=website,
                    progress_cb=progress,
                )
                job = {
                    'state': 'complete',
                    'domain': domain,
                    'run_id': rem['run_id'],
                    'subject_kind': subject_kind,
                    'analysis_mode': analysis_mode,
                    'observations': rem['facts_written'],
                    'sources_completed': rem['steps_count'],
                    'sources_with_gaps': rem['skipped_count'],
                    'execution_node': f"{rem['node_ip']} ({rem['node_region']})",
                }
            else:
                ledger = Ledger(self.engine)
                allowed_tiers = {'A', 'B', 'C'} if contacts else {'A', 'C'}
                available = {s['name'] for s in self._catalog()
                             if s['integrated'] and s['ready'] and s['tier'] in allowed_tiers}
                if not website:
                    available.discard('company-web')
                if self.sources is not None:
                    available &= self.sources
                available = {name for name in available if subject_kind in registry.get(name).accepts}

                if subject_kind == 'email':
                    pir_templates = ('email-public-presence', 'email-account-presence')
                elif subject_kind == 'username':
                    pir_templates = ('username-account-presence',)
                elif subject_kind == 'ip':
                    pir_templates = ('ip-infrastructure', 'whois-registration')
                else:
                    pir_templates = (
                        'attack-surface', 'company-contacts', 'email-posture', 'public-history',
                        'web-response', 'tool-discovery', 'whois-registration', 'ip-infrastructure',
                    ) + (('who-to-contact',) if contacts else ())

                report = execute_run(
                    engine=self.engine, ledger=ledger, gate=PolicyGate(self.engine, ledger),
                    company=domain, engagement=engagement, analyst='local-workspace',
                    pir_templates=pir_templates,
                    tiers=allowed_tiers,
                    caps=RunCaps(max_steps=30, max_spend_usd=Decimal('1'), max_wall_secs=300),
                    sources=available, progress=progress, subject_kind=subject_kind,
                    run_id=run_id, parallel=(self.sources is None),
                )
                job = {'state': 'complete', 'domain': domain, 'run_id': report.run_id,
                       'subject_kind': subject_kind,
                       'analysis_mode': analysis_mode,
                       'observations': report.facts_written,
                       'sources_completed': len(report.steps),
                       'sources_with_gaps': len(report.skipped)}
            if analysis_mode != 'deterministic':
                progress({'phase': 'analysis', 'run_id': job['run_id']})
                try:
                    analysis = self.analyze(job['run_id'], analysis_mode, providers)
                    job['analysis_status'] = analysis['status']
                except ValueError as exc:
                    job['analysis_status'] = 'failed'
                    job['analysis_error'] = str(exc)
        except ValueError as exc:
            job = {'state': 'failed', 'domain': domain, 'error': str(exc)}
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
            if host not in (f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'):
                return False
            sec_fetch_site = (self.headers.get('Sec-Fetch-Site') or '').strip().lower()
            if sec_fetch_site and sec_fetch_site not in ('same-origin', 'none'):
                return False
            return True

        def _send(self, status, body, content_type='application/json'):
            import gzip
            data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
            accept_enc = (self.headers.get('Accept-Encoding') or '').lower()
            use_gzip = 'gzip' in accept_enc and len(data) >= 1024
            if use_gzip:
                data = gzip.compress(data, compresslevel=5)
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            if use_gzip:
                self.send_header('Content-Encoding', 'gzip')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
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
            if path == '/api/settings':
                return self._send(200, workspace.settings())
            if path == '/api/profile':
                try:
                    return self._send(200, {'profile': workspace.profile()})
                except ValueError as exc:
                    return self._send(400, {'error': str(exc)})
            if path == '/api/workspace':
                return self._send(200, workspace.snapshot())
            if path == '/api/ollama/status':
                from neesha.runtime.ollama import ollama_status
                return self._send(200, ollama_status())
            if path == '/api/cloud/nodes':
                return self._send(200, workspace.vultr.list_nodes(sync_remote=False))
            if path.startswith('/api/operations/cases/'):
                case_id = path.removeprefix('/api/operations/cases/').strip('/')
                try:
                    return self._send(200, workspace.operations.build_case_dossier(case_id, workspace.brief))
                except ValueError as exc:
                    return self._send(404, {'error': str(exc)})
            if path.startswith('/api/tools/preinstall/'):
                from neesha.adapters.tool_installer import generate_preinstall_script
                target_os = path.removeprefix('/api/tools/preinstall/')
                filename, content_type, script_body = generate_preinstall_script(target_os)
                return self._send(200, {'filename': filename, 'content_type': content_type, 'script': script_body})
            if path.startswith('/api/runs/'):
                tail = path.removeprefix('/api/runs/')
                if '/diff/' in tail:
                    from neesha.harness.operations import diff_briefs
                    run_a, run_b = tail.split('/diff/', 1)
                    for r_chk in (run_a, run_b):
                        if len(r_chk) != 32 or any(c not in '0123456789abcdef' for c in r_chk):
                            return self._send(404, {'error': 'Run not found.'})
                    try:
                        return self._send(200, diff_briefs(workspace.brief(run_a), workspace.brief(run_b)))
                    except sa.exc.NoResultFound:
                        return self._send(404, {'error': 'Run not found.'})
                    except ValueError as exc:
                        return self._send(400, {'error': str(exc)})
                if tail.endswith(('/maltego.graphml', '/maltego.csv', '/stix.json', '/dossier.html')):
                    from neesha.harness.mapping import (
                        build_html_dossier,
                        build_maltego_csv,
                        build_maltego_graphml,
                        build_stix_bundle,
                    )
                    run_id, fmt = tail.split('/', 1)
                    if len(run_id) != 32 or any(c not in '0123456789abcdef' for c in run_id):
                        return self._send(404, {'error': 'Run not found.'})
                    try:
                        b = workspace.brief(run_id)
                        if fmt == 'maltego.graphml':
                            return self._send(200, {'filename': f'find3r-{run_id}-maltego.graphml', 'content_type': 'application/graphml+xml; charset=utf-8', 'content': build_maltego_graphml(b)})
                        if fmt == 'maltego.csv':
                            return self._send(200, {'filename': f'find3r-{run_id}-maltego.csv', 'content_type': 'text/csv; charset=utf-8', 'content': build_maltego_csv(b)})
                        if fmt == 'stix.json':
                            return self._send(200, {'filename': f'find3r-{run_id}-stix21.json', 'content_type': 'application/stix+json; charset=utf-8', 'content': build_stix_bundle(b)})
                        return self._send(200, {'filename': f'find3r-{run_id}-dossier.html', 'content_type': 'text/html; charset=utf-8', 'content': build_html_dossier(b)})
                    except sa.exc.NoResultFound:
                        return self._send(404, {'error': 'Run not found.'})
                    except ValueError as exc:
                        return self._send(400, {'error': str(exc)})
                run_id = tail
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
            parsed_path = urlparse(self.path).path
            path_parts = parsed_path.split('/')
            analysis_path = (
                len(path_parts) == 5
                and path_parts[1:3] == ['api', 'runs']
                and path_parts[4] == 'analysis'
            )
            allowed_posts = (
                '/api/investigations', '/api/profile', '/api/resolve', '/api/settings',
                '/api/tools/install', '/api/tools/refresh',
                '/api/ollama/select', '/api/ollama/pull', '/api/ollama/create', '/api/ollama/install',
                '/api/cloud/spinup', '/api/cloud/destroy', '/api/cloud/select', '/api/cloud/rotate', '/api/cloud/sync',
                '/api/operations/cases', '/api/operations/cases/delete',
                '/api/operations/pin', '/api/operations/note', '/api/operations/note/delete',
                '/api/operations/hypothesis', '/api/operations/hypothesis/delete',
            )
            if parsed_path not in allowed_posts and not analysis_path:
                return self._send(404, {'error': 'Not found.'})
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 16384:
                    raise ValueError('Request must be between 1 and 16384 bytes.')
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError('Expected a JSON object.')
                if parsed_path == '/api/resolve':
                    result = resolve_seed(payload.get('seed', ''), payload.get('kind', 'auto'))
                elif parsed_path == '/api/profile':
                    result = workspace.save_profile(payload)
                elif parsed_path == '/api/settings':
                    result = workspace.save_settings(payload)
                elif parsed_path == '/api/tools/refresh':
                    result = workspace.refresh_tools()
                elif parsed_path == '/api/tools/install':
                    result = workspace.install_tool(payload.get('tool', 'all'))
                elif parsed_path == '/api/ollama/select':
                    result = workspace.select_ollama_model(str(payload.get('model', 'llama3.1:8b')))
                elif parsed_path == '/api/ollama/pull':
                    result = workspace.pull_ollama(str(payload.get('model', 'llama3.1:8b')))
                elif parsed_path == '/api/ollama/create':
                    result = workspace.create_ollama(
                        str(payload.get('name', '')),
                        str(payload.get('source', '')),
                    )
                elif parsed_path == '/api/ollama/install':
                    result = workspace.install_ollama()
                elif parsed_path == '/api/cloud/spinup':
                    result = workspace.vultr.spin_up_node(
                        region=str(payload.get('region', 'random')),
                        plan=str(payload.get('plan', 'vc2-1c-2gb')),
                        auto_select=bool(payload.get('auto_select', True)),
                    )
                elif parsed_path == '/api/cloud/destroy':
                    result = workspace.vultr.destroy_node(str(payload.get('instance_id', '')))
                elif parsed_path == '/api/cloud/select':
                    result = workspace.vultr.select_node(str(payload.get('node_id', 'local')))
                elif parsed_path == '/api/cloud/rotate':
                    result = workspace.vultr.rotate_node(region=str(payload.get('region', 'random')))
                elif parsed_path == '/api/cloud/sync':
                    result = workspace.vultr.list_nodes(sync_remote=True)
                elif parsed_path == '/api/operations/cases':
                    result = workspace.operations.save_case(payload)
                elif parsed_path == '/api/operations/cases/delete':
                    result = workspace.operations.delete_case(str(payload.get('id', '')))
                elif parsed_path == '/api/operations/pin':
                    result = workspace.operations.toggle_pin(payload)
                elif parsed_path == '/api/operations/note':
                    result = workspace.operations.add_note(payload)
                elif parsed_path == '/api/operations/note/delete':
                    result = workspace.operations.delete_note(str(payload.get('id', '')), str(payload.get('run_id', '')))
                elif parsed_path == '/api/operations/hypothesis':
                    rid = str(payload.get('run_id', '')).strip()
                    facts = workspace.brief(rid).get('facts', []) if len(rid) == 32 else []
                    result = workspace.operations.save_hypothesis(payload, facts)
                elif parsed_path == '/api/operations/hypothesis/delete':
                    rid = str(payload.get('run_id', '')).strip()
                    facts = workspace.brief(rid).get('facts', []) if len(rid) == 32 else []
                    result = workspace.operations.delete_hypothesis(str(payload.get('id', '')), rid, facts)
                elif analysis_path:
                    run_id = path_parts[3]
                    if len(run_id) != 32 or any(c not in '0123456789abcdef' for c in run_id):
                        raise ValueError('Invalid investigation ID.')
                    result = workspace.analyze(run_id, payload.get('mode'), payload.get('providers'))
                else:
                    result = workspace.launch(payload)
            except (ValueError, RuntimeError, UnicodeError, sa.exc.NoResultFound) as exc:
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
    # Terminate any stale NEESHA server process holding this port before binding.
    import signal
    import subprocess
    try:
        out = subprocess.check_output(['lsof', '-ti', f'tcp:{port}', '-sTCP:LISTEN'], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            pid = int(line.strip())
            if pid != os.getpid():
                cmd_out = subprocess.check_output(['ps', '-p', str(pid), '-o', 'command='], text=True, stderr=subprocess.DEVNULL)
                if any(tok in cmd_out.lower() for tok in ('neesha', 'find3r')):
                    os.kill(pid, signal.SIGTERM)
        time.sleep(0.2)
    except Exception:
        pass
    ledger = Ledger(engine)
    if ledger.summary().cap_usd == 0:
        ledger.set_cap(Decimal('100.00'))
    workspace = Workspace(engine)
    # Reports hold personal data and are not encrypted at rest: keep the tree
    # owner-only so other local users cannot read exported briefings.
    from neesha.config import harden_path
    if workspace.reports_root.exists():
        harden_path(workspace.reports_root)
    cat = workspace._catalog(force=True)
    ready_names = [s['name'] for s in cat if s.get('ready')]
    server = ThreadingHTTPServer(('127.0.0.1', port), make_handler(workspace))
    print(f'Find3r workspace: http://127.0.0.1:{server.server_port} ({len(ready_names)}/{len(cat)} sources ready) (Ctrl-C to stop)', flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
