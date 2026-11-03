"""Workspace API and collector integration, without external traffic."""
import json
import threading
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer

import pytest

from neesha.console.server import Workspace, canonical_domain, make_handler
from neesha.db import schema


@pytest.mark.parametrize('value,expected', [
    ('Example.COM.', 'example.com'),
    ('https://example.com/about?q=1', 'example.com'),
    ('https://bücher.de', 'xn--bcher-kva.de'),
])
def test_domain_normalization(value, expected):
    assert canonical_domain(value) == expected


@pytest.mark.parametrize('value', ['127.0.0.1', 'https://127.0.0.1', 'person@example.com',
    'https://user:pass@example.com', '../etc/passwd', '', '-bad.example',
    'example.com/path', 'ftp://example.com', '<script>.com'])
def test_invalid_or_unsupported_seeds_are_rejected(value):
    with pytest.raises(ValueError):
        canonical_domain(value)


@pytest.fixture
def workspace(engine, tmp_path):
    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        conn.execute(schema.engagement.insert().values(
            id='authorized', authority_basis='prospect_company',
            authorized_domains=['example.com'], permitted_techniques=[],
            authorized_by='test-analyst', starts_at=now-timedelta(days=1),
            expires_at=now+timedelta(days=1), created_at=now,
        ))
    return Workspace(engine, sources={'crt.sh'}, profile_path=tmp_path / 'service-profile.json',
                     reports_root=tmp_path / 'reports')


@pytest.fixture
def client(workspace):
    import socket

    handler_cls = make_handler(workspace)

    class _DummyServer:
        server_port = 8765
        server_name = '127.0.0.1'

    dummy_server = _DummyServer()

    def request(path, method='GET', payload=None, headers=None):
        s_client, s_server = socket.socketpair()
        req_headers = {'Host': f'127.0.0.1:{dummy_server.server_port}'}
        if headers:
            req_headers.update(headers)

        def _serve_one():
            try:
                handler_cls(s_server, ('127.0.0.1', 0), dummy_server)
            finally:
                s_server.close()

        t = threading.Thread(target=_serve_one, daemon=True)
        t.start()
        conn = HTTPConnection('127.0.0.1', dummy_server.server_port, timeout=5)
        conn.sock = s_client
        body = json.dumps(payload) if payload is not None else None
        conn.request(method, path, body=body, headers=req_headers)
        response = conn.getresponse()
        data = response.read()
        result = (response.status, dict(response.getheaders()), data)
        conn.close()
        t.join(timeout=2)
        return result

    yield request, f'http://127.0.0.1:{dummy_server.server_port}'


def test_workspace_serves_local_assets_and_real_snapshot(client):
    request, _ = client
    for path in ('/', '/app.js', '/style.css'):
        status, headers, body = request(path)
        assert status == 200
        assert body
        assert "frame-ancestors 'none'" in headers['Content-Security-Policy']
        assert headers['Cache-Control'] == 'no-store'
    status, _, body = request('/api/workspace')
    assert status == 200
    data = json.loads(body)
    assert data['runs'] == []
    assert 'engagements' not in data


def test_host_allowlist_and_post_session_gate(client, workspace):
    request, origin = client
    assert request('/api/session', headers={'Host': 'evil.example'})[0] == 403
    payload = {'domain': 'example.com', 'engagement_id': 'authorized'}
    assert request('/api/investigations', 'POST', payload)[0] == 403
    assert request('/api/investigations', 'POST', payload,
        {'Origin': 'https://evil.example', 'X-Workspace-Token': workspace.token})[0] == 403
    assert request('/api/investigations', 'POST', payload,
        {'Origin': origin, 'X-Workspace-Token': 'wrong'})[0] == 403
    assert workspace.job['state'] == 'idle'


def test_investigation_reaches_guarded_brief(workspace, monkeypatch):
    monkeypatch.setattr('neesha.adapters.crtsh.http_get', lambda *a, **kw: json.dumps([
        {'name_value': 'mail.example.com', 'issuer_name': 'Example CA'}
    ]))
    # Exercise the worker synchronously, then the same read path as the UI.
    from neesha.harness.gate import EngagementView
    now = datetime.now(timezone.utc)
    engagement = EngagementView('authorized', 'prospect_company',
        authorized_domains=('example.com',), starts_at=now-timedelta(days=1),
        expires_at=now+timedelta(days=1))
    workspace._run('example.com', engagement, False)
    assert workspace.job['state'] == 'complete'
    from neesha.harness.brief import build_brief
    brief = build_brief(workspace.engine, workspace.job['run_id'])
    assert any(f['value'] == 'mail.example.com' for f in brief['facts'])
    assert all(f['source_record_id'] for f in brief['facts'])
    assert workspace.snapshot()['runs'][0]['company'] == 'example.com'


def test_unsafe_run_paths_are_not_filesystem_reads(client):
    request, _ = client
    for path in ('/api/runs/../../secret', '/style.css/../secret', '/.env'):
        assert request(path)[0] == 404


def test_launch_api_completes_without_blocking_the_server(client, workspace, monkeypatch):
    request, origin = client
    monkeypatch.setattr('neesha.adapters.crtsh.http_get', lambda *a, **kw: json.dumps([
        {'name_value': 'mail.example.com', 'issuer_name': 'Example CA'}]))
    done = threading.Event()
    original = workspace._run

    def run(*args):
        try:
            original(*args)
        finally:
            done.set()
    monkeypatch.setattr(workspace, '_run', run)
    status, _, _ = request('/api/investigations', 'POST',
        {'domain': 'example.com'},
        {'Origin': origin, 'X-Workspace-Token': workspace.token})
    assert status == 202
    assert done.wait(5)
    assert workspace.job['state'] == 'complete'
    status, _, body = request('/api/runs/' + workspace.job['run_id'])
    assert status == 200
    assert json.loads(body)['facts']
    import sqlalchemy as sa
    with workspace.engine.connect() as conn:
        context = conn.execute(sa.select(schema.engagement).where(
            schema.engagement.c.id != 'authorized')).mappings().one()
    assert context['authority_basis'] == 'prospect_company'
    assert context['authorized_domains'] == ['example.com']
    assert context['permitted_techniques'] == []


def test_free_pipeline_collects_contacts_roles_and_posture_without_hunter(
    workspace, monkeypatch
):
    from neesha.adapters import registry
    from neesha.adapters.base import RawResult
    from neesha.harness.gate import EngagementView
    from neesha.harness.brief import build_brief

    monkeypatch.delenv('HUNTER_API_KEY', raising=False)
    domain = 'example.com'
    payloads = {
        'company-web': {'domain':domain,'pages':[{'url':'https://example.com/contact',
            'status':200,'tls_validated':True,'security_headers':{'x-content-type-options':'nosniff'},
            'html':'<a href="mailto:info@example.com">Email</a><a href="tel:+12125550123">Call</a>'
                '<script type="application/ld+json">'+json.dumps({
                    '@type':'Person','name':'Dana Example','jobTitle':'Head of IT',
                    'email':'dana@example.com','worksFor':{'url':'https://example.com'}})+'</script>'}]},
        'dns-posture': [
            {'name':domain,'type':'A','status':'ok','records':['93.184.215.14']},
            {'name':domain,'type':'MX','status':'ok','records':['10 mail.example.com']},
            {'name':domain,'type':'TXT','status':'ok','records':['v=spf1 -all']},
            {'name':'_dmarc.'+domain,'type':'TXT','status':'ok','records':['v=DMARC1; p=reject']}],
        'otx': {'passive_dns':[{'hostname':'mail.example.com','address':'93.184.215.14'}]},
        'wayback': [['timestamp','original'],['20261031120000','https://old.example.com/about']],
        'urlscan': {'results':[{'page':{'url':'https://app.example.com/'}}]},
    }
    for name, payload in payloads.items():
        def fetch(self, reference, payload=payload):
            return RawResult(payload=json.dumps(payload).encode(), request_url=reference.url,
                             origin_url=reference.origin_url)
        monkeypatch.setattr(registry.get(name), 'fetch', fetch)
    monkeypatch.setattr('neesha.adapters.crtsh.http_get', lambda *a, **kw: json.dumps([
        {'name_value':'mail.example.com','issuer_name':'Example CA'}]))
    workspace.sources = set(payloads) | {'crt.sh'}
    now = datetime.now(timezone.utc)
    engagement = EngagementView('authorized','prospect_company',authorized_domains=(domain,),
        starts_at=now-timedelta(days=1),expires_at=now+timedelta(days=1))
    workspace._run(domain,engagement,False)
    assert workspace.job['state'] == 'complete'
    brief = build_brief(workspace.engine,workspace.job['run_id'])
    by_attr = {}
    for fact in brief['facts']:
        by_attr.setdefault(fact['attribute'],set()).add(fact['value'])
    assert 'info@example.com' in by_attr['company.business_email']
    assert '+12125550123' in by_attr['company.business_phone']
    assert 'Head of IT' in by_attr['person.role']
    assert 'dana@example.com' in by_attr['person.business_email']
    assert 'reject' in by_attr['email.dmarc.policy']
    assert by_attr['dns.subdomain'] >= {'mail.example.com','old.example.com','app.example.com'}
    assert {c['source'] for c in brief['collection']} == workspace.sources
    assert all(c['outcome']=='observations' for c in brief['collection'])
    assert 'hunter' not in {c['source'] for c in brief['collection']}


def test_resolver_distinguishes_domain_candidate_from_person_identity(client, workspace):
    request, origin = client
    headers = {'Origin':origin,'X-Workspace-Token':workspace.token}
    status, _, body = request('/api/resolve','POST', {'seed':'dana@example.com'},headers)
    assert status == 202
    result=json.loads(body)
    assert result['domain'] is None
    assert result['candidate_domains']==['example.com']
    assert result['requires_resolution'] is False
    assert result['domain_is_candidate'] is True
    status, _, body = request('/api/resolve','POST', {'seed':'Dana Example','kind':'name'},headers)
    assert status==202
    assert json.loads(body)['requires_resolution'] is True


def test_service_profile_api_validates_and_keeps_storage_local(client, workspace):
    request, origin=client
    headers={'Origin':origin,'X-Workspace-Token':workspace.token}
    assert request('/api/profile','POST',{'api_key':'secret'},headers)[0]==400
    profile={'name':'Configured services','services':['Email security'],'criteria':[
        {'id':'monitoring-policy','service':'Email security','attribute':'email.dmarc.policy',
         'equals':'none','weight':3}]}
    assert request('/api/profile','POST',profile,headers)[0]==202
    assert workspace.profile_path.exists()
    assert json.loads(request('/api/profile')[2])['profile']==profile


def test_analysis_endpoint_fails_closed_without_runtime_credentials(client, workspace, monkeypatch):
    from neesha.harness.gate import EngagementView
    now=datetime.now(timezone.utc)
    monkeypatch.setattr('neesha.adapters.crtsh.http_get',lambda *a,**kw:json.dumps([
        {'name_value':'mail.example.com','issuer_name':'Example CA'}]))
    workspace._run('example.com',EngagementView('authorized','prospect_company',
        authorized_domains=('example.com',),starts_at=now-timedelta(days=1),
        expires_at=now+timedelta(days=1)),False)
    for key in ('OPENAI_API_KEY','ANTHROPIC_API_KEY','GEMINI_API_KEY','DEEPSEEK_API_KEY'):
        monkeypatch.delenv(key,raising=False)
    request,origin=client
    status,_,body=request('/api/runs/'+workspace.job['run_id']+'/analysis','POST',
        {'mode':'single','providers':['openai']},
        {'Origin':origin,'X-Workspace-Token':workspace.token})
    assert status==400
    assert 'explicit model and API key' in json.loads(body)['error']
    snapshot=json.loads(request('/api/workspace')[2])
    assert len(snapshot['runtime_providers'])==4
    assert not any(p['ready'] for p in snapshot['runtime_providers'])


def test_new_brief_exposes_scores_graph_and_retrieval_provenance(workspace,monkeypatch):
    from neesha.harness.gate import EngagementView
    now=datetime.now(timezone.utc)
    monkeypatch.setattr('neesha.adapters.crtsh.http_get',lambda *a,**kw:json.dumps([
        {'name_value':'mail.example.com','issuer_name':'Example CA'}]))
    workspace._run('example.com',EngagementView('authorized','prospect_company',
        authorized_domains=('example.com',),starts_at=now-timedelta(days=1),
        expires_at=now+timedelta(days=1)),False)
    result=workspace.brief(workspace.job['run_id'])
    assert result['graph']['edges']
    assert result['scores']['commercial_fit']['score'] is None
    assert result['scores']['security_needs']['score'] is None
    assert all(f['retrieved_by'] and f['analyst'] for f in result['facts'])


def test_delete_api_requires_session_and_removes_selected_run(client, workspace, monkeypatch):
    from neesha.harness.gate import EngagementView
    now=datetime.now(timezone.utc)
    monkeypatch.setattr('neesha.adapters.crtsh.http_get',lambda *a,**kw:json.dumps([
        {'name_value':'mail.example.com','issuer_name':'Example CA'}]))
    workspace._run('example.com',EngagementView('authorized','prospect_company',
        authorized_domains=('example.com',),starts_at=now-timedelta(days=1),
        expires_at=now+timedelta(days=1)),False)
    path='/api/runs/'+workspace.job['run_id']
    request,origin=client
    assert request(path,'DELETE')[0]==403
    headers={'Origin':origin,'X-Workspace-Token':workspace.token}
    assert request('/api/runs/../secret','DELETE',headers=headers)[0]==404
    status,_,body=request(path,'DELETE',headers=headers)
    assert status==200 and json.loads(body)['deleted'] is True
    assert request(path)[0]==404
    assert request('/api/workspace')[0]==200


def test_auto_analysis_configuration_is_validated_before_collection(client, workspace, monkeypatch):
    monkeypatch.delenv('OPENAI_API_KEY',raising=False)
    request,origin=client
    status,_,body=request('/api/investigations','POST',
        {'seed':'example.com','analysis_mode':'single','providers':['openai']},
        {'Origin':origin,'X-Workspace-Token':workspace.token})
    assert status==400 and 'API key' in json.loads(body)['error']
    assert workspace.job['state']=='idle'


def test_analysis_is_persisted_and_removed_with_run(workspace, monkeypatch):
    from neesha.harness.gate import EngagementView
    now=datetime.now(timezone.utc)
    monkeypatch.setattr('neesha.adapters.crtsh.http_get',lambda *a,**kw:json.dumps([
        {'name_value':'mail.example.com','issuer_name':'Example CA'}]))
    monkeypatch.setattr('neesha.runtime.investigation.analyze_brief',
        lambda *a,**kw: {'status':'complete','claims':[], 'mode':'single'})
    workspace._run('example.com',EngagementView('authorized','prospect_company',
        authorized_domains=('example.com',),starts_at=now-timedelta(days=1),
        expires_at=now+timedelta(days=1)),False,True,'domain','single',['openai'])
    run_id=workspace.job['run_id']
    assert workspace.job['analysis_status']=='complete'
    assert workspace.brief(run_id)['model_analysis']['status']=='complete'
    path=workspace._analysis_path(run_id)
    assert path.exists()
    workspace.delete(run_id)
    assert not path.exists()


def test_gmail_api_runs_exact_email_sources_without_company_association(client, workspace, monkeypatch):
    from neesha.adapters import registry
    from neesha.adapters.base import RawResult
    from neesha.runtime.investigation import _safe_facts
    import sqlalchemy as sa
    email='Example.User+case@gmail.com'
    workspace.sources={'github-email','gravatar'}
    payloads={
        'github-email':{'email':email,'matches':[{'commit_url':'https://github.com/example/repo/commit/'+'a'*40,
                                               'author_name':'Example User'}]},
        'gravatar':{'email':email,'profile':{'url':'https://gravatar.com/example','display_name':'Example User'}}}
    for name,payload in payloads.items():
        monkeypatch.setattr(registry.get(name),'fetch',lambda self,ref,payload=payload:
                            RawResult(json.dumps(payload).encode(),ref.url,ref.origin_url,http_status=200))
    done=threading.Event()
    original=workspace._run
    def run(*args):
        try: original(*args)
        finally: done.set()
    monkeypatch.setattr(workspace,'_run',run)
    request,origin=client
    status,_,body=request('/api/investigations','POST',{'seed':email},
        {'Origin':origin,'X-Workspace-Token':workspace.token})
    assert status==202 and done.wait(5)
    assert workspace.job['state']=='complete'
    brief=workspace.brief(workspace.job['run_id'])
    assert brief['subject_kind']=='email' and brief['seed']['normalized']==email
    assert len(brief['facts'])==4
    assert all(f['subject']==email and f['sensitivity']=='personal' for f in brief['facts'])
    assert len(_safe_facts(brief)[0])==4
    assert {s['source'] for s in brief['collection']}==workspace.sources
    assert not any(n['kind']=='organization' for n in brief['graph']['nodes'])
    with workspace.engine.connect() as conn:
        context=conn.execute(sa.select(schema.engagement).where(schema.engagement.c.authority_basis=='public_research')).mappings().one()
        assert context['authorized_domains']==[] and context['authorized_emails']==[email]
        assert not conn.execute(sa.select(schema.entity).where(schema.entity.c.canonical_name=='gmail.com')).first()


def test_local_ollama_and_manually_installed_models(client, workspace, monkeypatch, tmp_path):
    from neesha.runtime import ollama as ollama_mod
    from neesha.runtime.investigation import analyze_brief
    # Simulate offline manually installed models in ~/.ollama/models/manifests
    manifest_file = tmp_path / 'manifests' / 'registry.ollama.ai' / 'library' / 'custom-osint' / 'latest'
    manifest_file.parent.mkdir(parents=True)
    manifest_file.write_text('{}')
    hf_manifest = tmp_path / 'manifests' / 'hf.co' / 'sec-team' / 'osint-gguf' / 'Q4_K_M'
    hf_manifest.parent.mkdir(parents=True)
    hf_manifest.write_text('{}')
    monkeypatch.setenv('OLLAMA_MODELS', str(tmp_path))
    monkeypatch.setattr(ollama_mod, 'find_tool_binary', lambda name: '/usr/local/bin/ollama')

    # Verify offline manifest scanner picks up manual models when HTTP tags are empty
    scanned = ollama_mod._scan_offline_manifests()
    scanned_ids = [m['id'] for m in scanned]
    assert 'custom-osint:latest' in scanned_ids
    assert 'hf.co/sec-team/osint-gguf:Q4_K_M' in scanned_ids

    monkeypatch.setattr(ollama_mod, 'list_installed_models', lambda *a, **kw: (True, scanned))
    request, origin = client
    headers = {'Origin': origin, 'X-Workspace-Token': workspace.token}

    # Custom/manual model tag with slash namespace can be selected via API
    st, _, body = request('/api/ollama/select', 'POST', {'model': 'hf.co/sec-team/osint-gguf:Q4_K_M'}, headers)
    assert st == 202
    data = json.loads(body)
    assert data['selected_model'] == 'hf.co/sec-team/osint-gguf:Q4_K_M'
    # Manually installed models appear first in catalog
    catalog_ids = [c['id'] for c in data['catalog']]
    assert catalog_ids[0] in ('custom-osint:latest', 'hf.co/sec-team/osint-gguf:Q4_K_M')

    # Import a local .gguf file directly through the platform API (/api/ollama/create)
    gguf_file = tmp_path / 'my-weights.gguf'
    gguf_file.write_bytes(b'GGUF')
    monkeypatch.setattr(ollama_mod, 'ensure_ollama_running', lambda **kw: True)
    class DummyProc:
        returncode = 0
        stdout = 'success'
    monkeypatch.setattr(ollama_mod.subprocess, 'run', lambda *a, **kw: DummyProc())
    st_create, _, body_create = request('/api/ollama/create', 'POST', {
        'name': 'imported-osint',
        'source': str(gguf_file),
    }, headers)
    assert st_create == 202
    created_data = json.loads(body_create)
    assert created_data['selected_model'] == 'imported-osint:latest'
    assert created_data['created_model'] == 'imported-osint:latest'

    # Run $0.00 synthesis with manually installed model
    monkeypatch.setattr('neesha.runtime.investigation.generate_ollama',
        lambda *a, **kw: '<think>reasoning</think>{"claims":[{"text":"Example DNS resolves","evidence_ids":["f1"]}]}')
    brief = {
        'subject_kind': 'domain',
        'seed': {'input': 'example.com', 'normalized': 'example.com'},
        'facts': [{'fact_id': 'f1', 'source_record_id': 's1', 'subject': 'example.com', 'attribute': 'dns.a', 'value': '93.184.216.34', 'sensitivity': 'business'}],
    }
    res = analyze_brief(workspace.engine, brief, 'single', ['ollama:hf.co/sec-team/osint-gguf:Q4_K_M'])
    assert res['status'] == 'complete'
    assert res['spend_usd'] == '0'
    assert len(res['claims']) == 1
    assert res['claims'][0]['retrieved_by']['model'] == 'hf.co/sec-team/osint-gguf:Q4_K_M'


def test_geo_map_shodan_enrichment_and_maltego_exports(client, workspace, monkeypatch):
    from neesha.adapters.base import RawResult, Request
    from neesha.adapters.internetdb import InternetDbAdapter
    from neesha.harness.gate import EngagementView
    from neesha.harness.mapping import build_geo_map, build_maltego_csv, build_maltego_graphml, build_maltego_transform_xml

    # 1. Verify Shodan + InternetDB Geo-IP extraction
    adapter = InternetDbAdapter()
    raw = RawResult(
        json.dumps({
            'ip': '104.16.132.229',
            'ports': [443, 8443],
            'hostnames': ['edge.example.com'],
            'vulns': ['CVE-2024-9999'],
            'country_code': 'DE',
            'city': 'Frankfurt',
            'latitude': 50.1109,
            'longitude': 8.6821,
            'asn': 'AS13335',
            'org': 'Cloudflare, Inc.',
            'isp': 'Cloudflare',
        }).encode(),
        'https://internetdb.shodan.io/104.16.132.229',
        http_status=200,
    )
    drafts = adapter.parse(raw, Request('ip', '104.16.132.229'))
    by_attr = {(d.attribute, d.value) for d in drafts}
    assert ('host.country', 'DE') in by_attr
    assert ('host.city', 'Frankfurt') in by_attr
    assert ('host.latitude', '50.1109') in by_attr
    assert ('host.longitude', '8.6821') in by_attr
    assert ('host.asn', 'AS13335') in by_attr

    # 2. Verify build_geo_map plots multiple nodes, arcs, and summaries
    sample_facts = [
        {'fact_id': 'f1', 'subject': 'example.com', 'attribute': 'dns.a', 'value': '104.16.132.229'},
        {'fact_id': 'f2', 'subject': '104.16.132.229', 'attribute': 'host.country', 'value': 'DE'},
        {'fact_id': 'f3', 'subject': '104.16.132.229', 'attribute': 'host.city', 'value': 'Frankfurt'},
        {'fact_id': 'f4', 'subject': '104.16.132.229', 'attribute': 'host.latitude', 'value': '50.1109'},
        {'fact_id': 'f5', 'subject': '104.16.132.229', 'attribute': 'host.longitude', 'value': '8.6821'},
        {'fact_id': 'f6', 'subject': '104.16.132.229', 'attribute': 'host.port', 'value': '443'},
        {'fact_id': 'f7', 'subject': '104.16.132.229', 'attribute': 'host.vuln', 'value': 'CVE-2024-9999'},
        {'fact_id': 'f8', 'subject': 'api.example.com', 'attribute': 'dns.a', 'value': '52.1.2.3'},
    ]
    geo = build_geo_map('example.com', sample_facts, 'domain')
    assert geo['summary']['total_nodes'] == 2
    assert geo['summary']['vulnerable_nodes_count'] == 1
    assert len(geo['arcs']) == 1
    xml_out = build_maltego_transform_xml(sample_facts)
    assert '<MaltegoTransformResponseMessage>' in xml_out
    assert 'maltego.IPv4Address' in xml_out

    # 3. Verify brief geo_map and Maltego HTTP export endpoints
    now = datetime.now(timezone.utc)
    monkeypatch.setattr('neesha.adapters.crtsh.http_get', lambda *a, **kw: json.dumps([
        {'name_value': 'mail.example.com', 'issuer_name': 'Example CA'}]))
    workspace._run('example.com', EngagementView('authorized', 'prospect_company',
        authorized_domains=('example.com',), starts_at=now - timedelta(days=1),
        expires_at=now + timedelta(days=1)), False)
    run_id = workspace.job['run_id']
    request, _ = client
    st_g, _, body_g = request(f'/api/runs/{run_id}/maltego.graphml')
    assert st_g == 200
    g_data = json.loads(body_g)
    assert 'maltego.DNSName' in g_data['content']
    st_c, _, body_c = request(f'/api/runs/{run_id}/maltego.csv')
    assert st_c == 200
    c_data = json.loads(body_c)
    assert 'Source Entity Type' in c_data['content']


def test_hardening_geo_hints_xml_escape_and_ollama_import(engine, monkeypatch):
    import pytest
    from neesha.harness.mapping import _xml_escape, build_geo_map
    from neesha.runtime.investigation import RuntimeAnalysisError, analyze_brief
    from neesha.runtime.ollama import create_custom_ollama_model

    # 1. _xml_escape strips XML 1.0 control chars and escapes quotes
    escaped = _xml_escape('test\x00\x07"quote"\'single\'<&>')
    assert '\x00' not in escaped and '\x07' not in escaped
    assert '&quot;quote&quot;' in escaped and '&apos;single&apos;' in escaped

    # 2. KNOWN_NETWORK_HINTS takes precedence over domain whois.country
    geo = build_geo_map('example.com', [
        {'fact_id': 'f1', 'subject': 'example.com', 'attribute': 'whois.country', 'value': 'US'},
        {'fact_id': 'f2', 'subject': 'example.com', 'attribute': 'dns.a', 'value': '1.1.1.1'},
    ], 'domain')
    assert geo['points'][0]['country'] == 'AU'
    assert geo['points'][0]['org'] == 'Cloudflare DNS'

    # 3. create_custom_ollama_model rejects quotes and non-weights files safely
    monkeypatch.setattr('neesha.runtime.ollama.find_tool_binary', lambda name: '/usr/local/bin/ollama')
    monkeypatch.setattr('neesha.runtime.ollama.ensure_ollama_running', lambda **kw: True)
    with pytest.raises(ValueError, match='valid local'):
        create_custom_ollama_model('bad:latest', '/tmp/evil"quote.gguf')
    with pytest.raises(ValueError, match='weights file or a Modelfile'):
        create_custom_ollama_model('bad:latest', '/etc/passwd')

    # 4. Canonical duplicate Ollama provider detection in multi mode
    monkeypatch.setenv('NEESHA_OLLAMA_MODEL', 'llama3.1:8b')
    with pytest.raises(RuntimeAnalysisError, match='distinct providers'):
        analyze_brief(engine, {'facts': []}, 'multi', ['ollama', 'ollama:llama3.1:8b'])



