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
    server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(workspace))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_port

    def request(path, method='GET', payload=None, headers=None):
        conn = HTTPConnection('127.0.0.1', port, timeout=5)
        body = json.dumps(payload) if payload is not None else None
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        data = response.read()
        result = (response.status, dict(response.getheaders()), data)
        conn.close()
        return result

    yield request, f'http://127.0.0.1:{port}'
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


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
    status, _, body = request('/api/resolve','POST', {'seed':'Dana Example','kind':'person'},headers)
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
