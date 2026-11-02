import json
import socket
import time

import pytest

from neesha.adapters.base import AdapterError, RawResult, Request
from neesha.adapters.company_web import CompanyWebAdapter, MAX_BYTES, _public_addresses, safe_fetch


def test_published_contacts_and_structured_roles_no_generated_emails():
    html = '''<p>Sales: sales@acme.com. Personal: somebody@gmail.com.</p>
    <a href="mailto:support@acme.com?subject=hello">Support</a>
    <a href="tel:+1-212-555-0199">Telephone</a>
    <script>const hidden = "hidden@acme.com";</script>
    <script type="application/ld+json">{"@type":"Person","name":"Dana Ops",
      "jobTitle":"Head of IT","email":"dana@acme.com","telephone":"+1 212 555 0123"}</script>
    <p>Jane Example — perhaps the buyer?</p>'''
    raw = RawResult(json.dumps({'pages': [{'url':'https://acme.com/team', 'html':html}]}).encode(), 'https://acme.com/')
    facts = CompanyWebAdapter().parse(raw, Request('domain', 'acme.com'))
    assert {(f.attribute,f.value) for f in facts if f.entity_kind == 'company'} >= {
        ('company.business_email','sales@acme.com'), ('company.business_email','support@acme.com'),
        ('company.business_phone','+1-212-555-0199'), ('company.contact_page','https://acme.com/team')}
    people = [f for f in facts if f.entity_kind == 'person']
    assert {f.entity_name for f in people} == {'Dana Ops'}
    assert ('person.role','Head of IT') in {(f.attribute,f.value) for f in people}
    assert ('person.business_email','dana@acme.com') in {(f.attribute,f.value) for f in people}
    assert not any('gmail' in f.value or 'hidden@' in f.value or 'jane@' in f.value for f in facts)
    assert all(not f.is_inference for f in facts)


def test_company_site_fetch_is_bounded_and_same_company(monkeypatch):
    calls=[]
    def fetch(url,domain,deadline):
        calls.append(url)
        if url.endswith('/'):
            return url, '<a href="/team">Team</a><a href="/contact">Contact</a><a href="https://evil.example/team">Other</a><a href="/news">News</a>', {}
        return url, '<a href="mailto:business@acme.com">Email</a>', {}
    monkeypatch.setattr('neesha.adapters.company_web.safe_fetch', fetch)
    adapter = CompanyWebAdapter()
    result = adapter.fetch(adapter.search(Request('domain','acme.com'))[0])
    assert calls == ['https://acme.com/','https://acme.com/team','https://acme.com/contact']
    assert adapter.collection_mode == 'direct_contact'
    assert adapter.tier == 'A'
    assert any(f.value=='business@acme.com' for f in adapter.parse(result, Request('domain','acme.com')))


@pytest.mark.parametrize('ip',['127.0.0.1','10.0.0.1','169.254.169.254','::1','fe80::1','192.0.2.1'])
def test_private_and_reserved_addresses_are_blocked(monkeypatch,ip):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**kw:[(0,0,0,'',(ip,443))])
    with pytest.raises(AdapterError,match='non-public'):
        _public_addresses('acme.com',443)


def test_mixed_public_and_private_dns_is_blocked(monkeypatch):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**kw:[(0,0,0,'',('93.184.216.34',443)),(0,0,0,'',('127.0.0.1',443))])
    with pytest.raises(AdapterError,match='non-public'):
        _public_addresses('acme.com',443)


class Response:
    status = 200
    body = b'<html>hello</html>'
    headers = {'Content-Type':'text/html'}
    def getheader(self,key,default=None):
        return self.headers.get(key,default)
    def read(self,count):
        return self.body[:count]


class Connection:
    calls=[]
    responses=[]
    def __init__(self,host,port,address,timeout):
        self.calls.append((host,port,address,timeout))
    def request(self,*a,**kw):
        pass
    def getresponse(self):
        return self.responses.pop(0)
    def close(self):
        pass


@pytest.fixture
def network(monkeypatch):
    Connection.calls=[]
    Connection.responses=[]
    monkeypatch.setattr('neesha.adapters.company_web._PinnedHTTPS',Connection)
    monkeypatch.setattr('neesha.adapters.company_web._PinnedHTTP',Connection)
    monkeypatch.setattr('neesha.adapters.company_web._public_addresses',lambda *a:['93.184.216.34'])
    return Connection


@pytest.mark.parametrize('location',['http://127.0.0.1/admin','http://169.254.169.254/latest/meta-data/','https://unrelated.example/team','file:///etc/passwd'])
def test_out_of_scope_redirect_never_connects(network,location):
    redirect=Response()
    redirect.status=302
    redirect.headers={'Location':location}
    network.responses=[redirect]
    with pytest.raises(AdapterError,match='scope'):
        safe_fetch('https://acme.com/','acme.com',deadline=time.monotonic()+30)
    assert len(network.calls)==1


def test_same_host_redirect_rechecks_dns_and_pins_public_address(network,monkeypatch):
    redirect=Response()
    redirect.status=302
    redirect.headers={'Location':'/team'}
    network.responses=[redirect,Response()]
    lookups=[]
    def addresses(host,port):
        lookups.append(host)
        if len(lookups)>1:
            raise AdapterError('Private or non-public website addresses were blocked.')
        return ['93.184.216.34']
    monkeypatch.setattr('neesha.adapters.company_web._public_addresses',addresses)
    with pytest.raises(AdapterError,match='non-public'):
        safe_fetch('https://acme.com/','acme.com',deadline=time.monotonic()+30)
    assert lookups == ['acme.com','acme.com']
    assert network.calls[0][2]=='93.184.216.34'
    assert len(network.calls)==1


def test_oversize_html_is_rejected(network):
    response=Response()
    response.body=b'x'*(MAX_BYTES+1)
    network.responses=[response]
    with pytest.raises(AdapterError,match='size limit'):
        safe_fetch('https://acme.com/','acme.com',deadline=time.monotonic()+30)


def test_names_without_structured_roles_are_not_invented():
    raw=RawResult(json.dumps({'pages':[{'url':'https://acme.com','html':'<h2>Dana Ops</h2><p>CEO</p>'}]}).encode(),'https://acme.com')
    assert not CompanyWebAdapter().parse(raw,Request('domain','acme.com'))


def test_external_speaker_is_not_attached_as_an_employee():
    raw=RawResult(json.dumps({'pages':[{'url':'https://acme.com/events', 'html':
        '<script type="application/ld+json">{"@type":"Person","name":"Guest Speaker",'
        '"jobTitle":"CTO","email":"guest@othercorp.com"}</script>'}]}).encode(),'https://acme.com')
    assert not CompanyWebAdapter().parse(raw,Request('domain','acme.com'))


def test_explicit_employer_supports_role_without_email():
    raw=RawResult(json.dumps({'pages':[{'url':'https://acme.com/team', 'html':
        '<script type="application/ld+json">{"@type":"Person","name":"Dana Ops",'
        '"jobTitle":"CTO","worksFor":{"@type":"Organization","url":"https://acme.com"}}</script>'}]}).encode(),'https://acme.com')
    assert any(f.attribute=='person.role' for f in CompanyWebAdapter().parse(raw,Request('domain','acme.com')))


def test_actual_http_headers_status_and_tls_are_preserved(network):
    response=Response()
    response.headers={'Content-Type':'text/html','x-frame-options':'DENY'}
    network.responses=[response]
    url,body,metadata=safe_fetch('https://acme.com/','acme.com',deadline=time.monotonic()+30)
    raw=RawResult(json.dumps({'pages':[{'url':url,'html':body,**metadata}]}).encode(),url)
    facts=CompanyWebAdapter().parse(raw,Request('domain','acme.com'))
    values={(f.attribute,f.value) for f in facts}
    assert ('http.status','200') in values
    assert ('http.security_header.x-frame-options','DENY') in values
    assert ('tls.connection.validated','true') in values
    assert not any(f.attribute=='http.security_header.content-security-policy' for f in facts)
