"""Typed DNS and urlscan integration tests; no DNS or HTTP leaves the process."""
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from neesha.adapters.base import AdapterError, RawResult, Request
from neesha.adapters.dns_posture import DnsPostureAdapter
from neesha.adapters.urlscan import UrlscanAdapter
from neesha.resolvers.dns import QueryResult, Record


def raw(value):
    return RawResult(json.dumps(value).encode(), 'https://source.example/')


def test_dns_fetch_queries_expected_records_and_preserves_success(monkeypatch):
    calls=[]
    def query(self,name,rtype):
        calls.append((name,rtype))
        if rtype=='A':
            return QueryResult(name,rtype,'system','ok',[Record(rtype,'203.0.113.10')])
        return QueryResult(name,rtype,'system','noerror-nodata')
    monkeypatch.setattr('neesha.adapters.dns_posture.SystemResolver.query',query)
    adapter=DnsPostureAdapter()
    request=Request('domain','acme.com')
    facts=adapter.parse(adapter.fetch(adapter.search(request)[0]),request)
    assert calls==[('acme.com',t) for t in ('A','AAAA','MX','NS','CAA','TXT')]+[('_dmarc.acme.com','TXT')]
    assert [(f.attribute,f.value) for f in facts]==[('dns.a','203.0.113.10')]


@pytest.mark.parametrize('status',['nxdomain','noerror-nodata'])
def test_dns_negative_answers_are_not_security_absence_claims(monkeypatch,status):
    monkeypatch.setattr('neesha.adapters.dns_posture.SystemResolver.query',lambda self,n,t:QueryResult(n,t,'system',status))
    adapter=DnsPostureAdapter()
    request=Request('domain','acme.com')
    assert adapter.parse(adapter.fetch(adapter.search(request)[0]),request)==[]


def test_dns_all_timeouts_are_a_collection_failure(monkeypatch):
    monkeypatch.setattr('neesha.adapters.dns_posture.SystemResolver.query',lambda self,n,t:QueryResult(n,t,'system','error',error='timeout'))
    adapter=DnsPostureAdapter()
    with pytest.raises(AdapterError,match='unknown'):
        adapter.fetch(adapter.search(Request('domain','acme.com'))[0])


def test_dns_txt_parses_valid_spf_dmarc_and_ignores_wrong_subject_or_failed_rows():
    facts=DnsPostureAdapter().parse(raw([
        {'name':'acme.com','type':'TXT','status':'ok','records':['other verification','v=spf1 include:mail.example -all']},
        {'name':'_dmarc.acme.com','type':'TXT','status':'ok','records':['v=DMARC1; p=reject; rua=mailto:dmarc@acme.com']},
        {'name':'other.example','type':'A','status':'ok','records':['192.0.2.5']},
        {'name':'acme.com','type':'A','status':'error','records':['198.51.100.5']},
        {'name':'acme.com','type':'NS','status':'ok','records':None},
    ]),Request('domain','acme.com'))
    assert {(f.attribute,f.value) for f in facts}=={
        ('email.spf.record','v=spf1 include:mail.example -all'),('email.spf.qualifier','-all'),
        ('email.dmarc.record','v=DMARC1; p=reject; rua=mailto:dmarc@acme.com'),('email.dmarc.policy','reject')}


@pytest.mark.parametrize('payload',[b'not-json',b'{}',b'null'])
def test_dns_malformed_top_level_payload_is_a_failure(payload):
    with pytest.raises(AdapterError):
        DnsPostureAdapter().parse(RawResult(payload,'dns://acme.com'),Request('domain','acme.com'))


def test_dns_conflicting_authentication_records_do_not_claim_enforcement():
    facts=DnsPostureAdapter().parse(raw([
        {'name':'acme.com','type':'TXT','status':'ok','records':['v=spf1 -all','v=spf1 +all']},
        {'name':'_dmarc.acme.com','type':'TXT','status':'ok','records':['v=DMARC1; p=reject','v=DMARC1; p=none']},
    ]),Request('domain','acme.com'))
    assert {f.value for f in facts}=={'v=spf1 -all','v=spf1 +all','v=DMARC1; p=reject','v=DMARC1; p=none'}
    assert not any(f.attribute in ('email.spf.qualifier','email.dmarc.policy') for f in facts)


def test_dns_invalid_authentication_versions_are_not_valid_controls():
    facts=DnsPostureAdapter().parse(raw([
        {'name':'acme.com','type':'TXT','status':'ok','records':['v=spf10 -all']},
        {'name':'_dmarc.acme.com','type':'TXT','status':'ok','records':['v=DMARC10; p=reject']},
    ]),Request('domain','acme.com'))
    assert facts==[]


@pytest.mark.parametrize('value',[{},[],{'results':None},{'results':{}},None])
def test_urlscan_malformed_response_is_a_collection_failure(value):
    with pytest.raises(AdapterError):
        UrlscanAdapter().parse(raw(value),Request('domain','acme.com'))


def test_urlscan_subject_scope_query_redaction_and_dedupe():
    facts=UrlscanAdapter().parse(raw({'results':[
        {'page':{'url':'https://vpn.acme.com/login?session=secret#token'}},
        {'page':{'url':'https://vpn.acme.com/login?session=another'}},
        {'page':{'url':'https://acme.com/'}},
        {'page':{'url':'https://acme.com.evil.example/'}},
        {'page':{'url':'https://other.example/'}},
        {'page':None}, None,
    ]}),Request('domain','acme.com'))
    assert {(f.attribute,f.value) for f in facts}=={
        ('dns.subdomain','vpn.acme.com'),('web.observed.url','https://vpn.acme.com/login'),
        ('web.observed.url','https://acme.com/')}
    assert all(f.entity_name=='acme.com' for f in facts)
    assert not any('secret' in f.value or 'session' in f.value for f in facts)


@pytest.mark.parametrize('url',[
    'https://user:password@vpn.acme.com/','https://vpn.acme.com:bad/',
    'https://vpn.acme.com:70000/','ftp://vpn.acme.com/file','file://vpn.acme.com/etc/passwd',
    'https://[broken/',
])
def test_urlscan_credentialed_and_malformed_urls_emit_no_facts(url):
    assert UrlscanAdapter().parse(raw({'results':[{'page':{'url':url}}]}),Request('domain','acme.com'))==[]


def test_urlscan_search_only_never_submits_scan(monkeypatch):
    calls=[]
    class Response:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read(self,count):
            assert count==2_000_001
            return b'{"results":[]}'
    def urlopen(request,**kwargs):
        calls.append((request.full_url,request.get_method(),kwargs['timeout']))
        return Response()
    monkeypatch.setattr('neesha.adapters.urlscan.urlopen',urlopen)
    adapter=UrlscanAdapter()
    reference=adapter.search(Request('domain','acme.com'))[0]
    result=adapter.fetch(reference)
    assert urlsplit(calls[0][0]).path=='/api/v1/search/'
    assert parse_qs(urlsplit(calls[0][0]).query)['q']==['domain:acme.com']
    assert calls[0][1:] == ('GET',12)
    assert adapter.parse(result,Request('domain','acme.com'))==[]


def test_urlscan_response_limit_and_provider_failure_are_explicit(monkeypatch):
    class Response:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read(self,count):return b'x'*count
    monkeypatch.setattr('neesha.adapters.urlscan.urlopen',lambda *a,**kw:Response())
    adapter=UrlscanAdapter()
    reference=adapter.search(Request('domain','acme.com'))[0]
    with pytest.raises(AdapterError,match='limit'):
        adapter.fetch(reference)
    def fail(*args,**kwargs):raise OSError('provider unavailable')
    monkeypatch.setattr('neesha.adapters.urlscan.urlopen',fail)
    with pytest.raises(AdapterError,match='unavailable'):
        adapter.fetch(reference)
