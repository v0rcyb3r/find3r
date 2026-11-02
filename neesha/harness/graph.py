"""An evidence graph projection; names are labels, never identity join keys."""
from __future__ import annotations
import hashlib
import re


def build_graph(company: str, facts: list[dict], subject_kind: str = "company") -> dict:
    nodes, edges = {}, {}

    def node(kind, key, label):
        identity = hashlib.sha256((kind + ':' + key).encode()).hexdigest()[:24]
        nodes.setdefault(identity, {'id':identity,'kind':kind,'label':label})
        return identity

    org = None if subject_kind == 'email' else node('organization', company.lower(), company)
    seed = (node('email', company, company) if subject_kind == 'email'
            else node('domain', company.lower(), company.lower()))

    def link(a,b,kind,fact):
        if a == b or not fact.get('fact_id') or not fact.get('source_record_id'):
            return
        key=(a,b,kind)
        edge=edges.setdefault(key,{'source':a,'target':b,'kind':kind,'evidence_ids':[],
                                   'source_record_ids':[], 'provenance':[]})
        if fact['fact_id'] not in edge['evidence_ids']:
            edge['evidence_ids'].append(fact['fact_id'])
            if fact['source_record_id'] not in edge['source_record_ids']:
                edge['source_record_ids'].append(fact['source_record_id'])
            edge['provenance'].append({k:fact.get(k) for k in (
                'fact_id','source_record_id','source','source_url','collected_at',
                'collection_mode','retrieved_by','confidence','admiralty')})

    for fact in facts:
        if not isinstance(fact,dict) or fact.get('is_inference') is True:
            continue
        flags = fact.get('flags') or []
        if not isinstance(flags, list) or 'inference' in flags:
            continue
        if any(not isinstance(fact.get(key), str) or not fact[key].strip()
               for key in ('fact_id', 'source_record_id')):
            continue
        attr,value=fact.get('attribute',''),fact.get('value','')
        if not isinstance(attr,str) or not isinstance(value,str) or not value:
            continue
        subject=fact.get('subject',company)
        if not isinstance(subject, str) or not subject:
            continue
        if fact.get('entity_id') is not None and not isinstance(fact['entity_id'], str):
            continue
        if subject_kind == 'email':
            # Public provider metadata is not proof of identity, ownership, or
            # account registration. Never create a person/company from a label.
            if not attr.startswith('public.'):
                continue
            if attr == 'public.account.found' or attr.startswith('public.account.found'):
                # An enumerated account existence: show it as an account tied to
                # the exact email, labelled by the service. Evidence-backed only.
                account = node('account', str(fact.get('source', '')) + ':' + value, value)
                link(seed, account, 'account_observed', fact)
            elif attr.startswith('public.account.summary'):
                continue  # a count, not an entity to draw
            elif attr.endswith('.url') or attr.endswith('_url'):
                observation = node('url', value, value)
                link(seed, observation, 'public_provider_metadata', fact)
            elif attr.endswith('linked_login'):
                account = node('account', str(fact.get('source', '')) + ':' + value, value)
                link(seed, account, 'public_provider_metadata', fact)
            else:
                observation = node('observation', attr + ':' + value, attr + ' = ' + value)
                link(seed, observation, 'public_provider_metadata', fact)
            continue
        person=None
        if attr.startswith('person.'):
            # A record-scoped fallback deliberately refuses cross-source name joins.
            key=fact.get('entity_id') or (fact.get('source_record_id','')+':'+subject)
            person=node('person',key,subject)
            if attr=='person.role':
                link(person,org,'published_role: '+value,fact)
        if attr in ('dns.subdomain','discovery.subdomain'):
            domain=node('domain',value.lower(),value)
            link(domain,seed,'subdomain_of',fact)
        elif attr in ('dns.a','dns.aaaa') or attr.startswith('dns.passive.ip'):
            ip=node('ip',value,value)
            host=node('domain',subject.lower(),subject)
            link(host,ip,'historical_dns' if attr.startswith('dns.passive') else 'resolved_to',fact)
        elif attr in ('company.business_email','person.business_email'):
            email=node('email',value.lower(),value)
            link(person or org,email,'published_business_email',fact)
        elif attr in ('company.business_phone','person.business_phone'):
            phone=node('phone',company+':'+re.sub(r'[^\d+]','',value),value)
            link(person or org,phone,'published_business_phone',fact)
        elif attr in ('company.contact_page','person.profile_url','web.archive.url','web.observed.url'):
            url=node('url',value,value)
            link(person or seed,url,'archived_url' if attr=='web.archive.url' else 'observed_url',fact)
        elif attr.startswith(('http.','tls.','email.','dns.')):
            observation=node('observation',attr+':'+value,attr+' = '+value)
            link(seed,observation,'observed',fact)
    return {'nodes':list(nodes.values()),'edges':list(edges.values()),
            'identity_policy':'Explicit identifiers or source-scoped observations; no name-only identity merges.',
            'context':('Independent exact-email observations. Public profile or commit metadata does not establish legal identity, account registration, or company affiliation.'
                       if subject_kind == 'email' else 'The organization label is the investigation seed, not verified legal ownership. Historical DNS and archived URLs do not establish current ownership.')}
