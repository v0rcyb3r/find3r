"""Graph projection preserves evidence and never treats names as identity keys."""
import copy
import json

from neesha.harness.graph import build_graph


def fact(attribute,value,fid,subject='acme.com',entity_id=None,**extra):
    return {'attribute':attribute,'value':value,'fact_id':fid,'source_record_id':'record-'+fid,
            'subject':subject,'entity_id':entity_id,'source':'fixture','source_url':'https://source.example/',
            'collected_at':'2026-11-02T12:00:00+00:00','collection_mode':'third_party_passive',
            'retrieved_by':'fixture-adapter','confidence':'medium','admiralty':'C3','flags':[],**extra}


def test_organization_infrastructure_contacts_and_roles_keep_full_edge_provenance():
    facts=[fact('dns.subdomain','vpn.acme.com','sub'),fact('dns.a','203.0.113.10','ip'),
        fact('person.role','CISO','role',subject='Dana Ops',entity_id='person-1'),
        fact('person.business_email','dana@acme.com','email',subject='Dana Ops',entity_id='person-1'),
        fact('person.business_phone','+1 (212) 555-0123','phone',subject='Dana Ops',entity_id='person-1'),
        fact('company.business_email','info@acme.com','general'),
        fact('company.business_phone','+1 212 555 0199','switchboard'),
        fact('http.security_header.x-frame-options','DENY','header')]
    graph=build_graph('acme.com',facts)
    assert {n['kind'] for n in graph['nodes']} >= {'organization','domain','person','email','phone','ip','observation'}
    nodes={n['id']:n for n in graph['nodes']}
    assert len(graph['edges'])==len(facts)
    indexed={f['fact_id']:f for f in facts}
    for edge in graph['edges']:
        assert edge['source'] in nodes and edge['target'] in nodes
        assert edge['evidence_ids']
        assert edge['source_record_ids']
        assert edge['provenance']
        for item in edge['provenance']:
            original=indexed[item['fact_id']]
            for key in ('source_record_id','source','source_url','collected_at','collection_mode','retrieved_by','confidence','admiralty'):
                assert item[key]==original[key]
    role_edge=next(e for e in graph['edges'] if e['kind']=='published_role: CISO')
    assert nodes[role_edge['source']]['kind']=='person'
    assert nodes[role_edge['target']]['kind']=='organization'
    assert 'not verified legal ownership' in graph['context']


def test_same_name_with_different_entity_ids_stays_distinct():
    graph=build_graph('acme.com',[
        fact('person.role','CISO','one',subject='Alex Smith',entity_id='person-1'),
        fact('person.role','CFO','two',subject='Alex Smith',entity_id='person-2'),
    ])
    people=[n for n in graph['nodes'] if n['kind']=='person']
    assert len(people)==2
    assert {n['label'] for n in people}=={'Alex Smith'}
    assert len({n['id'] for n in people})==2


def test_same_name_without_identifier_remains_source_scoped():
    graph=build_graph('acme.com',[
        fact('person.role','CISO','one',subject='Alex Smith'),
        fact('person.role','CFO','two',subject='Alex Smith'),
    ])
    assert len([n for n in graph['nodes'] if n['kind']=='person'])==2


def test_one_person_identifier_links_multiple_observations_and_merges_contact_evidence():
    graph=build_graph('acme.com',[
        fact('person.business_email','alex@acme.com','one',subject='Alex',entity_id='p1'),
        fact('person.business_email','alex@acme.com','two',subject='Alex',entity_id='p1'),
    ])
    assert len([n for n in graph['nodes'] if n['kind']=='person'])==1
    assert len([n for n in graph['nodes'] if n['kind']=='email'])==1
    edge,=graph['edges']
    assert set(edge['evidence_ids'])=={'one','two'}
    assert set(edge['source_record_ids'])=={'record-one','record-two'}


def test_historical_dns_and_archived_urls_are_not_current_ownership_claims():
    graph=build_graph('acme.com',[
        fact('dns.passive.ipv4','203.0.113.20','old',subject='old.acme.com'),
        fact('dns.a','203.0.113.20','new',subject='www.acme.com'),
        fact('web.archive.url','https://acme.com/old','archive'),
        fact('web.observed.url','https://acme.com/current','current'),
    ])
    assert {e['kind'] for e in graph['edges']}=={'historical_dns','resolved_to','archived_url','observed_url'}
    assert 'do not establish current ownership' in graph['context']


def test_missing_provenance_and_inferred_facts_never_create_edges():
    graph=build_graph('acme.com',[
        fact('dns.subdomain','no-id.acme.com',''),
        fact('dns.a','203.0.113.1','no-record',source_record_id=''),
        fact('person.role','CISO','inferred',subject='Dana',is_inference=True),
        fact('person.role','CFO','flagged',subject='Dana',flags=['inference']),
        None,{},
    ])
    assert graph['edges']==[]


def test_malicious_labels_are_inert_serializable_data_and_do_not_mutate_input():
    hostile='<script>globalThis.pwned = true</script>'
    facts=[fact('person.role',hostile,'role',subject=hostile,entity_id='hostile-person'),
           fact('company.business_email','javascript:alert(1)','email')]
    original=copy.deepcopy(facts)
    graph=build_graph('acme.com',facts)
    assert json.loads(json.dumps(graph))==graph
    assert any(n['label']==hostile for n in graph['nodes'])
    assert any(e['kind']=='published_role: '+hostile for e in graph['edges'])
    assert facts==original


def test_invalid_fields_do_not_crash_projection_or_create_unprovenanced_nodes():
    graph=build_graph('acme.com',[
        fact(None,'invalid','attr'),fact('person.role','CISO','entity',entity_id=[]),
        fact('dns.a','203.0.113.1','subject',subject=None),
        fact('person.role','CISO','',subject='Unprovenanced'),
        fact('dns.a','203.0.113.1','flags',flags={'inference':False}),
    ])
    assert graph['edges']==[]
    assert {n['kind'] for n in graph['nodes']}=={'organization','domain'}
