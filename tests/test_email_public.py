"""Passive email-first collection: exact publication evidence, never login probes."""
import hashlib
import json
import urllib.error
import urllib.request
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest

from neesha.adapters.base import AdapterError, Request
from neesha.adapters.email_public import MAX_BYTES, NoRedirect, get_json, normalize_email
from neesha.adapters.emailrep import EmailRepAdapter
from neesha.adapters.github_email import GitHubEmailAdapter
from neesha.adapters.gravatar import GravatarAdapter, email_hash

EMAIL = 'Analyst+research@gmail.com'
SEED = Request('email', EMAIL)
SHA = 'a' * 40


def test_email_normalization_preserves_local_case_and_aliases():
    assert normalize_email(' Analyst+research@GMAIL.COM ') == EMAIL
    assert normalize_email('x@bücher.de') == 'x@xn--bcher-kva.de'
    assert normalize_email('a.b+tag@gmail.com') != normalize_email('ab@gmail.com')


@pytest.mark.parametrize('value', ['domain.com', 'a@@gmail.com', '.a@gmail.com',
    'a..b@gmail.com', 'a@localhost', 'a b@gmail.com', 'a\n@gmail.com', 'a@-bad.com', None])
def test_invalid_email_cannot_inject_provider_queries(value):
    with pytest.raises(AdapterError):
        normalize_email(value)


def github_item(email=EMAIL, *, private=False, login='analyst', name='Public Commit Name'):
    return {'repository': {'private': private},
            'commit': {'author': {'email': email, 'name': name}, 'message': 'PASSWORD DO NOT CACHE'},
            'author': {'login': login}, 'html_url': 'https://github.com/acme/tool/commit/' + SHA}


def test_github_exact_email_matches_only_public_commit_publication(monkeypatch):
    adapter = GitHubEmailAdapter()
    query = parse_qs(urlsplit(adapter.search(SEED)[0].url).query)
    assert query['q'] == ['author-email:' + EMAIL + ' is:public']
    assert query['per_page'] == ['20']
    data = {'items': [github_item(), github_item(), github_item('other@gmail.com'),
                     github_item(private=True), github_item(EMAIL.lower()), None],
            'total_count': 9999, 'incomplete_results': True, 'password': 'DO NOT CACHE'}
    provider = Mock(return_value=(data, 200))
    monkeypatch.setattr('neesha.adapters.github_email.get_json', provider)
    result = adapter.fetch(adapter.search(SEED)[0])
    facts = adapter.parse(result, SEED)
    assert {f.attribute for f in facts} == {
        'public.email.github.commit_url', 'public.email.github.author_name',
        'public.email.github.linked_login'}
    assert all(f.entity_kind == 'email' and f.entity_name == EMAIL for f in facts)
    assert all(f.sensitivity == 'personal' for f in facts)
    assert not any('registered' in f.attribute or 'business' in f.attribute for f in facts)
    assert b'PASSWORD' not in result.payload
    assert b'DO NOT CACHE' not in result.payload
    assert b'other@gmail.com' not in result.payload
    assert 'Authorization' not in provider.call_args.kwargs['headers']


def test_github_has_no_negative_account_registration_claim_on_no_results(monkeypatch):
    adapter = GitHubEmailAdapter()
    monkeypatch.setattr('neesha.adapters.github_email.get_json', Mock(return_value=(
        {'items': [], 'incomplete_results': False}, 200)))
    assert adapter.parse(adapter.fetch(adapter.search(SEED)[0]), SEED) == []


def test_github_rejects_untrusted_profile_and_commit_urls(monkeypatch):
    item = github_item()
    item['html_url'] = 'https://evil.example/commit/' + SHA
    adapter = GitHubEmailAdapter()
    monkeypatch.setattr('neesha.adapters.github_email.get_json', Mock(return_value=({'items': [item]}, 200)))
    assert adapter.parse(adapter.fetch(adapter.search(SEED)[0]), SEED) == []


def test_gravatar_current_contract_uses_sha256_not_md5(monkeypatch):
    adapter = GravatarAdapter()
    digest = hashlib.sha256(EMAIL.lower().encode()).hexdigest()
    assert email_hash(EMAIL) == digest
    reference = adapter.search(SEED)[0]
    assert reference.url == 'https://api.gravatar.com/v3/profiles/' + digest
    provider = Mock(return_value=({'hash': digest, 'profile_url': 'https://gravatar.com/analyst',
        'display_name': 'Public Profile Name', 'location': 'DO NOT CACHE',
        'contact_info': {'home_phone': 'DO NOT CACHE'}, 'password': 'DO NOT CACHE'}, 200))
    monkeypatch.setattr('neesha.adapters.gravatar.get_json', provider)
    result = adapter.fetch(reference)
    facts = adapter.parse(result, SEED)
    assert {f.attribute for f in facts} == {'public.profile.gravatar.url', 'public.profile.gravatar.display_name'}
    assert b'DO NOT CACHE' not in result.payload
    assert all(f.entity_name == EMAIL for f in facts)


def test_gravatar_absent_or_private_profile_does_not_claim_no_account(monkeypatch):
    adapter = GravatarAdapter()
    monkeypatch.setattr('neesha.adapters.gravatar.get_json', Mock(return_value=(None, 404)))
    result = adapter.fetch(adapter.search(SEED)[0])
    assert result.http_status == 404
    assert adapter.parse(result, SEED) == []


def test_gravatar_rejects_wrong_hash_and_unsafe_url(monkeypatch):
    adapter = GravatarAdapter()
    for data in ({'hash': 'wrong'}, {'hash': email_hash(EMAIL), 'profile_url': 'https://evil.example/a'}):
        monkeypatch.setattr('neesha.adapters.gravatar.get_json', Mock(return_value=(data, 200)))
        with pytest.raises(AdapterError):
            adapter.fetch(adapter.search(SEED)[0])


def test_emailrep_is_honest_about_existing_key_requirement(monkeypatch):
    monkeypatch.delenv('EMAILREP_API_KEY', raising=False)
    adapter = EmailRepAdapter()
    assert adapter.default_enabled is False
    assert adapter.availability()['available'] is False
    assert 'new keys are not issued' in adapter.availability()['reason']
    with pytest.raises(AdapterError, match='existing API key'):
        adapter.fetch(adapter.search(SEED)[0])


def test_emailrep_discards_breach_fields_and_labels_profile_hints_as_inference(monkeypatch):
    monkeypatch.setenv('EMAILREP_API_KEY', 'SECRET-KEY')
    adapter = EmailRepAdapter()
    provider = Mock(return_value=({'email': EMAIL, 'reputation': 'high', 'references': 5,
        'password': 'DO NOT CACHE', 'details': {'credentials_leaked': True, 'data_breach': True,
        'profiles': ['github', 'linkedin', '<script>', 'github']}}, 200))
    monkeypatch.setattr('neesha.adapters.emailrep.get_json', provider)
    result = adapter.fetch(adapter.search(SEED)[0])
    facts = adapter.parse(result, SEED)
    assert b'credentials_leaked' not in result.payload
    assert b'data_breach' not in result.payload
    assert b'DO NOT CACHE' not in result.payload
    assert b'SECRET-KEY' not in result.payload
    assert 'SECRET-KEY' not in result.request_url
    assert provider.call_args.kwargs['headers'] == {'Key': 'SECRET-KEY'}
    hints = [f for f in facts if f.attribute.endswith('profile_hint')]
    assert {f.value for f in hints} == {'github', 'linkedin'}
    assert all(f.is_inference for f in hints)
    assert all(f.entity_kind == 'email' and f.entity_name == EMAIL for f in facts)


def test_emailrep_cannot_substitute_another_email(monkeypatch):
    monkeypatch.setenv('EMAILREP_API_KEY', 'key')
    adapter = EmailRepAdapter()
    monkeypatch.setattr('neesha.adapters.emailrep.get_json', Mock(return_value=({'email': 'other@gmail.com'}, 200)))
    with pytest.raises(AdapterError, match='does not match'):
        adapter.fetch(adapter.search(SEED)[0])


def test_transport_has_no_redirects_and_a_hard_read_cap(monkeypatch):
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.status = 200
    response.read.return_value = b'{}'
    opener = Mock()
    opener.open.return_value = response
    build = Mock(return_value=opener)
    monkeypatch.setattr('urllib.request.build_opener', build)
    assert get_json('https://api.gravatar.com/v3/profiles/hash', source='Gravatar') == ({}, 200)
    assert any(isinstance(handler, NoRedirect) for handler in build.call_args.args)
    assert any(isinstance(handler, urllib.request.ProxyHandler) and handler.proxies == {}
               for handler in build.call_args.args)
    response.read.assert_called_once_with(MAX_BYTES + 1)
    assert opener.open.call_args.kwargs['timeout'] == 15


def test_transport_not_found_is_explicit_and_rate_limit_is_a_gap(monkeypatch):
    opener = Mock()
    monkeypatch.setattr('urllib.request.build_opener', Mock(return_value=opener))
    opener.open.side_effect = urllib.error.HTTPError('https://provider.test', 404, 'private', {}, None)
    assert get_json('https://provider.test', source='Provider', allow_not_found=True) == (None, 404)
    opener.open.side_effect = urllib.error.HTTPError('https://provider.test', 429, 'SECRET', {}, None)
    with pytest.raises(AdapterError, match='rate limit') as caught:
        get_json('https://provider.test', source='Provider')
    assert 'SECRET' not in str(caught.value)


@pytest.mark.parametrize('adapter', [GitHubEmailAdapter(), GravatarAdapter(), EmailRepAdapter()])
def test_every_adapter_refuses_replayed_metadata_for_a_different_email(adapter, monkeypatch):
    from neesha.adapters.base import RawResult
    with pytest.raises(AdapterError, match='does not match'):
        adapter.parse(RawResult(json.dumps({'email': 'other@gmail.com'}).encode(), 'https://source.test'), SEED)


@pytest.mark.parametrize('adapter,module', [(GitHubEmailAdapter(), 'github_email'),
    (GravatarAdapter(), 'gravatar'), (EmailRepAdapter(), 'emailrep')])
def test_reference_cannot_send_input_or_secrets_to_arbitrary_host(adapter, module, monkeypatch):
    from neesha.adapters.base import Reference
    provider = Mock()
    monkeypatch.setattr('neesha.adapters.' + module + '.get_json', provider)
    with pytest.raises(AdapterError, match='does not match'):
        adapter.fetch(Reference(url='https://evil.example/', label=EMAIL))
    provider.assert_not_called()


def test_gravatar_only_retains_explicitly_visible_linked_public_accounts(monkeypatch):
    adapter = GravatarAdapter()
    base = {'hash': email_hash(EMAIL), 'profile_url': 'https://gravatar.com/analyst',
        'verified_accounts': [
            {'url': 'https://github.com/analyst', 'is_hidden': False},
            {'url': 'https://linkedin.com/in/private', 'is_hidden': True},
            {'url': 'https://example.com/ambiguous'},
            {'url': 'https://example.com/?token=secret', 'is_hidden': False},
        ]}
    monkeypatch.setattr('neesha.adapters.gravatar.get_json', Mock(return_value=(base, 200)))
    facts = adapter.parse(adapter.fetch(adapter.search(SEED)[0]), SEED)
    assert [f.value for f in facts if f.attribute.endswith('linked_profile_url')] == ['https://github.com/analyst']
    base['section_visibility'] = {'hidden_verified_accounts': True}
    monkeypatch.setattr('neesha.adapters.gravatar.get_json', Mock(return_value=(base, 200)))
    facts = adapter.parse(adapter.fetch(adapter.search(SEED)[0]), SEED)
    assert not any(f.attribute.endswith('linked_profile_url') for f in facts)


def test_email_cache_keys_do_not_merge_localpart_case_or_aliases():
    from neesha.adapters.base import Request
    from neesha.adapters.github_email import GitHubEmailAdapter
    adapter=GitHubEmailAdapter()
    assert adapter.cache_key(Request('email','Dana@example.com')) != adapter.cache_key(Request('email','dana@example.com'))
    assert adapter.cache_key(Request('email','Dana@example.com')) == adapter.cache_key(Request('email','Dana@EXAMPLE.COM'))
    assert adapter.cache_key(Request('email','dana+one@example.com')) != adapter.cache_key(Request('email','dana@example.com'))
