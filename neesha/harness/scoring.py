"""Explained weighted signals, with unknown coverage kept separate from scores.

These are transparent analyst aids, not exploitability estimates, an overall
security-posture rating, or a prediction that an organization will buy.
"""
from __future__ import annotations

import math
import re

_HEADERS = (
    'strict-transport-security', 'content-security-policy', 'x-content-type-options',
    'x-frame-options', 'referrer-policy', 'permissions-policy',
)
_ATTRIBUTE = re.compile(r'[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+')


def _observations(facts):
    rows = {}
    for fact in facts:
        if not isinstance(fact, dict) or fact.get('is_inference') is True:
            continue
        flags = fact.get('flags') or []
        if not isinstance(flags, list) or 'inference' in flags or fact.get('confidence') == 'unknown':
            continue
        if any(not isinstance(fact.get(k), str) or not fact[k].strip()
               for k in ('attribute', 'value', 'fact_id', 'source_record_id')):
            continue
        rows[fact['fact_id']] = fact
    return list(rows.values())


def _criterion(identifier, label, attribute, weight, rows, points, reason, **extra):
    return {
        'id': identifier, 'label': label, 'attribute': attribute, 'weight': weight,
        'status': 'assessed' if points is not None else 'unknown',
        'observed_values': sorted({r['value'] for r in rows}),
        'points': points, 'contribution': None,
        'evidence_ids': sorted({r['fact_id'] for r in rows}),
        'source_record_ids': sorted({r['source_record_id'] for r in rows}),
        'explanation': reason, **extra,
    }


def _summarize(criteria, explanation):
    total_weight = math.fsum(c['weight'] for c in criteria)
    assessed_weight = math.fsum(c['weight'] for c in criteria if c['points'] is not None)
    if assessed_weight:
        for criterion in criteria:
            if criterion['points'] is not None:
                criterion['contribution'] = round(criterion['weight'] * criterion['points'] / assessed_weight, 4)
        score = round(math.fsum(c['weight'] * c['points'] for c in criteria
                              if c['points'] is not None) / assessed_weight, 1)
    else:
        score = None
    return {
        'score': score,
        'coverage': round(100 * assessed_weight / total_weight, 1) if total_weight else 0.0,
        'assessed_weight': assessed_weight, 'total_weight': total_weight,
        'assessed_count': sum(c['points'] is not None for c in criteria),
        'criteria_count': len(criteria), 'criteria': criteria,
        'unknowns': [{'id': c['id'], 'reason': c['explanation']}
                     for c in criteria if c['points'] is None],
        'explanation': explanation,
    }


def _security(rows):
    criteria = []
    for identifier, label, attribute, weight, mapping, explanations in (
        ('dmarc_policy', 'Published DMARC policy', 'email.dmarc.policy', 3.0,
         {'absent': 100, 'none': 100, 'quarantine': 50, 'reject': 0},
         {'absent': 'No DMARC record is published, so DMARC evaluates no mail for this domain.',
          'none': 'The observed policy requests monitoring, not quarantine or rejection.',
          'quarantine': 'The observed policy requests quarantine rather than rejection.',
          'reject': 'The observed policy requests rejection; no need signal is assigned on this criterion.'}),
        ('spf_qualifier', 'Published SPF all qualifier', 'email.spf.qualifier', 2.0,
         {'absent': 100, '+all': 100, '~all': 50, '-all': 0},
         {'absent': 'No SPF record is published, so SPF constrains no senders for this domain.',
          '+all': 'The observed +all mechanism permits all senders.',
          '~all': 'The observed ~all mechanism is a soft-fail signal rather than a hard fail.',
          '-all': 'The observed -all mechanism requests a hard fail; no need signal is assigned on this criterion.'}),
    ):
        matching = [r for r in rows if r['attribute'] == attribute]
        values = {r['value'].strip().lower() for r in matching}
        if len(values) == 1 and next(iter(values)) in mapping:
            value = next(iter(values))
            points, reason = mapping[value], explanations[value]
            reason += ' This describes the published record, not actual receiver behavior or exploitability.'
        else:
            points = None
            reason = ('No observed record is available; this is unknown, not a missing control.' if not values
                      else 'Conflicting or unsupported observed values require analyst review; no score is assigned.')
        criteria.append(_criterion(identifier, label, attribute, weight, matching, points, reason))
    # A website scan that completed emits this marker, which is what lets a
    # header's absence be read as observed rather than merely uncollected.
    page_assessed = any(r['attribute'] == 'http.security_assessed' for r in rows)
    for header in _HEADERS:
        attribute = 'http.security_header.' + header
        matching = [r for r in rows if r['attribute'] == attribute]
        if matching:
            points = 0
            reason = 'This header was observed. Presence alone does not establish correct configuration or effective protection.'
        elif page_assessed:
            points = 100
            reason = 'The website was fetched and this security header was not present in the response; its absence is an observed need signal, not a configuration verdict.'
        else:
            points = None
            reason = 'No observation is available. An uncollected header is not assumed absent or vulnerable.'
        criteria.append(_criterion(
            'header_' + header.replace('-', '_'), 'Observed ' + header, attribute, 1.0,
            matching, points, reason,
        ))
    result = _summarize(criteria,
        'Higher values indicate stronger observed signals of potential security needs on assessed criteria only. '
        'Weights are transparent product rules, not a scientifically calibrated risk model. '
        'Coverage is separate: a low score with sparse coverage does not establish good security. '
        'This is not an exploitability score or an overall posture rating.')
    result['configured'] = True
    result['direction'] = 'higher means stronger observed potential-need signals'
    return result


def _text(value, field, *, required=True):
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        raise ValueError(f'{field} must be a nonempty string of at most 200 characters.')
    return value.strip()


def _validate_profile(profile):
    if not isinstance(profile, dict) or set(profile) - {'name', 'services', 'criteria'}:
        raise ValueError('Commercial profile fields must be name, services, and criteria only.')
    name = _text(profile.get('name'), 'profile name', required=False)
    services = profile.get('services', [])
    if not isinstance(services, list) or len(services) > 100:
        raise ValueError('services must be a list of at most 100 names.')
    services = [_text(service, 'service') for service in services]
    criteria = profile.get('criteria', [])
    if not isinstance(criteria, list) or len(criteria) > 100:
        raise ValueError('criteria must be a list of at most 100 criteria.')
    normalized, ids = [], set()
    for criterion in criteria:
        allowed = {'id', 'label', 'service', 'attribute', 'weight', 'equals', 'contains'}
        if not isinstance(criterion, dict) or set(criterion) - allowed:
            raise ValueError('Unknown commercial criterion field.')
        identifier = _text(criterion.get('id'), 'criterion id')
        if identifier in ids:
            raise ValueError('Commercial criterion ids must be unique.')
        ids.add(identifier)
        attribute = _text(criterion.get('attribute'), 'attribute')
        if not _ATTRIBUTE.fullmatch(attribute):
            raise ValueError('Commercial attribute must be a dotted fact attribute.')
        operators = set(criterion) & {'equals', 'contains'}
        if len(operators) != 1:
            raise ValueError('Each commercial criterion must define exactly one of equals or contains.')
        operator = next(iter(operators))
        expected = _text(criterion[operator], operator)
        weight = criterion.get('weight')
        if isinstance(weight, bool) or not isinstance(weight, (int, float)):
            raise ValueError('Criterion weight must be a finite number greater than zero and at most 1000.')
        if not 0 < weight <= 1000 or not math.isfinite(weight):
            raise ValueError('Criterion weight must be a finite number greater than zero and at most 1000.')
        service = _text(criterion.get('service'), 'criterion service', required=False)
        if service is not None and services and service not in services:
            raise ValueError('Criterion service must be present in configured services.')
        normalized.append({'id': identifier, 'label': _text(criterion.get('label', identifier), 'criterion label'),
                           'attribute': attribute, 'weight': float(weight),
                           'operator': operator, 'expected': expected, 'service': service})
    return name, services, normalized


def _commercial(rows, profile):
    if profile is None:
        result = _summarize([], 'Commercial fit is not configured. No ideal customer or service preference has been assumed.')
        result.update(configured=False, profile_name=None, services=[], direction='higher means stronger configured criterion matches')
        return result
    name, services, configured = _validate_profile(profile)
    criteria = []
    for rule in configured:
        matching = [r for r in rows if r['attribute'] == rule['attribute']]
        if not matching:
            points, reason = None, 'No observation for this configured attribute; fit is unknown, not zero.'
        else:
            expected = rule['expected'].casefold()
            matched = any((r['value'].strip().casefold() == expected if rule['operator'] == 'equals'
                           else expected in r['value'].casefold()) for r in matching)
            points = 100 if matched else 0
            reason = ('An observed value matches the configured criterion.' if matched
                      else 'The observed values do not match this criterion. This does not establish a complete inventory.')
        criteria.append(_criterion(rule['id'], rule['label'], rule['attribute'], rule['weight'],
            matching, points, reason, operator=rule['operator'], expected=rule['expected'], service=rule['service']))
    result = _summarize(criteria,
        'Fit measures only the configured service criteria against observed attributes. '
        'It is normalized over assessed criteria; missing observations remain unknown and reduce coverage. '
        'It does not predict purchase intent or buying authority.')
    result.update(configured=True, profile_name=name, services=services,
                  direction='higher means stronger configured criterion matches')
    return result


def score_brief(facts: list[dict], profile=None) -> dict:
    """Score guarded observed facts without network/model calls or inferred gaps.

    Commercial profile schema: {name?, services?:[str], criteria:[
      {id, label?, service?, attribute, weight, exactly one of equals|contains:str}
    ]}. Matching is case-insensitive. Weights must be finite, 0 < weight <= 1000.
    Security weights: DMARC=3, SPF=2, each of six observed headers=1.
    """
    rows = _observations(facts)
    return {'commercial_fit': _commercial(rows, profile), 'security_needs': _security(rows)}


def _unique(items) -> list[str]:
    return sorted({x for x in items if isinstance(x, str) and x})


HEADER_CRITERIA = tuple(
    (h.replace('-', '_'), h.title(), 'http.security_header.' + h, 1.0)
    for h in _HEADERS
)


def _letter_from_score(score: float | int | None) -> str:
    if score is None:
        return 'N/A'
    if score >= 90:
        return 'A'
    if score >= 80:
        return 'B'
    if score >= 70:
        return 'C'
    if score >= 60:
        return 'D'
    return 'F'


def _exposure(exp_id: str, severity: str, category: str, title: str, observed: str,
              consequence: str, remediation: str, stakeholder: str, matching: list[dict]) -> dict:
    return {
        'id': exp_id,
        'severity': severity,
        'category': category,
        'title': title,
        'observed': observed,
        'consequence': consequence,
        'remediation': remediation,
        'stakeholder_function': stakeholder,
        'evidence_ids': _unique(r['fact_id'] for r in matching),
        'source_record_ids': _unique(r['source_record_id'] for r in matching),
    }


RISKY_PORTS = {
    '21': ('FTP (21/tcp)', 'medium', 'Cleartext file transfer service exposed to the internet.'),
    '22': ('SSH (22/tcp)', 'low', 'Remote administration service exposed publicly; target for brute-force or key stuffing.'),
    '23': ('Telnet (23/tcp)', 'critical', 'Unencrypted legacy remote shell exposed to the internet.'),
    '25': ('SMTP (25/tcp)', 'low', 'Mail transfer agent exposed; verify relay restrictions and STARTTLS enforcement.'),
    '445': ('SMB (445/tcp)', 'critical', 'Windows SMB file sharing exposed to the internet; high ransomware and lateral movement risk.'),
    '1433': ('MS-SQL (1433/tcp)', 'high', 'Microsoft SQL Server port directly reachable from the internet.'),
    '3306': ('MySQL (3306/tcp)', 'high', 'MySQL database port directly reachable from the internet.'),
    '3389': ('RDP (3389/tcp)', 'high', 'Remote Desktop Protocol exposed to the internet; frequent initial access vector.'),
    '5432': ('PostgreSQL (5432/tcp)', 'high', 'PostgreSQL database port directly reachable from the internet.'),
    '6379': ('Redis (6379/tcp)', 'critical', 'Redis datastore port exposed to the internet.'),
    '9200': ('Elasticsearch (9200/tcp)', 'high', 'Elasticsearch HTTP API exposed to the internet.'),
    '27017': ('MongoDB (27017/tcp)', 'critical', 'MongoDB database port exposed to the internet.'),
}

SEVERITY_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}


def grade_brief_posture(facts: list[dict]) -> dict:
    """Compute A-F security posture grades across 5 domains and generate prioritized exposures."""
    rows = _observations(facts)
    by_attr: dict[str, list[dict]] = {}
    for row in rows:
        by_attr.setdefault(row['attribute'], []).append(row)

    exposures: list[dict] = []
    categories: dict[str, dict] = {}

    # 1. Email Authentication & Spoofing Defense
    dmarc_rows = by_attr.get('email.dmarc.policy', [])
    spf_rows = by_attr.get('email.spf.qualifier', [])
    dkim_rows = by_attr.get('email.dkim.selector', [])
    mtasts_rows = by_attr.get('email.mtasts.present', [])
    tlsrpt_rows = by_attr.get('email.tlsrpt.present', [])
    rua_rows = by_attr.get('email.dmarc.rua', [])

    if dmarc_rows or spf_rows or dkim_rows or mtasts_rows:
        email_score = 100
        email_reasons = []
        email_evidence = dmarc_rows + spf_rows + dkim_rows + mtasts_rows + tlsrpt_rows + rua_rows

        if dmarc_rows:
            dmarc_val = dmarc_rows[0]['value'].strip().casefold()
            if dmarc_val == 'absent':
                email_score -= 45
                email_reasons.append('No DMARC policy published')
                exposures.append(_exposure(
                    'exp-dmarc-absent', 'high', 'Email Security',
                    'Missing DMARC Policy (_dmarc TXT)',
                    'No _dmarc TXT record published',
                    'Attackers can spoof the primary domain in phishing and business email compromise (BEC) campaigns without receiving servers rejecting or quarantining unauthenticated messages.',
                    'Publish a `_dmarc` TXT record starting with `v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>;` and advance to `p=reject` after verifying legitimate senders.',
                    'IT / Messaging Operations',
                    dmarc_rows,
                ))
            elif dmarc_val == 'none':
                email_score -= 30
                email_reasons.append('DMARC p=none (monitoring only)')
                exposures.append(_exposure(
                    'exp-dmarc-none', 'medium', 'Email Security',
                    'Non-Enforcing DMARC Policy (p=none)',
                    'DMARC policy is p=none',
                    'Spoofed messages failing SPF and DKIM alignment are still delivered to recipient inboxes because DMARC is in monitoring-only mode.',
                    'Review aggregate DMARC reports (rua) and upgrade `_dmarc` policy from `p=none` to `p=quarantine` or `p=reject`.',
                    'IT / Messaging Operations',
                    dmarc_rows,
                ))
            elif dmarc_val == 'quarantine':
                email_score -= 10
                email_reasons.append('DMARC p=quarantine')
            elif dmarc_val == 'reject':
                email_reasons.append('DMARC p=reject enforced')
            if dmarc_val in ('none', 'quarantine', 'reject') and not rua_rows:
                email_score -= 5
                email_reasons.append('No DMARC rua reporting URI')

        if spf_rows:
            spf_val = spf_rows[0]['value'].strip().casefold()
            if spf_val == 'absent':
                email_score -= 30
                email_reasons.append('No SPF record published')
                exposures.append(_exposure(
                    'exp-spf-absent', 'high', 'Email Security',
                    'Missing SPF Policy',
                    'No v=spf1 TXT record published',
                    'Receiving mail servers cannot verify authorized outbound mail servers for the domain, increasing spoofing risk.',
                    'Publish a `v=spf1` TXT record listing authorized sending hosts/includes and terminating with `-all`.',
                    'IT / Messaging Operations',
                    spf_rows,
                ))
            elif spf_val == '+all':
                email_score -= 40
                email_reasons.append('SPF +all permits any sender')
                exposures.append(_exposure(
                    'exp-spf-pass-all', 'critical', 'Email Security',
                    'Permissive SPF Policy (+all)',
                    'SPF qualifier is +all',
                    'The domain explicitly authorizes every IP address on the internet to send authenticated email on its behalf.',
                    'Immediately replace `+all` with `~all` or `-all` in the root SPF TXT record.',
                    'IT / Messaging Operations',
                    spf_rows,
                ))
            elif spf_val == '~all':
                email_score -= 10
                email_reasons.append('SPF ~all (softfail)')
                exposures.append(_exposure(
                    'exp-spf-softfail', 'low', 'Email Security',
                    'SPF Softfail (~all) Instead of Hardfail (-all)',
                    'SPF qualifier is ~all',
                    'Unauthorized senders receive a softfail marker rather than a strict SPF fail directive.',
                    'Transition the SPF record terminator from `~all` to `-all` once all legitimate sending services are accounted for.',
                    'IT / Messaging Operations',
                    spf_rows,
                ))
            elif spf_val == '-all':
                email_reasons.append('SPF -all enforced')

        if dkim_rows:
            selectors = sorted({r['value'] for r in dkim_rows})
            email_reasons.append(f"DKIM active ({', '.join(selectors[:3])})")
        elif dmarc_rows or spf_rows:
            email_score -= 10
            email_reasons.append('No common DKIM selector detected')

        if mtasts_rows:
            mtasts_val = mtasts_rows[0]['value'].strip().casefold()
            if mtasts_val == 'absent':
                email_score -= 10
                email_reasons.append('MTA-STS absent')
                exposures.append(_exposure(
                    'exp-mtasts-absent', 'low', 'Email Security',
                    'Missing Inbound Mail TLS Enforcement (MTA-STS)',
                    '_mta-sts TXT record is absent',
                    'Inbound SMTP connections are susceptible to STARTTLS downgrade or man-in-the-middle interception.',
                    'Publish an `_mta-sts.<domain>` TXT record and host a valid policy at `https://mta-sts.<domain>/.well-known/mta-sts.txt`.',
                    'IT / Messaging Operations',
                    mtasts_rows,
                ))
            else:
                email_reasons.append('MTA-STS enabled')

        email_score = max(0, min(100, email_score))
        categories['email_auth'] = {
            'label': 'Email Authentication',
            'letter': _letter_from_score(email_score),
            'score': email_score,
            'rationale': '; '.join(email_reasons) or 'Assessed from DNS records.',
            'evidence_ids': _unique(r['fact_id'] for r in email_evidence),
        }
    else:
        categories['email_auth'] = {
            'label': 'Email Authentication',
            'letter': 'N/A',
            'score': None,
            'rationale': 'No DNS email authentication records collected in this run.',
            'evidence_ids': [],
        }

    # 2. TLS & Certificate Posture
    tls_days_rows = by_attr.get('tls.days_remaining', [])
    tls_issuer_rows = by_attr.get('tls.issuer', [])
    hsts_rows = by_attr.get('http.security_header.strict-transport-security', [])
    assessed_rows = by_attr.get('http.security_assessed', [])

    if tls_days_rows or tls_issuer_rows or hsts_rows or assessed_rows:
        tls_score = 100
        tls_reasons = []
        tls_evidence = tls_days_rows + tls_issuer_rows + hsts_rows + assessed_rows
        if tls_days_rows:
            try:
                days = int(tls_days_rows[0]['value'])
                if days < 0:
                    tls_score -= 60
                    tls_reasons.append(f'TLS certificate expired ({days} days)')
                    exposures.append(_exposure(
                        'exp-tls-expired', 'critical', 'TLS & Cryptography',
                        'Expired TLS Certificate',
                        f'Certificate expired ({days} days remaining)',
                        'Browsers and API clients will distrust HTTPS connections, causing outages and conditioning users to bypass security warnings.',
                        'Renew and deploy a valid TLS certificate immediately and configure automated ACME renewal.',
                        'Web / Platform Engineering',
                        tls_days_rows,
                    ))
                elif days <= 14:
                    tls_score -= 30
                    tls_reasons.append(f'TLS certificate expires in {days} days')
                    exposures.append(_exposure(
                        'exp-tls-expiring', 'high', 'TLS & Cryptography',
                        'Imminent TLS Certificate Expiration',
                        f'{days} days remaining until TLS certificate expiry',
                        'Certificate expiration within 14 days risks service disruption if automated renewal fails.',
                        'Verify automated certificate renewal pipeline and renew the certificate ahead of expiry.',
                        'Web / Platform Engineering',
                        tls_days_rows,
                    ))
                else:
                    tls_reasons.append(f'Valid TLS certificate ({days}d remaining)')
            except ValueError:
                pass
        if tls_issuer_rows:
            tls_reasons.append(f"Issuer: {tls_issuer_rows[0]['value']}")
        if hsts_rows:
            tls_reasons.append('HSTS enforced')
        elif assessed_rows:
            tls_score -= 20
            tls_reasons.append('HSTS header missing')
        tls_score = max(0, min(100, tls_score))
        categories['tls_transport'] = {
            'label': 'TLS & Transport Security',
            'letter': _letter_from_score(tls_score),
            'score': tls_score,
            'rationale': '; '.join(tls_reasons) or 'Assessed from TLS/HTTPS inspection.',
            'evidence_ids': _unique(r['fact_id'] for r in tls_evidence),
        }
    else:
        categories['tls_transport'] = {
            'label': 'TLS & Transport Security',
            'letter': 'N/A',
            'score': None,
            'rationale': 'No TLS certificate or HTTPS transport observations collected.',
            'evidence_ids': [],
        }

    # 3. HTTP Security Headers
    header_rows = [r for k, v in by_attr.items() if k.startswith('http.security_header.') for r in v]
    if assessed_rows or header_rows:
        present_count = 0
        missing_labels = []
        for cid, label, attr, _ in HEADER_CRITERIA:
            if by_attr.get(attr):
                present_count += 1
            elif assessed_rows:
                missing_labels.append((cid, label, attr))
        total_headers = len(HEADER_CRITERIA)
        if assessed_rows:
            hdr_score = round((present_count / total_headers) * 100)
        else:
            hdr_score = min(100, 60 + present_count * 10)
        if missing_labels:
            # Create consolidated or high-impact exposures for missing HSTS / CSP / XFO
            for cid, label, attr in missing_labels:
                if attr == 'http.security_header.strict-transport-security':
                    exposures.append(_exposure(
                        'exp-header-hsts', 'medium', 'Web Application Security',
                        'Missing HTTP Strict-Transport-Security (HSTS) Header',
                        'Strict-Transport-Security header not present on HTTPS response',
                        'Browsers may permit initial cleartext HTTP connections before redirecting, enabling SSL-stripping attacks.',
                        'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to all HTTPS responses.',
                        'Web / Platform Engineering',
                        assessed_rows,
                    ))
                elif attr == 'http.security_header.content-security-policy':
                    exposures.append(_exposure(
                        'exp-header-csp', 'medium', 'Web Application Security',
                        'Missing Content-Security-Policy (CSP) Header',
                        'Content-Security-Policy header not present on HTTPS response',
                        'Lack of a Content Security Policy increases impact of Cross-Site Scripting (XSS) and unauthorized third-party script injection.',
                        'Deploy a restrictive `Content-Security-Policy` header defining trusted script, frame, and connect origins.',
                        'Web / Platform Engineering',
                        assessed_rows,
                    ))
            other_missing = [lbl for _, lbl, attr in missing_labels
                             if attr not in ('http.security_header.strict-transport-security',
                                             'http.security_header.content-security-policy')]
            if other_missing:
                exposures.append(_exposure(
                    'exp-headers-hardening', 'low', 'Web Application Security',
                    f"Missing Defensive HTTP Headers ({', '.join(other_missing)})",
                    f"Absent headers: {', '.join(other_missing)}",
                    'Missing browser hardening headers increase exposure to clickjacking, MIME-sniffing, and cross-origin referrer leakage.',
                    'Configure `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Permissions-Policy` at the CDN or reverse proxy.',
                    'Web / Platform Engineering',
                    assessed_rows,
                ))
        categories['web_headers'] = {
            'label': 'Web Application Headers',
            'letter': _letter_from_score(hdr_score),
            'score': hdr_score,
            'rationale': f'{present_count}/{total_headers} defensive HTTP security headers observed.',
            'evidence_ids': _unique(r['fact_id'] for r in (assessed_rows + header_rows)),
        }
    else:
        categories['web_headers'] = {
            'label': 'Web Application Headers',
            'letter': 'N/A',
            'score': None,
            'rationale': 'Web response headers were not inspected in this run.',
            'evidence_ids': [],
        }

    # 4. DNSSEC & Domain Integrity
    dnssec_rows = by_attr.get('dnssec.status', [])
    whois_status_rows = by_attr.get('whois.status', [])
    if dnssec_rows or whois_status_rows:
        dns_score = 100
        dns_reasons = []
        if dnssec_rows:
            val = dnssec_rows[0]['value'].strip().casefold()
            if val == 'present':
                dns_reasons.append('DNSSEC signed (DNSKEY present)')
            else:
                dns_score -= 30
                dns_reasons.append('DNSSEC unsigned')
                exposures.append(_exposure(
                    'exp-dnssec-absent', 'low', 'DNS & Domain Hygiene',
                    'Domain Not Signed with DNSSEC',
                    'No DNSKEY records published for zone',
                    'Unsigned DNS zones lack cryptographic origin authentication and can be targeted by DNS cache poisoning or BGP/registrar hijacking.',
                    'Enable DNSSEC signing at the authoritative DNS provider and publish DS records at the domain registrar.',
                    'Network / Infrastructure Security',
                    dnssec_rows,
                ))
        if whois_status_rows:
            statuses = [r['value'] for r in whois_status_rows]
            if any('transferprohibited' in s.lower() for s in statuses):
                dns_reasons.append('Registrar transfer lock active')
            else:
                dns_score -= 15
                dns_reasons.append('No transfer lock status observed in RDAP')
        dns_score = max(0, min(100, dns_score))
        categories['dnssec'] = {
            'label': 'DNS & Domain Hygiene',
            'letter': _letter_from_score(dns_score),
            'score': dns_score,
            'rationale': '; '.join(dns_reasons) or 'Assessed from DNS/RDAP records.',
            'evidence_ids': _unique(r['fact_id'] for r in (dnssec_rows + whois_status_rows)),
        }
    else:
        categories['dnssec'] = {
            'label': 'DNS & Domain Hygiene',
            'letter': 'N/A',
            'score': None,
            'rationale': 'No DNSSEC or RDAP domain status observations collected.',
            'evidence_ids': [],
        }

    # 5. Network, Vulnerability & Identity Exposure
    vuln_rows = by_attr.get('host.vuln', [])
    port_rows = by_attr.get('host.port', [])
    leak_rows = by_attr.get('public.email.emailrep.credentials_leaked', [])
    breach_rows = by_attr.get('public.email.emailrep.data_breach', [])
    intelx_rows = by_attr.get('intelx.record.bucket', []) + [
        r for r in by_attr.get('intelx.search.sample_count', [])
        if r['value'].isdigit() and int(r['value']) > 0
    ]
    ip_rows = by_attr.get('dns.a', [])

    if vuln_rows or port_rows or leak_rows or breach_rows or intelx_rows or ip_rows:
        net_score = 100
        net_reasons = []
        net_evidence = vuln_rows + port_rows + leak_rows + breach_rows + intelx_rows + ip_rows

        if vuln_rows:
            cves = sorted({r['value'] for r in vuln_rows})
            net_score -= min(60, len(cves) * 20)
            net_reasons.append(f"{len(cves)} CVE(s) associated with exposed host services ({', '.join(cves[:4])})")
            exposures.append(_exposure(
                'exp-host-vulns', 'critical', 'Network & Vulnerability Exposure',
                f"Known CVEs Associated with Exposed Host Services ({len(cves)} found)",
                ', '.join(cves[:8]),
                'Publicly reachable host fingerprints match known Common Vulnerabilities and Exposures (CVEs) indexed by Shodan InternetDB.',
                'Patch affected externally facing services immediately, restrict access via firewall/VPN, and verify version banners.',
                'Network / Infrastructure Security',
                vuln_rows,
            ))

        if port_rows:
            ports = sorted({r['value'] for r in port_rows}, key=lambda x: int(x) if x.isdigit() else 99999)
            net_reasons.append(f"Open ports observed: {', '.join(ports[:8])}")
            for p_str in ports:
                if p_str in RISKY_PORTS:
                    p_label, p_sev, p_desc = RISKY_PORTS[p_str]
                    deduction = 25 if p_sev == 'critical' else 15 if p_sev == 'high' else 5
                    net_score -= deduction
                    matching_p = [r for r in port_rows if r['value'] == p_str]
                    exposures.append(_exposure(
                        f'exp-port-{p_str}', p_sev, 'Network & Vulnerability Exposure',
                        f'Exposed Network Service: {p_label}',
                        f'Port {p_str}/tcp open on target infrastructure',
                        p_desc,
                        f'Restrict port {p_str}/tcp behind a zero-trust access proxy, VPN, or IP allowlist if public access is not required.',
                        'Network / Infrastructure Security',
                        matching_p,
                    ))

        if any(r['value'].strip().casefold() == 'true' for r in leak_rows):
            net_score -= 35
            net_reasons.append('Leaked credentials reported')
            exposures.append(_exposure(
                'exp-credentials-leaked', 'critical', 'Identity & Credential Exposure',
                'Leaked Credentials Indexed in Public/Breach Sources',
                'emailrep credentials_leaked=true',
                'Credential pairs associated with the subject have been observed in breach corpuses, enabling credential stuffing or account takeover.',
                'Force password rotation, revoke active sessions/tokens, and enforce phishing-resistant MFA.',
                'Identity / SecOps',
                leak_rows,
            ))

        if any(r['value'].strip().casefold() == 'true' for r in breach_rows):
            net_score -= 20
            net_reasons.append('Known data breach exposure')
            exposures.append(_exposure(
                'exp-data-breach', 'high', 'Identity & Credential Exposure',
                'Identity Observed in Known Data Breach Corpus',
                'emailrep data_breach=true',
                'Target identity metadata appears in historical third-party breach disclosures.',
                'Audit account recovery workflows, rotate credentials, and monitor for targeted spear-phishing.',
                'Identity / SecOps',
                breach_rows,
            ))

        if intelx_rows:
            buckets = sorted({r['value'] for r in intelx_rows})
            net_score -= 20
            net_reasons.append(f"Intelligence X buckets: {', '.join(buckets[:4])}")
            exposures.append(_exposure(
                'exp-intelx-hits', 'high', 'Identity & Credential Exposure',
                f"External Intelligence Records Indexed ({', '.join(buckets[:3])})",
                f"Observed in buckets: {', '.join(buckets)}",
                'Domain or identity selectors appear in external leak/paste/archive collections.',
                'Review matching Intelligence X record metadata and rotate any exposed secrets or session tokens.',
                'Identity / SecOps',
                intelx_rows,
            ))

        if not net_reasons and ip_rows:
            net_reasons.append(f"{len({r['value'] for r in ip_rows})} resolved IPv4 host(s) with no flagged CVEs or risky ports")

        net_score = max(0, min(100, net_score))
        categories['network_exposure'] = {
            'label': 'Network & Exposure Surface',
            'letter': _letter_from_score(net_score),
            'score': net_score,
            'rationale': '; '.join(net_reasons) or 'Assessed from host and breach telemetry.',
            'evidence_ids': _unique(r['fact_id'] for r in net_evidence),
        }
    else:
        categories['network_exposure'] = {
            'label': 'Network & Exposure Surface',
            'letter': 'N/A',
            'score': None,
            'rationale': 'No host port, CVE, or breach telemetry collected in this run.',
            'evidence_ids': [],
        }

    # Overall posture grade
    assessed_cats = [c for c in categories.values() if c['score'] is not None]
    if assessed_cats:
        overall_score = round(sum(c['score'] for c in assessed_cats) / len(assessed_cats))
        overall_letter = _letter_from_score(overall_score)
        overall_rationale = (
            f"Aggregated across {len(assessed_cats)}/5 assessed security domains "
            f"({', '.join(c['label'] + ': ' + c['letter'] for c in assessed_cats)})."
        )
    else:
        overall_score = None
        overall_letter = 'N/A'
        overall_rationale = 'No posture-bearing telemetry collected in this run.'

    exposures.sort(key=lambda e: (SEVERITY_RANK.get(e['severity'], 99), e['title']))

    return {
        'overall': {
            'letter': overall_letter,
            'score': overall_score,
            'rationale': overall_rationale,
            'assessed_domains': len(assessed_cats),
            'total_domains': len(categories),
        },
        'categories': categories,
        'exposures': exposures,
    }
