"""Reviewable run briefings, with the accuracy gate applied before export."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import sqlalchemy as sa

from neesha.adapters import registry
from neesha.db import schema
from neesha.evidence.models import Evidence
from neesha.guardrail.engine import Guardrail
from neesha.harness.scoring import grade_brief_posture, score_brief
from neesha.harness.graph import build_graph
from neesha.harness.power_map import build_power_map


def build_brief(engine: sa.Engine, run_id: str, profile=None) -> dict:
    """Export business facts from one run, excluding expired and restricted data.

    Raw provider payloads are deliberately excluded. Each surviving assertion
    carries its underlying record, original collection time and guardrail grade.
    """
    now = datetime.now(timezone.utc)
    with engine.connect() as conn:
        run = conn.execute(sa.select(schema.run).where(schema.run.c.id == run_id)).mappings().one()
        root = conn.execute(sa.select(schema.entity).where(
            schema.entity.c.id == run['company_id'])).mappings().one()
        company = root['canonical_name']
        subject_kind = root['kind'] if root['kind'] in ('email', 'username', 'ip', 'phone', 'person') else 'company'
        root_subject = subject_kind in ('email', 'username', 'ip', 'phone', 'person')
        from neesha.resolve.intake import resolve_seed
        try:
            seed = resolve_seed(company, subject_kind if root_subject else 'domain')
        except ValueError:
            seed = resolve_seed(company, 'company')
        allowed_sensitivity = (sa.or_(
            schema.fact.c.sensitivity == 'business',
            sa.and_(schema.fact.c.sensitivity == 'personal',
                    schema.fact.c.entity_id == run['company_id'],
                    schema.fact.c.attribute.startswith('public.', autoescape=True)),
        ) if root_subject else schema.fact.c.sensitivity == 'business')
        requirements = [dict(row) for row in conn.execute(
            sa.select(schema.pir).where(schema.pir.c.run_id == run_id)
        ).mappings()]
        attempts = [dict(row) for row in conn.execute(
            sa.select(schema.query_log.c.adapter, schema.query_log.c.decision,
                      schema.query_log.c.decision_reason).where(schema.query_log.c.run_id == run_id)
            .order_by(schema.query_log.c.id)
        ).mappings()]
        rows = conn.execute(
            sa.select(
                schema.fact,
                schema.entity.c.canonical_name.label('subject'),
                schema.entity.c.aliases.label('subject_aliases'),
                schema.source_record.c.adapter,
                schema.source_record.c.request_url,
                schema.source_record.c.origin_url,
                schema.source_record.c.collected_at,
                schema.source_record.c.collection_mode,
                schema.source_record.c.raw_sha256,
            ).join(schema.entity, schema.fact.c.entity_id == schema.entity.c.id)
            .join(schema.source_record, schema.fact.c.source_record_id == schema.source_record.c.id)
            .where(
                schema.fact.c.run_id == run_id,
                allowed_sensitivity,
                schema.fact.c.retention_expires_at > now,
                schema.source_record.c.retention_expires_at > now,
            ).order_by(schema.fact.c.attribute, schema.fact.c.value, schema.fact.c.id)
        ).mappings().all()

    evidence = []
    for row in rows:
        adapter = registry.get(row['adapter'])
        # A serialized typed tuple avoids prose normalization conflating entities.
        claim = json.dumps([row['entity_id'], row['attribute'], row['value']], ensure_ascii=False)
        evidence.append(Evidence(
            evidence_id=row['id'], target_id=run['company_id'], entity_id=row['entity_id'],
            claim=hashlib.sha256(claim.encode()).hexdigest(), source_type=getattr(adapter, 'source_type', 'unknown'),
            source_url=row['request_url'], origin_url=row['origin_url'],
            collected_at=row['collected_at'],
            collection_mode='active' if row['collection_mode'] == 'active' else 'passive',
            collector=row['adapter'], agent=row['adapter'], scope_id=run['engagement_id'],
            confidence=row['confidence'], is_inference=row['is_inference'],
            retention_expires_at=row['retention_expires_at'],
        ))
    # An inference must not serve as corroboration for an observed fact.
    verdicts = {}
    for is_inference in (False, True):
        group = [e for e in evidence if e.is_inference == is_inference]
        verdicts.update({v.evidence_id: v for v in Guardrail.apply(group, strict=True).survived()})
    facts, inferences = [], []
    for row in rows:
        verdict = verdicts.get(row['id'])
        if verdict is None:
            continue
        item = {
            'fact_id': row['id'], 'entity_id': row['entity_id'],
            'subject': (row['subject_aliases'][0] if row['subject_aliases'] else row['subject']),
            'attribute': row['attribute'], 'value': row['value'],
            'sensitivity': row['sensitivity'], 'is_inference': row['is_inference'],
            'confidence': verdict.confidence.value, 'admiralty': verdict.grade,
            'flags': verdict.flags, 'source_record_id': row['source_record_id'],
            'source': row['adapter'], 'retrieved_by': row['adapter'], 'analyst': run['analyst'],
            'source_url': row['request_url'],
            'origin_url': row['origin_url'], 'collected_at': row['collected_at'].isoformat(),
            'collection_mode': row['collection_mode'], 'raw_sha256': row['raw_sha256'],
        }
        (inferences if verdict.is_inference else facts).append(item)

    visible_ids = {item['fact_id'] for item in facts + inferences}
    for requirement in requirements:
        original_ids = requirement['fact_ids'] or []
        requirement['fact_ids'] = [i for i in original_ids if i in visible_ids]
        if len(requirement['fact_ids']) < len(original_ids):
            requirement['status'] = 'partial' if requirement['fact_ids'] else 'unanswerable'
            requirement['answer'] = None
            requirement['gap_reason'] = 'Supporting records were expired, withheld, or rejected by the accuracy gate.'
    skipped = {s['adapter']: s['reason'] for s in (run['skipped'] or [])}
    collection = []
    for attempt in attempts:
        name = attempt['adapter']
        count = sum(f['source'] == name for f in facts + inferences)
        collection.append({
            'source': name, 'facts': count,
            'outcome': (attempt['decision'] if attempt['decision'] != 'allowed' else
                        'unavailable' if name in skipped else 'observations' if count else 'no matching data'),
            'reason': skipped.get(name, attempt['decision_reason']),
        })
    scores = score_brief(facts, profile) if not root_subject else score_brief([])
    if root_subject:
        for score in scores.values():
            score['configured'] = False
            score['explanation'] = f'Company service-fit and infrastructure-posture scoring do not apply to an independent {subject_kind} investigation.'
    posture = grade_brief_posture(facts)
    return {
        'subject_kind': subject_kind, 'seed': seed,
        'scores': scores,
        'posture': posture,
        'exposures': posture['exposures'],
        'collection': collection,
        'graph': build_graph(company, facts, subject_kind=subject_kind),
        'power_map': build_power_map(facts) if not root_subject else [],
        'run_id': run_id, 'company': company, 'status': run['status'],
        'stop_reason': run['stop_reason'], 'requirements': requirements,
        'facts': facts, 'inferences': inferences, 'skipped': run['skipped'] or [],
    }


def _literal(value) -> str:
    return str(value).replace('\n', ' ').replace('\r', ' ').replace('`', "'").replace('<', '&lt;').replace('>', '&gt;')


def write_brief(engine: sa.Engine, run_id: str, out: Path) -> tuple[Path, Path]:
    brief = build_brief(engine, run_id)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / f'{run_id}.json'
    md_path = out / f'{run_id}.md'
    json_path.write_text(json.dumps(brief, indent=2, ensure_ascii=False) + '\n')

    posture = brief.get('posture') or {}
    overall = posture.get('overall') or {'letter': 'N/A', 'score': None, 'rationale': 'Not assessed.'}
    categories = posture.get('categories') or {}
    exposures = brief.get('exposures') or []

    lines = [
        f"# Find3r intelligence briefing: {_literal(brief['company'])}",
        '',
        f"Run: {run_id} | {brief['status']} ({_literal(brief['stop_reason'])})",
        f"Subject Kind: `{brief['subject_kind']}` | Exported Facts: **{len(brief['facts'])}** | Prioritized Exposures: **{len(exposures)}** | Overall Posture Grade: **{overall['letter']}** ({overall['score'] if overall['score'] is not None else 'N/A'})",
        '',
        '## Security Posture Assessment (A–F)',
        '',
        f"**Overall Grade: {overall['letter']}** ({overall['score'] if overall['score'] is not None else 'unscored'}) — {_literal(overall['rationale'])}",
        '',
        '| Security Domain | Grade | Score | Rationale |',
        '| :--- | :---: | :---: | :--- |',
    ]
    for cat in categories.values():
        sc = f"{cat['score']}/100" if cat.get('score') is not None else 'N/A'
        lines.append(f"| {cat['label']} | **{cat['letter']}** | {sc} | {_literal(cat['rationale'])} |")

    lines += ['', '## Prioritized Exposures & Remediation Roadmap', '']
    if not exposures:
        lines.append('No actionable security exposures triggered from observed facts in this run.')
    else:
        for exp in exposures:
            lines += [
                f"### [{exp['severity'].upper()}] {_literal(exp['title'])} ({exp['category']})",
                f"- **Observed:** `{_literal(exp['observed'])}`",
                f"- **Impact / Consequence:** {_literal(exp['consequence'])}",
                f"- **Recommended Remediation:** {_literal(exp['remediation'])}",
                f"- **Owner / Stakeholder:** {_literal(exp['stakeholder_function'])}",
                f"- **Evidence IDs:** {', '.join(exp['evidence_ids']) or 'none'}",
                '',
            ]

    lines += ['## Requirements', '']
    score_lines = ['', '## Explained scores', '']
    for key, label in [('commercial_fit', 'Commercial fit'),
                       ('security_needs', 'Evidence of potential security needs')]:
        score = brief['scores'][key]
        score_lines += [f"### {label}", '',
                        f"Score: {score['score'] if score['score'] is not None else 'unassessed'} | coverage: {score['coverage']}%", '',
                        score['explanation'], '']
        for criterion in score['criteria']:
            score_lines += [f"- {criterion['label']}: {criterion['status']}; weight {criterion['weight']}; contribution {criterion['contribution']}. "
                            f"Evidence: {', '.join(criterion['evidence_ids']) or 'none'}. {criterion['explanation']}"]
    requirement_heading = lines.index('## Requirements')
    lines[requirement_heading:requirement_heading] = score_lines
    for requirement in brief['requirements']:
        lines += [f"- {_literal(requirement['question'])} — {requirement['status']}"]
        if requirement['gap_reason']:
            lines += [f"  Gap: {_literal(requirement['gap_reason'])}"]
    for title, key in [('What we know', 'facts'), ('What we infer', 'inferences')]:
        lines += ['', f'## {title}', '']
        if not brief[key]:
            lines += ['No exportable assertions.']
        for fact in brief[key]:
            lines += [f"- `{_literal(fact['subject'])}`: `{_literal(fact['attribute'])}` = `{_literal(fact['value'])}`",
                      f"  Grade: {fact['admiralty']} | confidence: {fact['confidence']}",
                      f"  Fact: {fact['fact_id']} | source record: {fact['source_record_id']}",
                      f"  Source: `{_literal(fact['source'])}` | `{_literal(fact['source_url'] or 'no URL')}`",
                      f"  Collected: {fact['collected_at']} | mode: {fact['collection_mode']}"]
    lines += ['', '## What we could not answer', '']
    gaps = [r for r in brief['requirements'] if r['status'] != 'answered']
    lines += [f"- {_literal(r['question'])}: {_literal(r['gap_reason'] or r['status'])}" for r in gaps] or ['No recorded requirement gaps.']
    lines += [f"- {_literal(s['adapter'])}: {_literal(s['reason'])}" for s in brief['skipped']]
    md_path.write_text('\n'.join(lines) + '\n')
    return md_path, json_path
