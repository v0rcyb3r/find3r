"""Delete one investigation's stored content without resetting spent budget.

This removes managed records and exports, not backups or forensic disk traces.
Shared evidence belonging to another run remains that run's property.
"""
from __future__ import annotations

import re
from pathlib import Path

import sqlalchemy as sa

from neesha.adapters.base import RawResult
from neesha.db import schema


def managed_reports(root: Path, run_id: str) -> list[Path]:
    """Only exact run-ID report names inside a real, nonsymlink reports tree."""
    if not re.fullmatch(r'[0-9a-f]{32}', run_id):
        raise ValueError('Invalid investigation ID.')
    if root.is_symlink():
        raise ValueError('Report storage must not be a symbolic link.')
    if not root.exists():
        return []
    paths = []
    for path in root.rglob('*'):
        if path.name not in {run_id + '.json', run_id + '.md', run_id + '.json.tmp'}:
            continue
        if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != root.parent):
            raise ValueError('A managed report path contains a symbolic link.')
        if path.is_file():
            paths.append(path)
    return paths


def delete_investigation(engine, run_id: str, reports_root: Path) -> dict:
    files = managed_reports(reports_root, run_id)
    with engine.begin() as conn:
        if engine.dialect.name == 'sqlite':
            conn.exec_driver_sql('PRAGMA secure_delete=ON')
        run = conn.execute(sa.select(schema.run).where(schema.run.c.id == run_id)).mappings().one()
        if run['status'] in ('planning', 'running', 'awaiting_approval'):
            raise ValueError('An active investigation cannot be deleted.')
        if conn.execute(sa.select(schema.ledger.c.id).where(
                schema.ledger.c.run_id == run_id, schema.ledger.c.state == 'reserved')).first():
            raise ValueError('This investigation has an unsettled budget reservation.')
        fact_ids = set(conn.execute(sa.select(schema.fact.c.id).where(schema.fact.c.run_id == run_id)).scalars())
        cross_run_source = conn.execute(sa.select(schema.fact.c.id).join(
            schema.source_record, schema.fact.c.source_record_id == schema.source_record.c.id
        ).where(schema.source_record.c.run_id == run_id, schema.fact.c.run_id != run_id).limit(1)).first()
        if cross_run_source:
            raise ValueError('Another investigation references this run’s source records; separate that shared evidence before deletion.')
        source_hashes = set(conn.execute(sa.select(schema.source_record.c.raw_sha256).where(
            schema.source_record.c.run_id == run_id)).scalars())
        # Cache envelopes have no run FK. Evict matching payloads; another run's
        # source records remain intact and future research recollects as needed.
        cache_keys = []
        for row in conn.execute(sa.select(schema.cache)).mappings():
            try:
                if RawResult.from_envelope(row['payload']).sha256 in source_hashes:
                    cache_keys.append(row['key'])
            except (ValueError, KeyError, TypeError):
                continue
        if cache_keys:
            conn.execute(schema.cache.delete().where(schema.cache.c.key.in_(cache_keys)))
        # Derived conclusions supported by deleted facts are invalidated rather
        # than silently keeping their old wording with fewer citations.
        for table in (schema.relationship, schema.exposure, schema.signal):
            ids = [r['id'] for r in conn.execute(sa.select(table)).mappings()
                   if fact_ids.intersection(r['fact_ids'] or [])]
            if ids:
                conn.execute(table.delete().where(table.c.id.in_(ids)))
        conn.execute(schema.signal.delete().where(schema.signal.c.detected_in_run == run_id))
        for row in conn.execute(sa.select(schema.pir).where(schema.pir.c.run_id != run_id)).mappings():
            if fact_ids.intersection(row['fact_ids'] or []):
                conn.execute(schema.pir.update().where(schema.pir.c.id == row['id']).values(
                    status='open', answer=None, fact_ids=[], gap_reason='Supporting investigation was deleted.'))
        conn.execute(schema.pir.delete().where(schema.pir.c.run_id == run_id))
        conn.execute(schema.fact.delete().where(schema.fact.c.run_id == run_id))
        conn.execute(schema.source_record.delete().where(schema.source_record.c.run_id == run_id))
        conn.execute(schema.query_log.delete().where(schema.query_log.c.run_id == run_id))
        # Spend survives deletion so deleting history cannot replenish a cap.
        conn.execute(schema.ledger.update().where(schema.ledger.c.run_id == run_id).values(run_id=None))
        conn.execute(schema.run.delete().where(schema.run.c.id == run_id))
        root_id = run['company_id']
        candidates = list(conn.execute(sa.select(schema.entity.c.id).where(
            sa.or_(schema.entity.c.id == root_id, schema.entity.c.company_id == root_id))).scalars())
        for entity_id in sorted(candidates, key=lambda item: item == root_id):
            uses = (
                sa.select(schema.fact.c.id).where(schema.fact.c.entity_id == entity_id),
                sa.select(schema.run.c.id).where(schema.run.c.company_id == entity_id),
                sa.select(schema.entity.c.id).where(schema.entity.c.company_id == entity_id),
                sa.select(schema.relationship.c.id).where(sa.or_(schema.relationship.c.source_entity_id == entity_id,
                                                               schema.relationship.c.target_entity_id == entity_id)),
                sa.select(schema.exposure.c.id).where(sa.or_(schema.exposure.c.entity_id == entity_id,
                                                           schema.exposure.c.company_id == entity_id)),
                sa.select(schema.signal.c.id).where(schema.signal.c.company_id == entity_id),
            )
            if not any(conn.execute(query.limit(1)).first() for query in uses):
                conn.execute(schema.entity.delete().where(schema.entity.c.id == entity_id))
        engagement_id = run['engagement_id']
        if not conn.execute(sa.select(schema.run.c.id).where(schema.run.c.engagement_id == engagement_id)).first() \
                and not conn.execute(sa.select(schema.query_log.c.id).where(schema.query_log.c.engagement_id == engagement_id)).first():
            conn.execute(schema.engagement.delete().where(schema.engagement.c.id == engagement_id))
    failures = []
    for path in files:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            failures.append(path.name)
    # Best-effort removal from the active SQLite journal; never claim physical
    # erasure on SSDs, other processes' snapshots, or independent backups.
    checkpointed = True
    if engine.dialect.name == 'sqlite':
        try:
            with engine.connect().execution_options(isolation_level='AUTOCOMMIT') as conn:
                result = conn.exec_driver_sql('PRAGMA wal_checkpoint(TRUNCATE)').first()
                checkpointed = not result or result[0] == 0
        except sa.exc.SQLAlchemyError:
            checkpointed = False
    return {'deleted': True, 'run_id': run_id, 'reports_removed': len(files) - len(failures),
            'report_cleanup_failures': failures, 'journal_checkpointed': checkpointed,
            'budget_charges_retained': True,
            'scope': 'Stored investigation, matching caches, and managed reports. Independent backups and downloaded exports are not erased.'}
