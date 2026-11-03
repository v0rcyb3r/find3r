"""Unlock entity kinds, root entities, and relationship kinds for OSINT graphs.

Revision ID: d4e2f8a9c1b3
Revises: c3f1a7b2d8e4
"""
from alembic import op
import sqlalchemy as sa

revision = "d4e2f8a9c1b3"
down_revision = "c3f1a7b2d8e4"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("entity") as batch:
        batch.drop_constraint("ck_entity_kind", type_="check")
        batch.drop_constraint("ck_entity_company_first", type_="check")
        batch.create_check_constraint(
            "ck_entity_kind",
            "kind IN ('company', 'domain', 'host', 'service', 'person', 'vendor', "
            "'email', 'username', 'ip', 'phone', 'account', 'url')",
        )
        batch.create_check_constraint(
            "ck_entity_company_first",
            "kind IN ('company', 'domain', 'email', 'username', 'person', 'ip', 'phone') "
            "OR company_id IS NOT NULL",
        )
    with op.batch_alter_table("relationship") as batch:
        batch.drop_constraint("ck_relationship_kind", type_="check")
        batch.alter_column("kind", type_=sa.String(48))
        batch.create_check_constraint(
            "ck_relationship_kind",
            "kind IN ('subdomain_of', 'resolves_to', 'resolved_to', 'runs_service', "
            "'employee_of', 'reports_to', 'owns_budget_for', 'influences', "
            "'incumbent_vendor_of', 'same_as', 'account_observed', "
            "'public_provider_metadata', 'published_role', 'historical_dns', "
            "'published_business_email', 'published_business_phone', 'archived_url', "
            "'observed_url', 'uses_ip', 'uses_phone', 'associated_with')",
        )


def downgrade():
    with op.batch_alter_table("relationship") as batch:
        batch.drop_constraint("ck_relationship_kind", type_="check")
        batch.alter_column("kind", type_=sa.String(24))
        batch.create_check_constraint(
            "ck_relationship_kind",
            "kind IN ('subdomain_of', 'resolves_to', 'runs_service', 'employee_of', "
            "'reports_to', 'owns_budget_for', 'influences', 'incumbent_vendor_of', 'same_as')",
        )
    with op.batch_alter_table("entity") as batch:
        batch.drop_constraint("ck_entity_kind", type_="check")
        batch.drop_constraint("ck_entity_company_first", type_="check")
        batch.create_check_constraint(
            "ck_entity_kind",
            "kind IN ('company', 'domain', 'host', 'service', 'person', 'vendor', 'email', 'username')",
        )
        batch.create_check_constraint(
            "ck_entity_company_first",
            "kind IN ('company', 'email', 'username') OR company_id IS NOT NULL",
        )
