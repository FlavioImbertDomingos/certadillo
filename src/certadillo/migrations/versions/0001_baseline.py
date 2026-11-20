"""Baseline: the schema as of Certadillo 0.1 (November 2026), before Alembic.

Databases created by earlier versions are stamped at this revision on first
start, after their missing nullable columns are added. Column types are the
portable ones from certadillo.db (TIMESTAMP WITH TIME ZONE and JSON as text on
Oracle), so the same revisions build the schema on every supported database.

Revision ID: 0001
Revises: none
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import oracle

import certadillo.db
revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('acme_nonces',
    sa.Column('value', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.PrimaryKeyConstraint('value')
    )
    op.create_table('adcs_findings',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('run_id', sa.String(length=36), nullable=False),
    sa.Column('source', sa.String(length=16), nullable=False),
    sa.Column('object_type', sa.String(length=16), nullable=False),
    sa.Column('object_name', sa.String(length=255), nullable=False),
    sa.Column('esc', sa.String(length=8), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('detail', sa.Text(), nullable=False),
    sa.Column('principals', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('remark', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_adcs_findings_esc'), 'adcs_findings', ['esc'], unique=False)
    op.create_index(op.f('ix_adcs_findings_run_id'), 'adcs_findings', ['run_id'], unique=False)
    op.create_table('agility_drills',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('target_ca', sa.String(length=120), nullable=False),
    sa.Column('source_cas', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('certificate_ids', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('campaign_id', sa.Integer(), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('closed_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=True),
    sa.Column('result', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('created_by', sa.String(length=120), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('alerts',
    sa.Column('fingerprint', sa.String(length=64), nullable=False),
    sa.Column('rule', sa.String(length=64), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('summary', sa.Text(), nullable=False),
    sa.Column('labels', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('first_seen', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('last_notified', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=True),
    sa.Column('resolved_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=True),
    sa.PrimaryKeyConstraint('fingerprint')
    )
    op.create_table('approvals',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('action', sa.String(length=64), nullable=False),
    sa.Column('payload', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('requested_by', sa.String(length=120), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('decided_by', sa.String(length=120), nullable=True),
    sa.Column('decided_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=True),
    sa.Column('comment', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('seal', sa.String(length=64), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('audit_events',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('ts', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('actor', sa.String(length=120), nullable=False),
    sa.Column('action', sa.String(length=64), nullable=False),
    sa.Column('target', sa.String(length=255), nullable=False),
    sa.Column('details', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('prev_hash', sa.String(length=64), nullable=False),
    sa.Column('hash', sa.String(length=64), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('prev_hash')
    )
    op.create_table('audit_ship_cursors',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('sink', sa.String(length=255), nullable=False),
    sa.Column('last_event_id', sa.Integer(), nullable=False),
    sa.Column('last_hash', sa.String(length=64), nullable=True),
    sa.Column('failures', sa.Integer(), nullable=False),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('sink')
    )
    op.create_table('cas',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('parent_id', sa.Integer(), nullable=True),
    sa.Column('subject', sa.String(length=512), nullable=False),
    sa.Column('cert_pem', sa.Text(), nullable=False),
    sa.Column('key_ref', sa.String(length=255), nullable=False),
    sa.Column('signer_type', sa.String(length=32), nullable=False),
    sa.Column('is_root', sa.Boolean(), nullable=False),
    sa.Column('crl_number', sa.Integer(), nullable=False),
    sa.Column('crl_last_generated', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=True),
    sa.Column('crl_der', sa.LargeBinary(), nullable=True),
    sa.Column('ocsp_cert_pem', sa.Text(), nullable=True),
    sa.Column('ocsp_key_ref', sa.String(length=255), nullable=True),
    sa.Column('scep_ra_cert_pem', sa.Text(), nullable=True),
    sa.Column('scep_ra_key_ref', sa.String(length=255), nullable=True),
    sa.Column('cmp_ra_cert_pem', sa.Text(), nullable=True),
    sa.Column('cmp_ra_key_ref', sa.String(length=255), nullable=True),
    sa.Column('tsa_cert_pem', sa.Text(), nullable=True),
    sa.Column('tsa_key_ref', sa.String(length=255), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.ForeignKeyConstraint(['parent_id'], ['cas.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('discovery_findings',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('kind', sa.String(length=32), nullable=False),
    sa.Column('key', sa.String(length=255), nullable=False),
    sa.Column('location', sa.String(length=512), nullable=True),
    sa.Column('detail', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('first_seen', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('acknowledged_by', sa.String(length=120), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('key')
    )
    op.create_index(op.f('ix_discovery_findings_kind'), 'discovery_findings', ['kind'], unique=False)
    op.create_table('discovery_runs',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('source', sa.String(length=120), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('found', sa.Integer(), nullable=False),
    sa.Column('new', sa.Integer(), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('started_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_discovery_runs_source'), 'discovery_runs', ['source'], unique=False)
    op.create_table('external_assets',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.Column('asset_id', sa.String(length=64), nullable=False),
    sa.Column('kind', sa.String(length=16), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('origin', sa.String(length=255), nullable=True),
    sa.Column('origin_type', sa.String(length=32), nullable=True),
    sa.Column('algorithm', sa.String(length=32), nullable=True),
    sa.Column('key_size', sa.Integer(), nullable=True),
    sa.Column('curve', sa.String(length=32), nullable=True),
    sa.Column('location', sa.String(length=512), nullable=True),
    sa.Column('state', sa.String(length=32), nullable=True),
    sa.Column('hardware_backed', sa.Boolean(), nullable=True),
    sa.Column('exportable', sa.Boolean(), nullable=True),
    sa.Column('expires', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=True),
    sa.Column('last_rotated', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=True),
    sa.Column('fingerprint_sha256', sa.String(length=64), nullable=True),
    sa.Column('applications', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('used_by', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('certificate_id', sa.Integer(), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('first_seen', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('source', 'asset_id', name='uq_external_asset')
    )
    op.create_index(op.f('ix_external_assets_fingerprint_sha256'), 'external_assets', ['fingerprint_sha256'], unique=False)
    op.create_table('policy_folders',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('parent_id', sa.Integer(), nullable=True),
    sa.Column('settings', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('created_by', sa.String(length=120), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('seal', sa.String(length=64), nullable=True),
    sa.ForeignKeyConstraint(['parent_id'], ['policy_folders.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_policy_folders_parent_id'), 'policy_folders', ['parent_id'], unique=False)
    op.create_table('renewal_campaigns',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('revocation_reason', sa.String(length=32), nullable=False),
    sa.Column('explanation_url', sa.String(length=1024), nullable=True),
    sa.Column('criteria', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('window_start', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('window_end', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('created_by', sa.String(length=120), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('ssh_keys',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('fingerprint', sa.String(length=64), nullable=False),
    sa.Column('key_type', sa.String(length=48), nullable=False),
    sa.Column('bits', sa.Integer(), nullable=True),
    sa.Column('comment', sa.String(length=200), nullable=True),
    sa.Column('kind', sa.String(length=16), nullable=False),
    sa.Column('host', sa.String(length=255), nullable=False),
    sa.Column('account', sa.String(length=120), nullable=True),
    sa.Column('account_exists', sa.Boolean(), nullable=False),
    sa.Column('path', sa.String(length=512), nullable=False),
    sa.Column('options', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('file_mtime', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=True),
    sa.Column('first_seen', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('owner', sa.String(length=120), nullable=True),
    sa.Column('owner_note', sa.String(length=500), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('host', 'path', 'fingerprint', name='uq_ssh_key_place')
    )
    op.create_index(op.f('ix_ssh_keys_fingerprint'), 'ssh_keys', ['fingerprint'], unique=False)
    op.create_index(op.f('ix_ssh_keys_host'), 'ssh_keys', ['host'], unique=False)
    op.create_table('teams',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('contact_email', sa.String(length=255), nullable=False),
    sa.Column('chat_channel', sa.String(length=255), nullable=True),
    sa.Column('webhook_url', sa.String(length=1024), nullable=True),
    sa.Column('webhook_enc', sa.Text(), nullable=True),
    sa.Column('cost_center', sa.String(length=64), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('apps',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('environment', sa.String(length=16), nullable=False),
    sa.Column('profile', sa.String(length=64), nullable=False),
    sa.Column('allowed_domains', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('data_classification', sa.String(length=32), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('created_by', sa.String(length=120), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('options', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=True),
    sa.Column('folder_id', sa.Integer(), nullable=True),
    sa.Column('seal', sa.String(length=64), nullable=True),
    sa.ForeignKeyConstraint(['folder_id'], ['policy_folders.id'], ),
    sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_index(op.f('ix_apps_folder_id'), 'apps', ['folder_id'], unique=False)
    op.create_table('provisioning_targets',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('kind', sa.String(length=32), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=False),
    sa.Column('config', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('credential_ref', sa.String(length=512), nullable=True),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('created_by', sa.String(length=120), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('seal', sa.String(length=64), nullable=True),
    sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('acme_accounts',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('thumbprint', sa.String(length=64), nullable=False),
    sa.Column('jwk', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('app_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('contact', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.ForeignKeyConstraint(['app_id'], ['apps.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('thumbprint')
    )
    op.create_table('acme_eab',
    sa.Column('kid', sa.String(length=64), nullable=False),
    sa.Column('hmac_key_b64', sa.String(length=128), nullable=False),
    sa.Column('hmac_key_enc', sa.Text(), nullable=True),
    sa.Column('app_id', sa.Integer(), nullable=False),
    sa.Column('used', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.ForeignKeyConstraint(['app_id'], ['apps.id'], ),
    sa.PrimaryKeyConstraint('kid')
    )
    op.create_table('adcs_jobs',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('job_type', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('app_id', sa.Integer(), nullable=True),
    sa.Column('profile', sa.String(length=64), nullable=True),
    sa.Column('adcs_ca', sa.String(length=255), nullable=True),
    sa.Column('adcs_template', sa.String(length=255), nullable=True),
    sa.Column('csr_pem', sa.Text(), nullable=True),
    sa.Column('csr_hash', sa.String(length=64), nullable=True),
    sa.Column('serial_hex', sa.String(length=64), nullable=True),
    sa.Column('reason', sa.String(length=32), nullable=True),
    sa.Column('result_cert_pem', sa.Text(), nullable=True),
    sa.Column('result_chain_pem', sa.Text(), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('certificate_id', sa.Integer(), nullable=True),
    sa.Column('requested_by', sa.String(length=120), nullable=True),
    sa.Column('claimed_by', sa.String(length=120), nullable=True),
    sa.Column('claimed_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.ForeignKeyConstraint(['app_id'], ['apps.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_adcs_jobs_csr_hash'), 'adcs_jobs', ['csr_hash'], unique=False)
    op.create_index(op.f('ix_adcs_jobs_status'), 'adcs_jobs', ['status'], unique=False)
    op.create_table('certificates',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('serial_hex', sa.String(length=64), nullable=False),
    sa.Column('fingerprint_sha256', sa.String(length=64), nullable=False),
    sa.Column('ca_id', sa.Integer(), nullable=True),
    sa.Column('app_id', sa.Integer(), nullable=True),
    sa.Column('issuer', sa.String(length=512), nullable=False),
    sa.Column('common_name', sa.String(length=255), nullable=False),
    sa.Column('sans', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('not_before', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('not_after', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('key_type', sa.String(length=16), nullable=False),
    sa.Column('key_size', sa.Integer(), nullable=False),
    sa.Column('sig_alg', sa.String(length=64), nullable=False),
    sa.Column('profile', sa.String(length=64), nullable=True),
    sa.Column('pem', sa.Text(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('source', sa.String(length=16), nullable=False),
    sa.Column('backend', sa.String(length=32), nullable=False),
    sa.Column('protocol', sa.String(length=16), nullable=True),
    sa.Column('location', sa.String(length=255), nullable=True),
    sa.Column('revoked_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=True),
    sa.Column('revocation_reason', sa.String(length=32), nullable=True),
    sa.Column('replaced_by', sa.Integer(), nullable=True),
    sa.Column('last_seen', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('seal', sa.String(length=64), nullable=True),
    sa.Column('backend_ref', sa.String(length=512), nullable=True),
    sa.Column('chain_pem', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['app_id'], ['apps.id'], ),
    sa.ForeignKeyConstraint(['ca_id'], ['cas.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('fingerprint_sha256')
    )
    op.create_index(op.f('ix_certificates_not_after'), 'certificates', ['not_after'], unique=False)
    op.create_index(op.f('ix_certificates_serial_hex'), 'certificates', ['serial_hex'], unique=False)
    op.create_table('cmp_secrets',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('reference', sa.String(length=64), nullable=False),
    sa.Column('secret_enc', sa.Text(), nullable=False),
    sa.Column('app_id', sa.Integer(), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('used', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.ForeignKeyConstraint(['app_id'], ['apps.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('reference')
    )
    op.create_table('cmp_transactions',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('transaction_id', sa.String(length=64), nullable=False),
    sa.Column('app_id', sa.Integer(), nullable=True),
    sa.Column('secret_id', sa.Integer(), nullable=True),
    sa.Column('sender_cert_pem', sa.Text(), nullable=True),
    sa.Column('certificate_id', sa.Integer(), nullable=True),
    sa.Column('approval_id', sa.Integer(), nullable=True),
    sa.Column('cert_req_id', sa.Integer(), nullable=False),
    sa.Column('body_type', sa.String(length=8), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.ForeignKeyConstraint(['app_id'], ['apps.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('transaction_id')
    )
    op.create_table('est_trust_anchors',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('app_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('cert_pem', sa.Text(), nullable=False),
    sa.Column('created_by', sa.String(length=120), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.ForeignKeyConstraint(['app_id'], ['apps.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('installations',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('app_id', sa.Integer(), nullable=False),
    sa.Column('target_id', sa.Integer(), nullable=False),
    sa.Column('common_name', sa.String(length=255), nullable=False),
    sa.Column('sans', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('key_type', sa.String(length=16), nullable=False),
    sa.Column('key_location', sa.String(length=16), nullable=False),
    sa.Column('params', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('validate_endpoint', sa.String(length=255), nullable=True),
    sa.Column('auto_renew', sa.Boolean(), nullable=False),
    sa.Column('certificate_id', sa.Integer(), nullable=True),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('failures', sa.Integer(), nullable=False),
    sa.Column('next_attempt_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=True),
    sa.Column('created_by', sa.String(length=120), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('seal', sa.String(length=64), nullable=True),
    sa.ForeignKeyConstraint(['app_id'], ['apps.id'], ),
    sa.ForeignKeyConstraint(['target_id'], ['provisioning_targets.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_installations_app_id'), 'installations', ['app_id'], unique=False)
    op.create_index(op.f('ix_installations_target_id'), 'installations', ['target_id'], unique=False)
    op.create_table('principals',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('role', sa.String(length=32), nullable=False),
    sa.Column('key_hash', sa.String(length=64), nullable=False),
    sa.Column('app_id', sa.Integer(), nullable=True),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('created_by', sa.String(length=120), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('seal', sa.String(length=64), nullable=True),
    sa.ForeignKeyConstraint(['app_id'], ['apps.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('key_hash'),
    sa.UniqueConstraint('name')
    )
    op.create_table('scep_challenges',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('challenge_hash', sa.String(length=64), nullable=False),
    sa.Column('app_id', sa.Integer(), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('used', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.ForeignKeyConstraint(['app_id'], ['apps.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('challenge_hash')
    )
    op.create_table('scep_transactions',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('transaction_id', sa.String(length=128), nullable=False),
    sa.Column('app_id', sa.Integer(), nullable=False),
    sa.Column('approval_id', sa.Integer(), nullable=True),
    sa.Column('signer_cert_pem', sa.Text(), nullable=False),
    sa.Column('subject', sa.String(length=512), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('certificate_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.ForeignKeyConstraint(['app_id'], ['apps.id'], ),
    sa.ForeignKeyConstraint(['approval_id'], ['approvals.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scep_transactions_transaction_id'), 'scep_transactions', ['transaction_id'], unique=False)
    op.create_table('signing_keys',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.Column('app_id', sa.Integer(), nullable=False),
    sa.Column('purpose', sa.String(length=16), nullable=False),
    sa.Column('alg', sa.String(length=16), nullable=False),
    sa.Column('key_ref', sa.String(length=255), nullable=False),
    sa.Column('signer_type', sa.String(length=32), nullable=False),
    sa.Column('certificate_id', sa.Integer(), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('created_by', sa.String(length=120), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.ForeignKeyConstraint(['app_id'], ['apps.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('ssh_certificates',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('serial', sa.BigInteger(), nullable=False),
    sa.Column('key_id', sa.String(length=255), nullable=False),
    sa.Column('cert_type', sa.String(length=8), nullable=False),
    sa.Column('principals', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('app_id', sa.Integer(), nullable=True),
    sa.Column('public_key_fp', sa.String(length=128), nullable=False),
    sa.Column('valid_after', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('valid_before', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('cert_text', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.ForeignKeyConstraint(['app_id'], ['apps.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('acme_orders',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('account_id', sa.Integer(), nullable=False),
    sa.Column('identifiers', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('expires', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('certificate_id', sa.Integer(), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('replaces', sa.String(length=255), nullable=True),
    sa.Column('replaces_cert_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['account_id'], ['acme_accounts.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('provisioning_runs',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('installation_id', sa.Integer(), nullable=False),
    sa.Column('trigger', sa.String(length=32), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('certificate_id', sa.Integer(), nullable=True),
    sa.Column('steps', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('actor', sa.String(length=120), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=True),
    sa.ForeignKeyConstraint(['installation_id'], ['installations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_provisioning_runs_installation_id'), 'provisioning_runs', ['installation_id'], unique=False)
    op.create_table('renewal_advice',
    sa.Column('certificate_id', sa.Integer(), nullable=False),
    sa.Column('campaign_id', sa.Integer(), nullable=False),
    sa.Column('window_start', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('window_end', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('revoked_by_campaign', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['campaign_id'], ['renewal_campaigns.id'], ),
    sa.ForeignKeyConstraint(['certificate_id'], ['certificates.id'], ),
    sa.PrimaryKeyConstraint('certificate_id')
    )
    op.create_index(op.f('ix_renewal_advice_campaign_id'), 'renewal_advice', ['campaign_id'], unique=False)
    op.create_table('signing_requests',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('key_id', sa.Integer(), nullable=False),
    sa.Column('requested_by', sa.String(length=120), nullable=False),
    sa.Column('digest_alg', sa.String(length=16), nullable=False),
    sa.Column('digest_hex', sa.String(length=128), nullable=False),
    sa.Column('artifact', sa.JSON().with_variant(certadillo.db.JSONText(), 'oracle'), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('approval_id', sa.Integer(), nullable=True),
    sa.Column('signature_der', sa.LargeBinary(), nullable=True),
    sa.Column('error', sa.String(length=500), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=False),
    sa.Column('signed_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=True),
    sa.ForeignKeyConstraint(['key_id'], ['signing_keys.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('acme_authz',
    sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
    sa.Column('order_id', sa.Integer(), nullable=False),
    sa.Column('identifier', sa.String(length=255), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('token', sa.String(length=64), nullable=False),
    sa.Column('challenge_status', sa.String(length=16), nullable=False),
    sa.Column('validated_at', sa.DateTime(timezone=True).with_variant(oracle.TIMESTAMP(timezone=True), 'oracle'), nullable=True),
    sa.Column('wildcard', sa.Boolean(), nullable=True),
    sa.Column('challenge_type', sa.String(length=16), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['order_id'], ['acme_orders.id'], ),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('acme_authz')
    op.drop_table('signing_requests')
    op.drop_index(op.f('ix_renewal_advice_campaign_id'), table_name='renewal_advice')
    op.drop_table('renewal_advice')
    op.drop_index(op.f('ix_provisioning_runs_installation_id'), table_name='provisioning_runs')
    op.drop_table('provisioning_runs')
    op.drop_table('acme_orders')
    op.drop_table('ssh_certificates')
    op.drop_table('signing_keys')
    op.drop_index(op.f('ix_scep_transactions_transaction_id'), table_name='scep_transactions')
    op.drop_table('scep_transactions')
    op.drop_table('scep_challenges')
    op.drop_table('principals')
    op.drop_index(op.f('ix_installations_target_id'), table_name='installations')
    op.drop_index(op.f('ix_installations_app_id'), table_name='installations')
    op.drop_table('installations')
    op.drop_table('est_trust_anchors')
    op.drop_table('cmp_transactions')
    op.drop_table('cmp_secrets')
    op.drop_index(op.f('ix_certificates_serial_hex'), table_name='certificates')
    op.drop_index(op.f('ix_certificates_not_after'), table_name='certificates')
    op.drop_table('certificates')
    op.drop_index(op.f('ix_adcs_jobs_status'), table_name='adcs_jobs')
    op.drop_index(op.f('ix_adcs_jobs_csr_hash'), table_name='adcs_jobs')
    op.drop_table('adcs_jobs')
    op.drop_table('acme_eab')
    op.drop_table('acme_accounts')
    op.drop_table('provisioning_targets')
    op.drop_index(op.f('ix_apps_folder_id'), table_name='apps')
    op.drop_table('apps')
    op.drop_table('teams')
    op.drop_index(op.f('ix_ssh_keys_host'), table_name='ssh_keys')
    op.drop_index(op.f('ix_ssh_keys_fingerprint'), table_name='ssh_keys')
    op.drop_table('ssh_keys')
    op.drop_table('renewal_campaigns')
    op.drop_index(op.f('ix_policy_folders_parent_id'), table_name='policy_folders')
    op.drop_table('policy_folders')
    op.drop_index(op.f('ix_external_assets_fingerprint_sha256'), table_name='external_assets')
    op.drop_table('external_assets')
    op.drop_index(op.f('ix_discovery_runs_source'), table_name='discovery_runs')
    op.drop_table('discovery_runs')
    op.drop_index(op.f('ix_discovery_findings_kind'), table_name='discovery_findings')
    op.drop_table('discovery_findings')
    op.drop_table('cas')
    op.drop_table('audit_ship_cursors')
    op.drop_table('audit_events')
    op.drop_table('approvals')
    op.drop_table('alerts')
    op.drop_table('agility_drills')
    op.drop_index(op.f('ix_adcs_findings_run_id'), table_name='adcs_findings')
    op.drop_index(op.f('ix_adcs_findings_esc'), table_name='adcs_findings')
    op.drop_table('adcs_findings')
    op.drop_table('acme_nonces')
