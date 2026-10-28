"""Durable scan job status without stored credentials."""
from alembic import op
import sqlalchemy as sa
from backend.models import GUID
revision = '3b281cfef010'
down_revision = '27d80b18e201'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('scan_jobs',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('user_id', GUID(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('repository', sa.String(1024), nullable=False),
        sa.Column('affected_file', sa.String(1024), nullable=False),
        sa.Column('state', sa.String(32), nullable=False),
        sa.Column('analysis_id', GUID(), sa.ForeignKey('analysis_results.id')),
        sa.Column('error', sa.Text()),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False))
    op.create_index('ix_scan_jobs_user_id', 'scan_jobs', ['user_id'])


def downgrade():
    op.drop_table('scan_jobs')
