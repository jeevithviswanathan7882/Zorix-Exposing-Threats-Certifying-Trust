"""Append-only finding review history.

Revision ID: 27d80b18e201
Revises: 36c430905f79
"""
from alembic import op
import sqlalchemy as sa
from backend.models import GUID

revision = '27d80b18e201'
down_revision = '36c430905f79'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('finding_review_events',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('analysis_result_id', GUID(), sa.ForeignKey('analysis_results.id'), nullable=False),
        sa.Column('user_id', GUID(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('finding_index', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(32), nullable=False),
        sa.Column('note', sa.Text(), nullable=False),
        sa.Column('event_type', sa.String(32), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_finding_review_events_analysis_result_id', 'finding_review_events', ['analysis_result_id'])
    op.execute("INSERT INTO finding_review_events (id, analysis_result_id, user_id, finding_index, status, note, event_type, created_at) SELECT id, analysis_result_id, user_id, finding_index, status, note, 'baseline_import', updated_at FROM finding_reviews")
    if op.get_bind().dialect.name == 'postgresql':
        op.execute("CREATE FUNCTION zorix_protect_review_events() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Review history is append-only'; END; $$")
        op.execute("CREATE TRIGGER protect_review_events BEFORE UPDATE OR DELETE ON finding_review_events FOR EACH ROW EXECUTE FUNCTION zorix_protect_review_events()")
    else:
        for action in ('UPDATE', 'DELETE'):
            op.execute(f"CREATE TRIGGER protect_review_events_{action.lower()} BEFORE {action} ON finding_review_events BEGIN SELECT RAISE(ABORT, 'Review history is append-only'); END")


def downgrade():
    op.drop_table('finding_review_events')
    if op.get_bind().dialect.name == 'postgresql':
        op.execute('DROP FUNCTION zorix_protect_review_events()')
