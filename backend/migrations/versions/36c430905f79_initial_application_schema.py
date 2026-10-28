"""initial application schema

Revision ID: 36c430905f79
Revises: None
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from backend.models import GUID


revision: str = '36c430905f79'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Frozen baseline: (required columns, nullable columns).
BASELINE_COLUMNS = {
    'analyses': (('id', 'created_at'), ()),
    'analysis_results': (('id', 'bug_report_id', 'confidence_score', 'created_at'), ('root_cause', 'exploit_payload', 'suggested_patch', 'environment_type')),
    'app_settings': (('id', 'key', 'value'), ()),
    'backend_stage_logs': (('id', 'analysis_result_id', 'stage_name', 'status', 'created_at'), ('start_time', 'end_time', 'output_message')),
    'bug_reports': (('id', 'project_id', 'title', 'repository_url', 'vulnerability_type', 'description', 'affected_file', 'source', 'created_at'), ('severity', 'cve_id', 'affected_line')),
    'code_snapshots': (('id', 'bug_report_id', 'repo_url', 'snapshot_data', 'created_at'), ('commit_hash',)),
    'docker_logs': (('id', 'analysis_result_id', 'status', 'created_at'), ('container_id', 'log_output', 'stdout', 'stderr', 'exit_code', 'execution_time')),
    'dynamic_scan_logs': (('id', 'analysis_result_id', 'repo_url', 'change_detected', 'scan_status', 'created_at'), ('change_log', 'scan_output')),
    'exploit_executions': (('id', 'analysis_result_id', 'exploit_type', 'exploit_payload', 'execution_status', 'vulnerable', 'created_at'), ('stdout', 'stderr', 'return_code', 'execution_time_ms', 'docker_container_id', 'started_at', 'completed_at')),
    'finding_reviews': (('id', 'analysis_result_id', 'user_id', 'finding_index', 'status', 'note', 'updated_at'), ()),
    'log_entries': (('id', 'stage', 'level', 'message', 'timestamp'), ('analysis_id', 'extra')),
    'ollama_prompts': (('id', 'analysis_result_id', 'prompt_type', 'prompt_text', 'generated_time'), ('response_text',)),
    'patches': (('id', 'cve_id', 'vulnerability_type', 'affected_versions', 'created_at'), ('patch_url', 'patch_content', 'release_date')),
    'payload_results': (('id', 'analysis_result_id', 'payload_id', 'payload_type', 'payload_category', 'payload_string', 'execution_status', 'exploit_success', 'created_at'), ('response_output', 'execution_time_ms')),
    'projects': (('id', 'user_id', 'name', 'repository_url', 'created_at'), ()),
    'reports': (('id', 'analysis_result_id', 'report_format', 'file_path', 'file_size', 'generated_at'), ()),
    'scan_results': (('id', 'analysis_result_id', 'scan_type', 'scanner_name', 'finding_count', 'critical_count', 'high_count', 'medium_count', 'low_count', 'created_at'), ('scan_output',)),
    'users': (('id', 'email', 'password_hash', 'role', 'created_at'), ()),
    'vulnerability_scores': (('id', 'analysis_result_id', 'cvss_score', 'severity', 'exploitability', 'impact_score', 'confidence', 'created_at'), ('cvss_vector',)),
}

def upgrade() -> None:
    # Earlier Zorix versions used metadata.create_all without a migration
    # version. Adopt that schema only when every expected table and column is
    # present; a partial schema must be repaired explicitly.
    inspector = sa.inspect(op.get_bind())
    present = set(inspector.get_table_names()) - {"alembic_version"}
    if present:
        expected = set(BASELINE_COLUMNS)
        if present not in (expected, expected - {"finding_reviews"}):
            raise RuntimeError("Existing Zorix schema differs from the migration baseline; back up and review it before upgrading")
        for name in present:
            required, optional = BASELINE_COLUMNS[name]
            actual = {column["name"]: column for column in inspector.get_columns(name)}
            if set(actual) != (set(required) | set(optional)):
                raise RuntimeError(f"Existing {name} columns differ from the migration baseline")
            if any(actual[column]["nullable"] for column in required) or any(not actual[column]["nullable"] for column in optional):
                raise RuntimeError(f"Existing {name} nullability differs from the migration baseline")
        if "finding_reviews" not in present:
            op.create_table('finding_reviews',
                sa.Column('id', GUID(length=36), nullable=False),
                sa.Column('analysis_result_id', GUID(length=36), nullable=False),
                sa.Column('user_id', GUID(length=36), nullable=False),
                sa.Column('finding_index', sa.Integer(), nullable=False),
                sa.Column('status', sa.String(length=32), nullable=False),
                sa.Column('note', sa.Text(), nullable=False),
                sa.Column('updated_at', sa.DateTime(), nullable=False),
                sa.ForeignKeyConstraint(['analysis_result_id'], ['analysis_results.id']),
                sa.ForeignKeyConstraint(['user_id'], ['users.id']),
                sa.PrimaryKeyConstraint('id'),
                sa.UniqueConstraint('analysis_result_id', 'finding_index'),
            )
            op.create_index(op.f('ix_finding_reviews_analysis_result_id'), 'finding_reviews', ['analysis_result_id'])
        return
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('analyses',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('app_settings',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('key', sa.String(length=255), nullable=False),
    sa.Column('value', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_app_settings_key'), 'app_settings', ['key'], unique=True)
    op.create_table('patches',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('cve_id', sa.String(length=50), nullable=False),
    sa.Column('vulnerability_type', sa.String(length=100), nullable=False),
    sa.Column('affected_versions', sa.Text(), nullable=False),
    sa.Column('patch_url', sa.String(length=1024), nullable=True),
    sa.Column('patch_content', sa.Text(), nullable=True),
    sa.Column('release_date', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_patches_cve_id'), 'patches', ['cve_id'], unique=True)
    op.create_table('users',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('password_hash', sa.String(length=255), nullable=False),
    sa.Column('role', sa.String(length=50), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_table('projects',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('user_id', GUID(length=36), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('repository_url', sa.String(length=1024), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_projects_user_id'), 'projects', ['user_id'], unique=False)
    op.create_table('bug_reports',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('project_id', GUID(length=36), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('repository_url', sa.String(length=1024), nullable=False),
    sa.Column('vulnerability_type', sa.String(length=100), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('severity', sa.String(length=50), nullable=True),
    sa.Column('cve_id', sa.String(length=50), nullable=True),
    sa.Column('affected_file', sa.String(length=1024), nullable=False),
    sa.Column('affected_line', sa.Integer(), nullable=True),
    sa.Column('source', sa.String(length=50), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_bug_reports_cve_id'), 'bug_reports', ['cve_id'], unique=False)
    op.create_index(op.f('ix_bug_reports_project_id'), 'bug_reports', ['project_id'], unique=False)
    op.create_table('analysis_results',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('bug_report_id', GUID(length=36), nullable=False),
    sa.Column('root_cause', sa.Text(), nullable=True),
    sa.Column('exploit_payload', sa.Text(), nullable=True),
    sa.Column('suggested_patch', sa.Text(), nullable=True),
    sa.Column('confidence_score', sa.Float(), nullable=False),
    sa.Column('environment_type', sa.String(length=100), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['bug_report_id'], ['bug_reports.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_analysis_results_bug_report_id'), 'analysis_results', ['bug_report_id'], unique=False)
    op.create_table('code_snapshots',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('bug_report_id', GUID(length=36), nullable=False),
    sa.Column('repo_url', sa.String(length=1024), nullable=False),
    sa.Column('commit_hash', sa.String(length=255), nullable=True),
    sa.Column('snapshot_data', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['bug_report_id'], ['bug_reports.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_code_snapshots_bug_report_id'), 'code_snapshots', ['bug_report_id'], unique=False)
    op.create_table('backend_stage_logs',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('analysis_result_id', GUID(length=36), nullable=False),
    sa.Column('stage_name', sa.String(length=100), nullable=False),
    sa.Column('status', sa.String(length=50), nullable=False),
    sa.Column('start_time', sa.DateTime(), nullable=True),
    sa.Column('end_time', sa.DateTime(), nullable=True),
    sa.Column('output_message', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['analysis_result_id'], ['analysis_results.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_backend_stage_logs_analysis_result_id'), 'backend_stage_logs', ['analysis_result_id'], unique=False)
    op.create_table('docker_logs',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('analysis_result_id', GUID(length=36), nullable=False),
    sa.Column('container_id', sa.String(length=255), nullable=True),
    sa.Column('log_output', sa.Text(), nullable=True),
    sa.Column('stdout', sa.Text(), nullable=True),
    sa.Column('stderr', sa.Text(), nullable=True),
    sa.Column('exit_code', sa.Integer(), nullable=True),
    sa.Column('execution_time', sa.Integer(), nullable=True),
    sa.Column('status', sa.String(length=50), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['analysis_result_id'], ['analysis_results.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_docker_logs_analysis_result_id'), 'docker_logs', ['analysis_result_id'], unique=False)
    op.create_table('dynamic_scan_logs',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('analysis_result_id', GUID(length=36), nullable=False),
    sa.Column('repo_url', sa.String(length=1024), nullable=False),
    sa.Column('change_detected', sa.Boolean(), nullable=False),
    sa.Column('change_log', sa.Text(), nullable=True),
    sa.Column('scan_status', sa.String(length=50), nullable=False),
    sa.Column('scan_output', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['analysis_result_id'], ['analysis_results.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_dynamic_scan_logs_analysis_result_id'), 'dynamic_scan_logs', ['analysis_result_id'], unique=False)
    op.create_table('exploit_executions',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('analysis_result_id', GUID(length=36), nullable=False),
    sa.Column('exploit_type', sa.String(length=100), nullable=False),
    sa.Column('exploit_payload', sa.Text(), nullable=False),
    sa.Column('execution_status', sa.String(length=50), nullable=False),
    sa.Column('stdout', sa.Text(), nullable=True),
    sa.Column('stderr', sa.Text(), nullable=True),
    sa.Column('return_code', sa.Integer(), nullable=True),
    sa.Column('execution_time_ms', sa.Integer(), nullable=True),
    sa.Column('vulnerable', sa.Boolean(), nullable=False),
    sa.Column('docker_container_id', sa.String(length=255), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('started_at', sa.DateTime(), nullable=True),
    sa.Column('completed_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['analysis_result_id'], ['analysis_results.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_exploit_executions_analysis_result_id'), 'exploit_executions', ['analysis_result_id'], unique=False)
    op.create_table('finding_reviews',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('analysis_result_id', GUID(length=36), nullable=False),
    sa.Column('user_id', GUID(length=36), nullable=False),
    sa.Column('finding_index', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('note', sa.Text(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['analysis_result_id'], ['analysis_results.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('analysis_result_id', 'finding_index')
    )
    op.create_index(op.f('ix_finding_reviews_analysis_result_id'), 'finding_reviews', ['analysis_result_id'], unique=False)
    op.create_table('log_entries',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('analysis_id', GUID(length=36), nullable=True),
    sa.Column('stage', sa.String(length=100), nullable=False),
    sa.Column('level', sa.String(length=20), nullable=False),
    sa.Column('message', sa.Text(), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=False),
    sa.Column('extra', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['analysis_id'], ['analysis_results.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_log_entries_analysis_id'), 'log_entries', ['analysis_id'], unique=False)
    op.create_table('ollama_prompts',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('analysis_result_id', GUID(length=36), nullable=False),
    sa.Column('prompt_type', sa.String(length=100), nullable=False),
    sa.Column('prompt_text', sa.Text(), nullable=False),
    sa.Column('response_text', sa.Text(), nullable=True),
    sa.Column('generated_time', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['analysis_result_id'], ['analysis_results.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ollama_prompts_analysis_result_id'), 'ollama_prompts', ['analysis_result_id'], unique=False)
    op.create_table('payload_results',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('analysis_result_id', GUID(length=36), nullable=False),
    sa.Column('payload_id', sa.String(length=100), nullable=False),
    sa.Column('payload_type', sa.String(length=100), nullable=False),
    sa.Column('payload_category', sa.String(length=100), nullable=False),
    sa.Column('payload_string', sa.Text(), nullable=False),
    sa.Column('execution_status', sa.String(length=50), nullable=False),
    sa.Column('response_output', sa.Text(), nullable=True),
    sa.Column('exploit_success', sa.Boolean(), nullable=False),
    sa.Column('execution_time_ms', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['analysis_result_id'], ['analysis_results.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_payload_results_analysis_result_id'), 'payload_results', ['analysis_result_id'], unique=False)
    op.create_table('reports',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('analysis_result_id', GUID(length=36), nullable=False),
    sa.Column('report_format', sa.String(length=20), nullable=False),
    sa.Column('file_path', sa.String(length=1024), nullable=False),
    sa.Column('file_size', sa.Integer(), nullable=False),
    sa.Column('generated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['analysis_result_id'], ['analysis_results.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_reports_analysis_result_id'), 'reports', ['analysis_result_id'], unique=True)
    op.create_table('scan_results',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('analysis_result_id', GUID(length=36), nullable=False),
    sa.Column('scan_type', sa.String(length=50), nullable=False),
    sa.Column('scanner_name', sa.String(length=100), nullable=False),
    sa.Column('finding_count', sa.Integer(), nullable=False),
    sa.Column('critical_count', sa.Integer(), nullable=False),
    sa.Column('high_count', sa.Integer(), nullable=False),
    sa.Column('medium_count', sa.Integer(), nullable=False),
    sa.Column('low_count', sa.Integer(), nullable=False),
    sa.Column('scan_output', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['analysis_result_id'], ['analysis_results.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_results_analysis_result_id'), 'scan_results', ['analysis_result_id'], unique=False)
    op.create_table('vulnerability_scores',
    sa.Column('id', GUID(length=36), nullable=False),
    sa.Column('analysis_result_id', GUID(length=36), nullable=False),
    sa.Column('cvss_score', sa.Float(), nullable=False),
    sa.Column('cvss_vector', sa.String(length=255), nullable=True),
    sa.Column('severity', sa.String(length=20), nullable=False),
    sa.Column('exploitability', sa.Float(), nullable=False),
    sa.Column('impact_score', sa.Float(), nullable=False),
    sa.Column('confidence', sa.Float(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['analysis_result_id'], ['analysis_results.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_vulnerability_scores_analysis_result_id'), 'vulnerability_scores', ['analysis_result_id'], unique=True)
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_vulnerability_scores_analysis_result_id'), table_name='vulnerability_scores')
    op.drop_table('vulnerability_scores')
    op.drop_index(op.f('ix_scan_results_analysis_result_id'), table_name='scan_results')
    op.drop_table('scan_results')
    op.drop_index(op.f('ix_reports_analysis_result_id'), table_name='reports')
    op.drop_table('reports')
    op.drop_index(op.f('ix_payload_results_analysis_result_id'), table_name='payload_results')
    op.drop_table('payload_results')
    op.drop_index(op.f('ix_ollama_prompts_analysis_result_id'), table_name='ollama_prompts')
    op.drop_table('ollama_prompts')
    op.drop_index(op.f('ix_log_entries_analysis_id'), table_name='log_entries')
    op.drop_table('log_entries')
    op.drop_index(op.f('ix_finding_reviews_analysis_result_id'), table_name='finding_reviews')
    op.drop_table('finding_reviews')
    op.drop_index(op.f('ix_exploit_executions_analysis_result_id'), table_name='exploit_executions')
    op.drop_table('exploit_executions')
    op.drop_index(op.f('ix_dynamic_scan_logs_analysis_result_id'), table_name='dynamic_scan_logs')
    op.drop_table('dynamic_scan_logs')
    op.drop_index(op.f('ix_docker_logs_analysis_result_id'), table_name='docker_logs')
    op.drop_table('docker_logs')
    op.drop_index(op.f('ix_backend_stage_logs_analysis_result_id'), table_name='backend_stage_logs')
    op.drop_table('backend_stage_logs')
    op.drop_index(op.f('ix_code_snapshots_bug_report_id'), table_name='code_snapshots')
    op.drop_table('code_snapshots')
    op.drop_index(op.f('ix_analysis_results_bug_report_id'), table_name='analysis_results')
    op.drop_table('analysis_results')
    op.drop_index(op.f('ix_bug_reports_project_id'), table_name='bug_reports')
    op.drop_index(op.f('ix_bug_reports_cve_id'), table_name='bug_reports')
    op.drop_table('bug_reports')
    op.drop_index(op.f('ix_projects_user_id'), table_name='projects')
    op.drop_table('projects')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
    op.drop_index(op.f('ix_patches_cve_id'), table_name='patches')
    op.drop_table('patches')
    op.drop_index(op.f('ix_app_settings_key'), table_name='app_settings')
    op.drop_table('app_settings')
    op.drop_table('analyses')
    # ### end Alembic commands ###
