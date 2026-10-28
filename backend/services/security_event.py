"""Portable security event and explicit review policy, suitable for SIEM ingestion."""
from collections import Counter


def build_security_event(analysis_id, repository, evidence, reviews):
    states = {review.finding_index: review.status for review in reviews}
    findings = evidence.get('findings', [])
    blocking = sum(finding.get('severity') == 'ERROR' and states.get(index) != 'false_positive'
                   for index, finding in enumerate(findings))
    status = 'scanner_incomplete' if evidence.get('status') != 'completed' else 'attention_required' if blocking else 'no_blocking_matches'
    return {'schema': 'zorix.security_event/v1', 'event_type': 'analysis_snapshot',
            'analysis_id': str(analysis_id), 'repository': repository,
            'commit_sha': evidence.get('commit_sha'), 'imported': evidence.get('imported', False),
            'source_tools': evidence.get('source_tools', ['Semgrep']),
            'artifact_sha256': evidence.get('artifact_sha256'), 'rules_sha256': evidence.get('rules_sha256'),
            'scanner_status': evidence.get('status'), 'verification_status': 'unverified',
            'finding_count': len(findings), 'severity_counts': dict(Counter(f.get('severity', 'INFO') for f in findings)),
            'review_counts': dict(Counter(states.get(i, 'open') for i in range(len(findings)))),
            'policy': {'status': status, 'blocking_findings': blocking,
                       'rule': 'ERROR findings block unless reviewed as false_positive; accepted risks remain blocking'},
            'findings': findings}
