import pytest
from backend.services.evidence_import import normalize_report
from backend.services.sarif_export import build_sarif


def test_trivy_packages_survive_export_without_invented_source_lines():
    findings, provenance = normalize_report({'SchemaVersion': 2, 'Results': [{
        'Target': 'image:demo', 'Vulnerabilities': [{'VulnerabilityID': 'CVE-EXAMPLE',
        'PkgName': 'example', 'InstalledVersion': '1.0', 'FixedVersion': '2.0',
        'Severity': 'HIGH', 'Title': 'Example advisory', 'Secret': 'must not be stored'}],
        'Secrets': [{'Match': 'must not be stored'}],
    }]}, 'trivy')
    assert provenance['imported'] is True
    assert len(provenance['artifact_sha256']) == 64
    assert findings[0]['package']['FixedVersion'] == '2.0'
    assert findings[0]['line'] is None
    assert 'must not be stored' not in str(findings)
    artifact = build_sarif({'status': 'completed', 'findings': findings, **provenance})
    result = artifact['runs'][0]['results'][0]
    assert result['ruleId'] == 'CVE-EXAMPLE'
    assert 'locations' not in result
    assert artifact['runs'][0]['properties']['imported'] is True


def test_sarif_keeps_tools_and_locations_but_discards_snippets():
    report = {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'CodeQL'}},
        'results': [{'ruleId': 'test-rule', 'message': {'text': 'Review'}, 'level': 'error',
        'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'app.py'},
        'region': {'startLine': 4, 'snippet': {'text': 'private source'}}}}]}]}]}
    findings, provenance = normalize_report(report, 'sarif')
    assert provenance['source_tools'] == ['CodeQL']
    assert findings[0]['line'] == 4
    assert findings[0]['severity'] == 'ERROR'
    assert 'private source' not in str(findings)
    report['runs'][0]['invocations'] = [{'executionSuccessful': False}]
    with pytest.raises(ValueError, match='unsuccessful'):
        normalize_report(report, 'sarif')


@pytest.mark.parametrize('report,kind', [({}, 'sarif'), ({}, 'trivy'), ({}, 'unknown'),
    ({'version': '2.1.0', 'runs': []}, 'sarif')])
def test_import_rejects_wrong_schemas(report, kind):
    with pytest.raises(ValueError):
        normalize_report(report, kind)


@pytest.mark.parametrize('kind,report,tool', [
    ('bandit', {'results': [{'test_id': 'B602', 'filename': 'app.py', 'line_number': 2,
       'issue_severity': 'HIGH', 'issue_text': 'Review subprocess', 'code': 'PRIVATE'}], 'errors': []}, 'Bandit'),
    ('gitleaks', {'findings': [{'RuleID': 'token', 'File': '.env', 'StartLine': 1,
       'Description': 'Credential match', 'Secret': 'PRIVATE', 'Match': 'PRIVATE'}]}, 'Gitleaks'),
    ('checkov', {'results': {'failed_checks': [{'check_id': 'CKV_DEMO', 'file_path': 'main.tf',
       'file_line_range': [1, 2], 'check_name': 'Review configuration', 'code_block': ['PRIVATE']}]},
       'summary': {'parsing_errors': 0}}, 'Checkov'),
    ('zap', {'site': [{'@name': 'https://example.com', 'alerts': [{'pluginid': '100', 'riskcode': '3',
       'name': 'Review HTTP finding', 'instances': [{'uri': 'https://user:PRIVATE@example.com/path?token=PRIVATE',
       'evidence': 'PRIVATE', 'attack': 'PRIVATE'}]}]}]}, 'OWASP ZAP'),
    ('nuclei', {'results': [{'template-id': 'demo-template', 'matched-at': 'https://example.com/path?token=PRIVATE',
       'info': {'name': 'Review match', 'severity': 'high'}, 'request': 'PRIVATE', 'response': 'PRIVATE'}]}, 'Nuclei'),
])
def test_additional_tool_adapters_strip_unselected_sensitive_fields(kind, report, tool):
    findings, provenance = normalize_report(report, kind)
    assert len(findings) == 1
    assert provenance['source_tools'] == [tool]
    assert 'PRIVATE' not in str(findings)
    assert findings[0]['source_tool'] == tool


def test_import_limits_prevent_result_amplification():
    report = {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'test'}},
              'results': [{'ruleId': 'r', 'message': {'text': 'm'}}] * 1001}]}
    with pytest.raises(ValueError, match='1000'):
        normalize_report(report, 'sarif')
