"""Normalize bounded tool reports; discard snippets, credentials, and raw responses."""
import hashlib
import json
from urllib.parse import urlsplit, urlunsplit

MAX_REPORT_BYTES = 1_000_000
MAX_FINDINGS = 1000


def text(value, limit=4000):
    if not isinstance(value, (str, int, float)):
        return ''
    return str(value)[:limit]


def _normalize_report(report: dict, report_format: str) -> tuple[list[dict], dict]:
    if not isinstance(report, dict):
        raise ValueError('Report must be a JSON object')
    encoded = json.dumps(report, sort_keys=True, ensure_ascii=False).encode()
    if len(encoded) > MAX_REPORT_BYTES:
        raise ValueError('Report exceeds the 1 MB import limit')
    findings, tools = [], set()
    def append(finding):
        if len(findings) >= MAX_FINDINGS:
            raise ValueError('Report exceeds the 1000 finding limit')
        findings.append(finding)
    if report_format == 'sarif':
        if report.get('version') != '2.1.0' or not isinstance(report.get('runs'), list) or not report['runs']:
            raise ValueError('Expected a SARIF 2.1.0 report with runs')
        if len(report['runs']) > 50:
            raise ValueError('Report exceeds the 50 run limit')
        for run in report['runs']:
            if not isinstance(run, dict):
                raise ValueError('Invalid SARIF run')
            if any(invocation.get('executionSuccessful') is False for invocation in run.get('invocations', [])):
                raise ValueError('SARIF reports an unsuccessful tool execution')
            tool = text(run.get('tool', {}).get('driver', {}).get('name'), 100)
            if not tool:
                raise ValueError('SARIF tool name is required')
            tools.add(tool)
            results = run.get('results', [])
            if not isinstance(results, list):
                raise ValueError('Invalid SARIF results')
            for item in results:
                location = (item.get('locations') or [{}])[0].get('physicalLocation', {})
                line = location.get('region', {}).get('startLine')
                append({
                    'rule_id': text(item.get('ruleId') or 'unclassified', 255),
                    'file': safe_url(location.get('artifactLocation', {}).get('uri') or '(artifact)'),
                    'line': line if isinstance(line, int) and not isinstance(line, bool) and line > 0 else None,
                    'severity': {'error': 'ERROR', 'warning': 'WARNING', 'note': 'INFO', 'none': 'INFO'}.get(item.get('level', 'warning'), 'WARNING'),
                    'message': text(item.get('message', {}).get('text') or item.get('message', {}).get('markdown') or 'Review tool evidence'),
                    'source_tool': tool,
                })
                if len(findings) > MAX_FINDINGS:
                    raise ValueError('Report exceeds the 1000 finding limit')
    elif report_format == 'trivy':
        if report.get('SchemaVersion') != 2 or not isinstance(report.get('Results'), list):
            raise ValueError('Expected a Trivy SchemaVersion 2 vulnerability report')
        tools.add('Trivy')
        for result in report['Results']:
            for item in result.get('Vulnerabilities') or []:
                severity = text(item.get('Severity')).upper()
                package = {key: text(item.get(key), 1024) for key in (
                    'PkgName', 'InstalledVersion', 'FixedVersion', 'PkgID', 'PkgPath')}
                append({
                    'rule_id': text(item.get('VulnerabilityID') or 'unclassified', 255),
                    'file': text(result.get('Target') or '(artifact)', 1024), 'line': None,
                    'severity': 'ERROR' if severity in ('CRITICAL', 'HIGH') else 'WARNING' if severity == 'MEDIUM' else 'INFO',
                    'source_severity': severity, 'source_tool': 'Trivy', 'package': package,
                    'message': text(item.get('Title') or item.get('Description') or 'Review package advisory'),
                })
                if len(findings) > MAX_FINDINGS:
                    raise ValueError('Report exceeds the 1000 finding limit')
    elif report_format == 'bandit':
        if not isinstance(report.get('results'), list) or report.get('errors'):
            raise ValueError('Expected a successful Bandit JSON report')
        tools.add('Bandit')
        for item in report['results']:
            severity = text(item.get('issue_severity')).upper()
            append({'rule_id': text(item.get('test_id') or 'bandit:unclassified', 255),
                'file': text(item.get('filename') or '(artifact)', 1024),
                'line': positive_line(item.get('line_number')), 'severity': normalize_severity(severity),
                'source_severity': severity, 'source_tool': 'Bandit',
                'message': text(item.get('issue_text') or item.get('test_name') or 'Review Python finding')})
    elif report_format == 'gitleaks':
        if not isinstance(report.get('findings'), list):
            raise ValueError('Expected Gitleaks findings wrapped in a findings array')
        tools.add('Gitleaks')
        for item in report['findings']:
            append({'rule_id': text(item.get('RuleID') or 'gitleaks:unclassified', 255),
                'file': text(item.get('File') or '(artifact)', 1024), 'line': positive_line(item.get('StartLine')),
                'severity': 'ERROR', 'source_tool': 'Gitleaks',
                'message': text(item.get('Description') or 'Potential exposed credential; secret value omitted')})
    elif report_format == 'zap':
        if not isinstance(report.get('site'), list):
            raise ValueError('Expected a ZAP traditional JSON report with sites')
        tools.add('OWASP ZAP')
        for site in report['site']:
            for item in site.get('alerts', []):
                severity = {'3': 'HIGH', '2': 'MEDIUM', '1': 'LOW', '0': 'INFO'}.get(str(item.get('riskcode')), 'UNSPECIFIED')
                instances = item.get('instances') or [{}]
                for instance in instances:
                    append({'rule_id': 'zap:' + text(item.get('pluginid') or item.get('alertRef') or 'unclassified', 250),
                        'file': safe_url(instance.get('uri') or site.get('@name') or '(artifact)'), 'line': None,
                        'severity': normalize_severity(severity), 'source_severity': severity, 'source_tool': 'OWASP ZAP',
                        'message': text(item.get('name') or item.get('alert') or 'Review DAST alert')})
    elif report_format == 'nuclei':
        if not isinstance(report.get('results'), list):
            raise ValueError('Expected Nuclei JSONL records wrapped in results')
        tools.add('Nuclei')
        for item in report['results']:
            if not item.get('template-id'):
                raise ValueError('Nuclei template-id is required')
            info = item.get('info', {})
            severity = text(info.get('severity') or 'UNSPECIFIED').upper()
            append({'rule_id': text(item['template-id'], 255),
                'file': safe_url(item.get('matched-at') or item.get('host') or '(artifact)'), 'line': None,
                'severity': normalize_severity(severity), 'source_severity': severity, 'source_tool': 'Nuclei',
                'message': text(info.get('name') or 'Review template match')})
    elif report_format == 'checkov':
        sections = report.get('reports', [report])
        if not isinstance(sections, list) or not sections:
            raise ValueError('Expected Checkov results')
        tools.add('Checkov')
        for section in sections:
            if section.get('summary', {}).get('parsing_errors', 0) or not isinstance(section.get('results', {}).get('failed_checks'), list):
                raise ValueError('Expected successful Checkov parsing and a failed_checks array')
            for item in section['results']['failed_checks']:
                severity = text(item.get('severity') or 'UNSPECIFIED').upper()
                lines = item.get('file_line_range') or []
                append({'rule_id': text(item.get('check_id') or 'checkov:unclassified', 255),
                    'file': text(item.get('file_path') or '(artifact)', 1024),
                    'line': positive_line(lines[0]) if lines else None, 'severity': normalize_severity(severity),
                    'source_severity': severity, 'source_tool': 'Checkov',
                    'message': text(item.get('check_name') or 'Review infrastructure configuration')})
    else:
        raise ValueError('Unsupported report format')
    if len(findings) > MAX_FINDINGS:
        raise ValueError('Report exceeds the 1000 finding limit')
    return findings, {'source_tools': sorted(tools), 'imported': True,
                      'artifact_sha256': hashlib.sha256(encoded).hexdigest()}


def positive_line(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def normalize_severity(severity):
    return 'ERROR' if severity in ('CRITICAL', 'HIGH') else 'WARNING' if severity in ('MEDIUM', 'UNSPECIFIED', '') else 'INFO'


def safe_url(value):
    value = text(value, 1024)
    parts = urlsplit(value)
    if parts.scheme in ('http', 'https') and parts.hostname:
        host = parts.hostname
        if ':' in host:
            host = f'[{host}]'
        if parts.port:
            host += f':{parts.port}'
        return urlunsplit((parts.scheme, host, parts.path, '', ''))
    return value


def normalize_report(report, report_format):
    try:
        return _normalize_report(report, report_format)
    except (AttributeError, TypeError, IndexError, KeyError) as exc:
        raise ValueError('Malformed tool report') from exc
