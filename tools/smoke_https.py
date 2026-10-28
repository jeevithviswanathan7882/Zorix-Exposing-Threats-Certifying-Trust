"""Deterministic HTTPS/deployment check using synthetic imported evidence."""
import argparse
import json
import secrets
import ssl
import uuid
from urllib.request import Request, urlopen
from urllib.error import HTTPError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default='https://localhost:13443')
    parser.add_argument('--ca', required=True)
    args = parser.parse_args()
    context = ssl.create_default_context(cafile=args.ca)
    def call(path, method='GET', payload=None, token=None):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = f'Bearer {token}'
        request = Request(args.base + path, data=json.dumps(payload).encode() if payload is not None else None,
                          headers=headers, method=method)
        with urlopen(request, context=context, timeout=30) as response:
            return response.read()
    health = json.loads(call('/api/health'))
    assert health['services']['semgrep'] is True
    tokens = []
    for _ in range(2):
        credentials = {'email': f'ci-{uuid.uuid4().hex}@example.com', 'password': secrets.token_urlsafe(24)}
        call('/api/auth/register', 'POST', credentials)
        tokens.append(json.loads(call('/api/auth/login', 'POST', credentials))['access_token'])
    imported = json.loads(call('/api/analysis/import', 'POST', {
        'repo_url': 'https://github.com/example/ci-evidence', 'commit_sha': '0' * 40, 'report_format': 'trivy',
        'report': {'SchemaVersion': 2, 'Results': [{'Target': 'synthetic-ci-fixture', 'Vulnerabilities': [{
            'VulnerabilityID': 'CVE-SYNTHETIC-TEST', 'PkgName': 'fixture', 'InstalledVersion': '1',
            'FixedVersion': '2', 'Severity': 'HIGH', 'Title': 'Synthetic fixture for deployment testing',
        }]}]},
    }, tokens[0]))
    identifier = imported['analysis_id']
    for kind in ('html', 'sarif', 'json'):
        content = call(f'/api/analysis/reports/{identifier}/{kind}', token=tokens[0])
        assert content
        try:
            call(f'/api/analysis/reports/{identifier}/{kind}', token=tokens[1])
        except HTTPError as error:
            assert error.code == 404
        else:
            raise AssertionError('Cross-account evidence access was allowed')
    event = json.loads(call(f'/api/analysis/reports/{identifier}/json', token=tokens[0]))
    assert event['imported'] is True
    assert event['policy']['status'] == 'attention_required'
    assert event['findings'][0]['package']['FixedVersion'] == '2'
    print('HTTPS, secret-backed startup, registration, report import, policy/export, and owner isolation passed')


if __name__ == '__main__':
    main()
