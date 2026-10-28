"""Exit nonzero when a Zorix security-event artifact requires attention."""
import json
import sys
from pathlib import Path


def check(event):
    if event.get('schema') != 'zorix.security_event/v1':
        raise ValueError('Expected a Zorix security event')
    status = event.get('policy', {}).get('status')
    if status not in ('no_blocking_matches', 'attention_required', 'scanner_incomplete'):
        raise ValueError('Missing or invalid policy status')
    return 0 if status == 'no_blocking_matches' else 1


if __name__ == '__main__':
    try:
        event = json.loads(Path(sys.argv[1]).read_text())
        status = check(event)
        print(event['policy']['status'])
    except (ValueError, OSError, IndexError):
        print('Invalid security event artifact', file=sys.stderr)
        status = 2
    sys.exit(status)
