"""Authenticate the exact Secret payload before executing it against locked source."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def payload():
    raw = os.environ.get('FLCLASH_CUSTOMIZE_SCRIPT', '')
    if not raw.strip():
        raise ValueError('FLCLASH_CUSTOMIZE_SCRIPT repository Secret is required')
    data = (raw.replace('\r\n', '\n').rstrip('\n') + '\n').encode()
    expected = (ROOT / 'customize.sha256').read_text().strip()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('Customization Secret does not match this build snapshot')
    return data, expected


def kv_loader(data):
    policy = json.loads((ROOT / 'ci-customize.json').read_text())
    expected = policy['payload_sha256']
    hook = b'  process.stdout.write(result.script);'
    if not re.fullmatch('[0-9a-f]{64}', expected) or data.count(hook) != 1:
        raise ValueError('Expected the fixed KV-only bootstrap and a pinned payload')
    guard = b'  if (result.sha256 !== ' + json.dumps(expected).encode() + b') throw new Error("KV snapshot mismatch");\n'
    return data.replace(hook, guard + hook), expected


def main():
    data, digest = payload()
    if sys.argv[1:] == ['--check-secret']:
        print('Customization SHA-256: ' + digest)
        return
    verify_only = sys.argv[1:] == ['--verify']
    if sys.argv[1:] and not verify_only:
        raise ValueError('Usage: customize.py [--check-secret|--verify]')
    source = ROOT / 'source'
    lock = json.loads((ROOT / 'sources.lock.json').read_text())
    actual = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != lock['commit']:
        raise ValueError('Source HEAD does not match the reviewed commit')
    bash = os.environ['FLCLASH_BASH']
    loader, expected_payload = kv_loader(data)
    env = dict(os.environ, SOURCE=str(source))
    env.pop('FLCLASH_CUSTOMIZE_SCRIPT', None)
    metadata = None
    for mode in (('--verify',) if verify_only else ('apply', '--verify')):
        result = subprocess.run([bash, '-s', '--', mode], input=b'set +x\n' + loader, env=env, cwd=source, stderr=subprocess.PIPE)
        sys.stderr.buffer.write(result.stderr)
        result.check_returncode()
        matches = re.findall(rb'\[flclash-[a-z-]+\] version=([0-9]+) sha256=([0-9a-f]{64})', result.stderr)
        if len(matches) != 1 or matches[0][1].decode() != expected_payload:
            raise ValueError('Missing or inconsistent verified KV provenance')
        metadata = {'version': int(matches[0][0]), 'sha256': matches[0][1].decode()}
    (ROOT / '.kv-customize.json').write_text(json.dumps(metadata) + '\n')
    print('Verified customization SHA-256: ' + digest)


if __name__ == '__main__':
    try:
        main()
    except ValueError as error:
        print('::error::' + str(error), file=sys.stderr)
        raise SystemExit(1)
