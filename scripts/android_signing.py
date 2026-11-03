"""Validate verified APK signers against an independently pinned certificate."""
from pathlib import Path
import base64
import hashlib
import re
import subprocess
import os


def certificate_fingerprints(output):
    # Hash the actual certificates instead of parsing apksigner's human-readable labels.
    blocks = re.findall(r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', output, re.S)
    return {hashlib.sha256(base64.b64decode(''.join(block.split()), validate=True)).hexdigest()
            for block in blocks}


def verify(apksigner, apk, pin_file):
    pin = Path(pin_file).read_text().strip().lower()
    if not re.fullmatch('[0-9a-f]{64}', pin):
        raise ValueError('Invalid signing certificate pin')
    result = subprocess.run([str(apksigner), 'verify', '--verbose', '--print-certs-pem', str(apk)],
                            check=True, capture_output=True, text=True)
    found = certificate_fingerprints(result.stdout)
    if found != {pin}:
        # Only public certificate/verification details; never signing passwords or key material.
        print(result.stdout)
        print(result.stderr)
        details = (result.stdout + '\n' + result.stderr).replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
        print('::error title=APK certificate output::' + details)
        raise ValueError(f'Release certificate mismatch: expected {pin}, found {sorted(found)}')
    print('Release signature and fixed certificate verified: ' + pin)


def verify_packages(root, packages):
    sdk = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
    if not sdk:
        raise ValueError('Android SDK is required to verify release signatures')
    tools = [path for path in (Path(sdk) / 'build-tools').glob('*/apksigner')
             if path.is_file() and re.fullmatch(r'[0-9]+(?:\.[0-9]+){2}', path.parent.name)]
    if not tools or len(packages) != 3:
        raise ValueError('Require apksigner and all three Android ABI packages')
    apksigner = max(tools, key=lambda path: tuple(map(int, path.parent.name.split('.'))))
    for package in packages:
        verify(apksigner, package, root / 'release-certificate.sha256')
    return (root / 'release-certificate.sha256').read_text().strip()
