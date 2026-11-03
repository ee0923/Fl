"""Collect this job's complete upstream package set and reproducibility metadata."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import android_signing

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def collect(root, platform, arch):
    suffixes = {'linux': ['.AppImage', '.deb', '.rpm'], 'macos': ['.dmg'],
                'windows': ['.exe', '.zip'], 'android': ['-armeabi-v7a.apk', '-arm64-v8a.apk', '-x86_64.apk']}
    if platform not in suffixes or arch not in (('all',) if platform == 'android' else ('amd64', 'arm64')):
        raise ValueError('Unknown package target')
    source = root / 'source'
    version = re.search(r'^version:\s*([^+\s]+)', (source / 'pubspec.yaml').read_text(), re.M)[1]
    packages = []
    for suffix in suffixes[platform]:
        ending = suffix if platform == 'android' else '-' + arch + ('-setup.exe' if suffix == '.exe' else suffix)
        matches = list((source / 'dist').rglob(f'FlClash-{version}-{platform}{ending}'))
        if len(matches) != 1 or not matches[0].is_file() or matches[0].is_symlink() or not matches[0].stat().st_size:
            raise ValueError('Missing, ambiguous or empty package: ' + ending)
        packages.extend(matches)
    certificate = android_signing.verify_packages(root, packages) if platform == 'android' else None
    locks = ('pubspec.lock', 'core/go.sum', 'plugins/rust_api/rust/Cargo.lock', 'services/helper/Cargo.lock')
    lock_hashes = {name: sha(source / name) for name in locks}
    submodules = subprocess.check_output(['git', '-C', str(source), 'submodule', 'status', '--recursive'], text=True).strip()
    if any(line.startswith(('-', '+', 'U')) for line in submodules.splitlines()):
        raise ValueError('Submodule checkout does not match pinned gitlinks')
    destination = root / 'dist'
    destination.mkdir(exist_ok=False)
    files = []
    for path in packages:
        shutil.copyfile(path, destination / path.name)
        files.append({'name': path.name, 'size': path.stat().st_size, 'sha256': sha(path)})
    info = {
        'source': json.loads((root / 'sources.lock.json').read_text()),
        'submodules': submodules,
        'customization_sha256': (root / 'customize.sha256').read_text().strip(),
        'kv_customization': json.loads((root / '.kv-customize.json').read_text()),
        'dependency_lock_sha256': lock_hashes,
        'platform': platform, 'arch': arch,
        'build_repository': os.environ.get('GITHUB_REPOSITORY'),
        'build_commit': os.environ.get('GITHUB_SHA'),
        'run_id': os.environ.get('GITHUB_RUN_ID'), 'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
        'toolchain': {key: os.environ.get(key) for key in ('FLUTTER_VERSION', 'GO_VERSION', 'NDK_VERSION')},
        'signing': 'Verified encrypted KV Android release identity' if platform == 'android' else 'No desktop signing or notarization configured',
        'signing_certificate_sha256': certificate,
        'files': files,
    }
    (destination / f'build-info-{platform}-{arch}.json').write_text(json.dumps(info, indent=2) + '\n')
    (destination / f'SHA256SUMS-{platform}-{arch}.txt').write_text(
        ''.join(f"{item['sha256']}  {item['name']}\n" for item in files))
    # Public dependency locks only; signing properties and keystore never leave source/.
    for name in locks:
        shutil.copyfile(source / name, destination / (f'lock-{platform}-{arch}-' + name.replace('/', '_')))
    return info


if __name__ == '__main__':
    collect(ROOT, sys.argv[1], sys.argv[2])
