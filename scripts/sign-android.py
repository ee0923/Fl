"""Require explicit release credentials; never accept upstream debug signing fallback."""
import os
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]


def property_value(value):
    encoded = value.encode('utf-16-be')
    result = []
    for offset in range(0, len(encoded), 2):
        unit = int.from_bytes(encoded[offset:offset + 2], 'big')
        if unit in (32, 92):
            result.append('\\' + chr(unit))
        elif unit == 9:
            result.append(r'\t')
        elif 0x21 <= unit <= 0x7e:
            result.append(chr(unit))
        else:
            result.append(r'\u' + format(unit, '04x'))
    return ''.join(result)


def configure(root, env):
    names = ('ANDROID_SIGNING_STORE', 'ANDROID_SIGNING_ALIAS', 'ANDROID_SIGNING_PASSWORD', 'ANDROID_SIGNING_CERT_SHA256')
    if any(not env.get(name) for name in names):
        raise ValueError('Verified KV Android signing identity is required')
    pin = (root / 'release-certificate.sha256').read_text().strip()
    if not re.fullmatch('[0-9a-f]{64}', pin) or env['ANDROID_SIGNING_CERT_SHA256'] != pin:
        raise ValueError('KV Android signing certificate does not match the pinned identity')
    store = Path(env['ANDROID_SIGNING_STORE'])
    temporary = Path(env['RUNNER_TEMP']).resolve()
    if store.is_symlink() or not store.resolve().is_relative_to(temporary) or not store.is_file() or not store.stat().st_size:
        raise ValueError('KV signing store must be a regular file in RUNNER_TEMP')
    keys = ('keyAlias', 'storePassword', 'keyPassword')
    values = [env['ANDROID_SIGNING_ALIAS'], env['ANDROID_SIGNING_PASSWORD'], env['ANDROID_SIGNING_PASSWORD']]
    # Java properties treats backslashes and line breaks as escapes/separators.
    if any(any(char in value for char in '\r\n\0') for value in values):
        raise ValueError('Signing properties must be single-line values')
    values = [property_value(value) for value in values]
    android = root / 'source/android'
    keystore = android / 'app/keystore.jks'
    properties = android / 'local.properties'
    if any(path.exists() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()) for path in (keystore, properties)):
        raise ValueError('Refusing to overwrite existing signing files')
    shutil.copyfile(store, keystore)
    keystore.chmod(0o600)
    properties.write_text(''.join(f'{key}={value}\n' for key, value in zip(keys, values)), encoding='ascii')
    properties.chmod(0o600)
    print('Android release signing configured from verified encrypted KV')


def cleanup(root, env):
    if env.get('GITHUB_ACTIONS') != 'true' or not env.get('RUNNER_TEMP'):
        raise ValueError('Signing cleanup requires the Actions runner')
    for path in (root / 'source/android/app/keystore.jks', root / 'source/android/local.properties'):
        if path.exists() and path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root.resolve()):
            path.unlink()
    directory = Path(env['RUNNER_TEMP']) / 'flclash-release-signing'
    if directory.is_dir() and not directory.is_symlink():
        shutil.rmtree(directory)


if __name__ == '__main__':
    import sys
    try:
        if sys.argv[1:] == ['--cleanup']:
            cleanup(ROOT, os.environ)
        elif not sys.argv[1:]:
            configure(ROOT, os.environ)
        else:
            raise ValueError('Usage: sign-android.py [--cleanup]')
    except ValueError as error:
        print('::error::' + str(error), file=sys.stderr)
        raise SystemExit(1)
