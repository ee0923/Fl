"""Require explicit release credentials; never accept upstream debug signing fallback."""
import base64
import os
from pathlib import Path

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
    names = ('KEYSTORE', 'KEY_ALIAS', 'STORE_PASSWORD', 'KEY_PASSWORD')
    if any(not env.get(name) for name in names):
        raise ValueError('Android requires KEYSTORE, KEY_ALIAS, STORE_PASSWORD and KEY_PASSWORD Secrets')
    keys = ('keyAlias', 'storePassword', 'keyPassword')
    values = [env[name] for name in names[1:]]
    # Java properties treats backslashes and line breaks as escapes/separators.
    if any(any(char in value for char in '\r\n\0') for value in values):
        raise ValueError('Signing properties must be single-line values')
    values = [property_value(value) for value in values]
    data = base64.b64decode(env['KEYSTORE'], validate=True)
    if not data:
        raise ValueError('Empty signing keystore')
    android = root / 'source/android'
    keystore = android / 'app/keystore.jks'
    properties = android / 'local.properties'
    if keystore.exists() or properties.exists():
        raise ValueError('Refusing to overwrite existing signing files')
    keystore.write_bytes(data)
    keystore.chmod(0o600)
    properties.write_text(''.join(f'{key}={value}\n' for key, value in zip(keys, values)), encoding='ascii')
    properties.chmod(0o600)
    print('Android release signing configured')


if __name__ == '__main__':
    configure(ROOT, os.environ)
