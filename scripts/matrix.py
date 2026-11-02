"""Retain the locked upstream's seven release targets."""
import json
import sys

TARGETS = [
    {'id': 'android', 'platform': 'android', 'os': 'ubuntu-latest', 'arch': 'all'},
    {'id': 'windows-amd64', 'platform': 'windows', 'os': 'windows-2022', 'arch': 'amd64'},
    {'id': 'linux-amd64', 'platform': 'linux', 'os': 'ubuntu-22.04', 'arch': 'amd64'},
    {'id': 'macos-amd64', 'platform': 'macos', 'os': 'macos-15-intel', 'arch': 'amd64'},
    {'id': 'macos-arm64', 'platform': 'macos', 'os': 'macos-latest', 'arch': 'arm64'},
    {'id': 'windows-arm64', 'platform': 'windows', 'os': 'windows-11-arm', 'arch': 'arm64', 'flutter-channel': 'master'},
    {'id': 'linux-arm64', 'platform': 'linux', 'os': 'ubuntu-24.04-arm', 'arch': 'arm64', 'flutter-channel': 'master'},
]


def select(target):
    if target not in ('all', 'android', 'linux', 'macos', 'windows'):
        raise ValueError('Unknown build target')
    return {'include': [item for item in TARGETS if target in ('all', item['platform'])]}


if __name__ == '__main__':
    print('matrix=' + json.dumps(select(sys.argv[1] if len(sys.argv) > 1 else 'all'), separators=(',', ':')))
