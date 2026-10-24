#!/usr/bin/env python3
"""Reset the plugin administrator password from the owning server account."""
import argparse
import base64
import datetime
import getpass
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time
import warnings


def encode(value):
    return base64.urlsafe_b64encode(value).decode('ascii').rstrip('=')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, default=Path(os.environ.get('DSH_HOME', str(Path.home() / '.deepseek-harness'))), help='Harness data directory; defaults to DSH_HOME or ~/.deepseek-harness')
    parser.add_argument('--password-stdin', action='store_true', help='Read the new password from standard input instead of a terminal; do not pass it as a command argument')
    args = parser.parse_args()
    home = args.home.expanduser().resolve()
    target = home / 'web-admin' / 'credentials.json'
    if not target.is_file():
        parser.error('administrator credentials not found in this home; no changes made')
    if hasattr(os, 'geteuid') and target.stat().st_uid != os.geteuid():
        parser.error('run as the system account owning the administrator credentials; no changes made')
    original = target.read_bytes()
    try:
        current = json.loads(original)
    except (ValueError, UnicodeError):
        parser.error('administrator credentials are not valid JSON; no changes made')
    if not isinstance(current, dict) or not isinstance(current.get('username'), str) or not current['username']:
        parser.error('administrator username is missing; no changes made')
    if args.password_stdin:
        password = sys.stdin.read(8193).rstrip('\r\n')
    else:
        if not sys.stdin.isatty():
            parser.error('use an interactive terminal or explicitly select --password-stdin')
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            try:
                password = getpass.getpass('New administrator password: ')
                confirm = getpass.getpass('Confirm new password: ')
            except getpass.GetPassWarning:
                parser.error('terminal cannot hide password input; no changes made')
        if password != confirm:
            parser.error('passwords do not match; no changes made')
    if len(password) < 12 or len(password) > 1024 or any(char in password for char in '\r\n\0'):
        parser.error('password must contain 12 to 1024 characters without line breaks or NUL; no changes made')
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=16384, r=8, p=1, dklen=64, maxmem=64 * 1024 * 1024)
    updated = {
        'username': current['username'],
        'passwordHash': 'scrypt$16384$8$1$' + encode(salt) + '$' + encode(key),
        'passwordChangedAt': int(time.time() * 1000),
    }
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    backup = target.with_name(target.name + '.before-reset-' + stamp)
    with open(backup, 'xb', opener=lambda filename, flags: os.open(filename, flags, 0o600)) as stream:
        stream.write(original)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=target.parent, delete=False) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(json.dumps(updated, ensure_ascii=False, indent=2) + '\n')
        temporary_path.chmod(0o600)
        # Refuse to overwrite a change made while the operator was entering a password.
        if target.read_bytes() != original:
            parser.error('administrator credentials changed concurrently; no reset performed')
        temporary_path.replace(target)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    (target.parent / 'initial-password.txt').unlink(missing_ok=True)
    print('Administrator password reset. The password was not printed.')
    print('Backup:', backup)
    print('Restart the matching Harness instance to close existing connections, then sign in with the new password.')
    print('This resets plugin administrator credentials only; it does not enable the plugin or change native Harness authentication.')


if __name__ == '__main__':
    main()
