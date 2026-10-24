#!/usr/bin/env python3
"""Restore local administrator access for one explicitly selected Harness profile."""
import argparse
import datetime
import json
import os
from pathlib import Path
import shutil
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, default=Path(os.environ.get('DSH_HOME', str(Path.home() / '.deepseek-harness'))), help='Harness data directory; defaults to DSH_HOME or ~/.deepseek-harness')
    parser.add_argument('--profile', default='web', help='Target profile name (default: web)')
    args = parser.parse_args()
    if args.profile in ('', '.', '..') or any(char in args.profile for char in '/\\\0'):
        parser.error('profile must be a single directory name')
    home = args.home.expanduser().resolve()
    profile = home / 'profiles' / args.profile
    manifest_path = profile / 'package.json'
    if not manifest_path.is_file():
        parser.error('target profile package.json does not exist; no changes made')
    manifest = json.loads(manifest_path.read_text())
    selection = manifest.setdefault('dsh', {}).setdefault('profile', {})
    bundles = selection.setdefault('bundles', [])
    if not isinstance(bundles, list) or not all(isinstance(item, str) for item in bundles):
        parser.error('unsupported bundle selection; no changes made')
    patch_path = profile / 'cordis.patch.yml'
    patch = patch_path.read_text() if patch_path.exists() else ''
    settings_path = home / 'web-admin' / 'auth-settings.json'
    settings = json.loads(settings_path.read_text()) if settings_path.exists() else {}
    if not isinstance(settings, dict):
        parser.error('unsupported authentication settings; no changes made')
    settings.update(enabled=False, provider='local')
    package = '@local/dsh-web-user-auth'
    if package not in bundles:
        bundles.append(package)
    # A final overlay preserves unrelated entries and overrides earlier auth settings.
    patch = patch.rstrip() + '\n- id: web-user-auth\n  disabled: false\n  config:\n    enabled: false\n    provider: local\n'
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    for target in (manifest_path, patch_path, settings_path):
        if target.exists():
            backup = target.with_name(target.name + '.recovery-' + stamp)
            shutil.copy2(target, backup)
            print('Backup:', backup)
    settings_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    updates = ((manifest_path, json.dumps(manifest, ensure_ascii=False, indent=2) + '\n'), (patch_path, patch), (settings_path, json.dumps(settings, ensure_ascii=False, indent=2) + '\n'))
    for target, text in updates:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=target.parent, delete=False) as temporary:
            temporary.write(text)
            temporary_path = Path(temporary.name)
        try:
            temporary_path.chmod(0o600)
            temporary_path.replace(target)
        finally:
            temporary_path.unlink(missing_ok=True)
    print('Local administrator access restored for profile:', args.profile)
    print('The plugin must already be installed. Restart the matching Harness instance.')


if __name__ == '__main__':
    main()
