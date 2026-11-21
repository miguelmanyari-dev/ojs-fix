#!/usr/bin/env python3
"""Opt-in Linux root test. Creates its own isolated fixture; never reads an OJS site."""
import argparse
import errno
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import time
import uuid

MODULE = Path(__file__).resolve().parents[1] / 'ojs_fix.py'
spec = importlib.util.spec_from_file_location('ojs_fix', str(MODULE))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def app_is_denied(uid, gid, operation):
    child = os.fork()
    if child == 0:
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            operation()
            os._exit(1)
        except OSError as error:
            os._exit(0 if error.errno in (errno.EACCES, errno.EPERM) else 2)
        except BaseException:
            os._exit(3)
    _, status = os.waitpid(child, 0)
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


def run(uid, gid):
    guard.require(os.geteuid() == 0 and uid > 0 and gid > 0, 'Root and a non-root fixture uid/gid required')
    root = Path('/var/lib/ojs-fix-test-' + uuid.uuid4().hex)
    home, config, state = root / 'account', root / 'config', root / 'state'
    site, private = home / 'public_html', home / 'private'
    root.mkdir(mode=0o755)
    try:
        for p in (site / 'cache', site / 'public', site / 'plugins/empty', private):
            p.mkdir(parents=True, exist_ok=True)
        config.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
        for p in (home, site, site / 'cache', site / 'public', site / 'plugins', site / 'plugins/empty', private):
            os.chown(str(p), uid, gid)
        (site / 'index.php').write_text('<?php /* fixture only */')
        (site / 'config.inc.php').write_text('; fixture without credentials\n')
        profile = {
            'schema': 1, 'release': 'kernel-test', 'uid': uid, 'gid': gid,
            'site_dir': str(site), 'account_home': str(home), 'private_dir': str(private), 'state_dir': str(state),
            'domain': 'journal.example.org', 'origin_ip': '203.0.113.10', 'lock_home': True,
            'nginx_include': str(config / 'nginx.conf'), 'apache_include': str(config / 'apache.conf'),
            'maintenance_flag': str(config / 'maintenance.flag'),
            'health_checks': [{'path': '/ojs-fix-block-check.php', 'status': '403'}],
            'antivirus': {'command': ['/usr/bin/false']}, 'services': {}, 'managed_files': {}
        }
        guard.jsonfile(config / 'profile.json', profile)
        guard.configure(config / 'profile.json')
        guard.begin_maintenance(5)
        guard.approve(profile)
        baseline = guard.validate_baseline(json.loads((state / 'baseline.json').read_text()))
        assert app_is_denied(uid, gid, lambda: (site / 'index.php').write_text('changed'))
        assert app_is_denied(uid, gid, lambda: (site / 'index.php').chmod(0o644))
        assert app_is_denied(uid, gid, lambda: (site / 'unexpected.php').write_text('harmless'))
        assert app_is_denied(uid, gid, lambda: site.rename(home / 'replacement'))
        # Simulate a privileged accidental edit, then use real sealed-code restoration.
        guard.immutable(site / 'index.php', False)
        (site / 'index.php').write_text('changed by root fixture')
        _, actions = guard.inspect_code(profile, baseline, {})
        assert (site / 'index.php').read_text() == '<?php /* fixture only */'
        assert any(a['kind'] == 'code_restored' for a in actions)
        assert guard.immutable(site / 'index.php')
        # Writable runtime areas retain normal operations under the immutable parent.
        document = private / 'paper.pdf'
        document.write_bytes(b'%PDF-1.4 harmless fixture')
        (site / 'cache/probe').write_text('runtime is writable')
        (site / 'public/logo.txt').write_text('runtime is writable')
        assert document.exists()
        result = {'kernel_immutable_enforced': True, 'application_overwrite_denied': True,
                  'application_chmod_denied': True, 'new_code_denied': True,
                  'webroot_replacement_denied': True, 'sealed_code_restored': True,
                  'runtime_writable': True, 'fixture_only': True}
        print(json.dumps(result, sort_keys=True))
        return result
    finally:
        # Unlock every fixture entry, including files moved into quarantine.
        if root.exists():
            for directory, children, files in os.walk(str(root), topdown=False, followlinks=False):
                for name in files:
                    p = Path(directory) / name
                    if not p.is_symlink():
                        guard.immutable(p, False)
                guard.immutable(directory, False)
            shutil.rmtree(str(root))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--gid', type=int, required=True)
    arguments = parser.parse_args()
    run(arguments.uid, arguments.gid)
