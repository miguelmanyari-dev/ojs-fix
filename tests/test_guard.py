"""Safety regression tests. Kernel immutable checks have a separate root-only test."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tarfile
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ojs_fix', str(ROOT / 'ojs_fix.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.profile = json.loads((ROOT / 'examples/profile.example.json').read_text())

    def test_documented_example_validates(self):
        guard.validate_profile(self.profile)

    def test_rejects_unsafe_layouts_and_controls(self):
        cases = [
            ('site_dir', '/'), ('account_home', '/home'), ('account_home', '/var/lib'),
            ('private_dir', '/home/journal/public_html/files'),
            ('state_dir', '/home/journal/guard-state'), ('uid', 0),
            ('runtime_dirs', ['cache', 'public', 'plugins']), ('domain', 'journal.example.org;bad'),
            ('origin_ip', 'not-an-ip'), ('lock_home', False),
            ('site_dir', '/home/journal/../public_html'),
            ('maintenance_flag', '/home/journal/public_html/maintenance.flag'),
        ]
        for key, value in cases:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                p = copy.deepcopy(self.profile)
                p[key] = value
                guard.validate_profile(p)

    def test_forbidden_php_probe_is_mandatory(self):
        self.profile['health_checks'] = [{'path': '/', 'status': '200'}]
        with self.assertRaises(ValueError):
            guard.validate_profile(self.profile)

    def test_rejects_shell_command_and_unsafe_modes(self):
        self.profile['services']['nginx']['test'] = 'nginx -t; something'
        with self.assertRaises(ValueError):
            guard.validate_profile(self.profile)

    def test_privileged_digest_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'real').write_text('private')
            (root / 'link').symlink_to(root / 'real')
            with self.assertRaises(OSError):
                guard.digest(root / 'link')


class FilesystemTests(unittest.TestCase):
    """Simulate immutable flags; exercise real hashing, tar, quarantine and repair I/O."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.home = self.root / 'account'
        self.site = self.home / 'public_html'
        self.data = self.home / 'private'
        self.state = self.root / 'state'
        for path in (self.site / 'cache', self.site / 'public', self.site / 'plugins/empty', self.data, self.state):
            path.mkdir(parents=True, exist_ok=True)
        (self.site / 'index.php').write_text('<?php /* harmless fixture */')
        (self.site / 'config.inc.php').write_text('; fixture, no credentials\n')
        (self.data / 'paper.pdf').write_bytes(b'%PDF-1.4 harmless fixture')
        self.profile = {'uid': os.getuid(), 'gid': os.getgid(), 'release': 'fixture',
                        'maintenance_flag': str(self.root / 'maintenance.flag'),
                        'antivirus': {'command': ['/clamdscan'], 'batch_size': 25},
                        'origin_ip': '203.0.113.10',
                        'health_checks': [{'path': '/blocked.php', 'status': '403'}]}
        self.locked = set()
        def fake_immutable(path, enabled=None):
            key = str(Path(path))
            was = key in self.locked
            if enabled is True:
                self.locked.add(key)
            elif enabled is False:
                self.locked.discard(key)
            return was
        self.patches = [mock.patch.multiple(guard, SITE=self.site, DATA=self.data, STATE=self.state,
                                           HOME=self.home, CONFIG=self.root, DOMAIN='journal.example.org', PROFILE=self.profile),
                        mock.patch.object(guard, 'immutable', side_effect=fake_immutable),
                        mock.patch.object(guard.os, 'chown'), mock.patch.object(guard.os, 'geteuid', return_value=0),
                        mock.patch.object(guard, 'maintenance_active', side_effect=lambda:
                            json.loads((self.state / 'maintenance.json').read_text()).get('until', 0) > time.time())]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)
        guard.jsonfile(self.state / 'maintenance.json', {'until': time.time() + 120})
        guard.approve(self.profile)
        self.baseline = json.loads((self.state / 'baseline.json').read_text())
        (self.state / 'maintenance.json').unlink()

    def tearDown(self):
        self.temp.cleanup()

    def test_baseline_excludes_documents_and_locks_empty_directories(self):
        self.assertNotIn('public/paper.pdf', self.baseline['files'])
        self.assertIn('plugins/empty', self.baseline['directories'])
        self.assertTrue(guard.immutable(self.site / 'plugins/empty'))
        self.assertTrue(guard.immutable(self.home))
        self.assertEqual(0o400, self.baseline['files']['config.inc.php']['mode'])

    def test_restores_changed_code_and_preserves_document(self):
        path = self.site / 'index.php'
        path.chmod(0o644)
        path.write_text('changed')
        _, actions = guard.inspect_code(self.profile, self.baseline, {})
        self.assertIn('harmless fixture', path.read_text())
        self.assertTrue(any(a['kind'] == 'code_restored' for a in actions))
        self.assertTrue((self.data / 'paper.pdf').exists())
        self.assertTrue(list((self.state / 'quarantine').glob('*/payload.disabled')))

    def test_quarantines_unknown_directory_and_symlink_without_following(self):
        target = self.root / 'unrelated'
        target.write_text('keep me')
        (self.site / 'extra').mkdir()
        (self.site / 'extra/unapproved.php').write_text('harmless')
        (self.site / 'link.php').symlink_to(target)
        guard.inspect_code(self.profile, self.baseline, {})
        self.assertFalse((self.site / 'extra').exists())
        self.assertFalse((self.site / 'link.php').exists())
        self.assertEqual('keep me', target.read_text())

    def test_rejects_traversal_or_runtime_entry_in_baseline(self):
        for path in ('../../outside', '/etc/passwd', 'public/unsafe.php'):
            baseline = copy.deepcopy(self.baseline)
            baseline['files'][path] = baseline['files']['index.php']
            with self.subTest(path=path), self.assertRaises(ValueError):
                guard.validate_baseline(baseline)

    def test_corrupt_sealed_archive_never_becomes_restored_code(self):
        path = self.site / 'index.php'
        path.chmod(0o644)
        path.write_text('changed')
        with tarfile.open(str(self.state / 'approved-code.tar'), 'w') as archive:
            archive.add(str(path), arcname='index.php')
        with self.assertRaisesRegex(ValueError, 'Sealed baseline mismatch'):
            guard.inspect_code(self.profile, self.baseline, {})
        self.assertEqual('changed', path.read_text())

    def test_antivirus_quarantines_detected_and_executable_uploads(self):
        (self.data / 'bad.PHp.jpg').write_text('harmless test')
        (self.data / 'flagged.txt').write_text('scanner fixture')
        def scan(argv, timeout):
            if argv[-1].endswith('flagged.txt'):
                return 1, argv[-1] + ': Test-Signature FOUND\n', ''
            return 0, '', ''
        with mock.patch.object(guard, 'execute', side_effect=scan):
            seen, actions, pending = guard.inspect_uploads({})
        self.assertFalse((self.data / 'bad.PHp.jpg').exists())
        self.assertFalse((self.data / 'flagged.txt').exists())
        self.assertTrue((self.data / 'paper.pdf').exists())
        self.assertEqual(2, len(actions))
        self.assertEqual(0, pending)

    def test_antivirus_failure_is_not_recorded_as_clean(self):
        with mock.patch.object(guard, 'execute', return_value=(2, '', 'daemon unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'antivirus unavailable'):
                guard.inspect_uploads({})

    def test_upload_changed_during_scan_stays_pending(self):
        path = self.data / 'paper.pdf'
        def scan(argv, timeout):
            path.write_bytes(b'%PDF-1.4 changed during scan')
            return 0, '', ''
        with mock.patch.object(guard, 'execute', side_effect=scan):
            seen, _, pending = guard.inspect_uploads({})
        self.assertNotIn(str(path), seen)
        self.assertEqual(1, pending)

    def test_expired_maintenance_holds_repair_and_keeps_marker(self):
        guard.jsonfile(self.state / 'maintenance.json', {'until': time.time() - 1})
        with mock.patch.object(guard, 'configure', return_value=self.profile), \
             mock.patch.object(guard, 'enforce_configs') as configs:
            self.assertEqual(1, guard.main(['--profile', '/etc/ojs-fix/profile.json']))
            configs.assert_not_called()
        self.assertTrue((self.state / 'maintenance.json').exists())

    def test_failed_http_probe_prevents_finishing_maintenance(self):
        guard.jsonfile(self.state / 'maintenance.json', {'until': time.time() + 120})
        (self.root / 'maintenance.flag').write_text('hold')
        with mock.patch.object(guard, 'enforce_configs'), \
             mock.patch.object(guard, 'health_checks', return_value=[{'ok': False}]):
            with self.assertRaisesRegex(ValueError, 'HTTP health check failed'):
                guard.finish_maintenance()
        self.assertTrue((self.root / 'maintenance.flag').exists())
        self.assertTrue((self.state / 'maintenance.json').exists())

    def test_invalid_config_rolls_back_before_reload(self):
        config = self.root / 'nginx.conf'
        config.write_text('old configuration')
        profile = {'managed_files': {str(config): {'content': 'invalid new configuration', 'service': 'nginx'}},
                   'services': {'nginx': {'test': ['/nginx', '-t'], 'reload': ['/systemctl', 'reload', 'nginx']}},
                   'reload_order': ['nginx']}
        with mock.patch.object(guard, 'execute', return_value=(1, '', 'syntax error')) as command:
            with self.assertRaisesRegex(ValueError, 'validation failed'):
                guard.enforce_configs(profile)
            self.assertEqual(1, command.call_count)
        self.assertEqual('old configuration', config.read_text())

    def test_origin_probe_checks_exact_status_with_tls_verification(self):
        with mock.patch.object(guard, 'execute', return_value=(0, '200', '')) as command:
            self.assertFalse(guard.health_checks()[0]['ok'])
            argv = command.call_args[0][0]
            self.assertIn('--resolve', argv)
            self.assertNotIn('--insecure', argv)


if __name__ == '__main__':
    unittest.main()
