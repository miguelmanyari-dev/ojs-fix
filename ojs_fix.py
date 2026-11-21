#!/usr/bin/python3
"""OJS-Fix: root-owned OJS integrity, uploads and per-site web configuration guard.

Only an explicitly approved root-owned baseline can restore application code.
Runtime documents are never overwritten by the integrity repair mechanism.
"""
import argparse
import array
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import uuid

VERSION = '0.2.0'
SITE = DATA = CONFIG = STATE = HOME = None
DOMAIN = ''
PROFILE = {}
RUNTIME = ('cache', 'public')
NGINX_INCLUDE = APACHE_INCLUDE = ''


def require(condition, message):
    if not condition:
        raise ValueError(str(message))


def inside(path, parent):
    return path == parent or parent in path.parents


def absolute_path(value):
    require(isinstance(value, str) and value.startswith('/'), 'Absolute path required')
    path = pathlib.Path(value)
    require('..' not in path.parts and len(path.parts) >= 3, 'Unsafe or overly broad path: ' + value)
    require(not re.search(r'[\x00-\x20;"{}$\\]', value), 'Unsafe characters in path')
    return path


def reject_symlinks(path):
    for component in [path] + list(path.parents):
        require(not component.is_symlink(), 'Symlink in configured path: ' + str(component))


def protected_file(path):
    """Trust root-controlled files only, including their parent directory chain."""
    path = pathlib.Path(path)
    reject_symlinks(path)
    require(path.is_file(), 'Protected configuration is not a regular file: ' + str(path))
    for component in [path] + list(path.parents):
        st = component.stat()
        require(st.st_uid == 0 and not st.st_mode & 0o022,
                'Configuration must be root-owned and not group/world writable: ' + str(component))


def validate_profile(profile):
    require(profile.get('schema') == 1, 'Unsupported profile schema')
    for key in ('uid', 'gid'):
        require(type(profile.get(key)) is int and profile[key] > 0, 'Dedicated non-root uid/gid required')
    site = absolute_path(profile['site_dir'])
    home = absolute_path(profile['account_home'])
    data = absolute_path(profile['private_dir'])
    state = absolute_path(profile['state_dir'])
    require(str(home) not in ('/var/lib', '/var/www', '/usr/local', '/opt/alt', '/srv/www',
                             '/etc/nginx', '/etc/httpd', '/etc/apache2'),
            'account_home must be a dedicated account, not a system directory')
    require(len(home.parts) >= 3 and site.parent == home and site != data,
            'site_dir must be a direct child of a dedicated account_home')
    require(inside(data, home) and data != home and not inside(data, site),
            'Private files must be outside the web root and inside the dedicated account')
    require(not inside(state, home) and not inside(home, state), 'State must be outside the account')
    require(not inside(site, state) and not inside(state, site), 'State overlaps application code')
    require(profile.get('lock_home') is True, 'A dedicated immutable account home is required')
    require(profile.get('runtime_dirs', ['cache', 'public']) == ['cache', 'public'],
            'Only cache and public may be excluded from the code baseline')
    domain = profile['domain']
    require(isinstance(domain, str) and len(domain) <= 253 and '.' in domain and
            all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', part)
                for part in domain.split('.')), 'Invalid domain')
    ipaddress.ip_address(profile['origin_ip'])
    require(isinstance(profile.get('release'), str) and bool(profile['release']), 'Release label required')
    paths = [site, data, state, home]
    for key in ('nginx_include', 'apache_include', 'maintenance_flag'):
        control = absolute_path(profile[key])
        require(not inside(control, home) and not inside(control, state), 'Web control path overlaps account/state')
        paths.append(control)
    services = profile.get('services', {})
    for service, commands in services.items():
        require(re.fullmatch(r'[A-Za-z0-9_.@-]+', service), 'Invalid service name')
        for operation in ('test', 'reload'):
            command = commands[operation]
            require(isinstance(command, list) and command and all(isinstance(x, str) for x in command),
                    'Service commands must be argv arrays')
            require(command[0].startswith('/'), 'Absolute service executable required')
    require(set(profile.get('reload_order', services)) == set(services), 'reload_order must list every service')
    for path, spec in profile.get('managed_files', {}).items():
        target = absolute_path(path)
        source = absolute_path(spec['source'])
        require(not inside(target, home) and not inside(target, state), 'Managed config overlaps application/state')
        require(target != source, 'Config source and destination must differ')
        require(spec.get('service') is None or spec['service'] in services, 'Unknown managed service')
        require(spec.get('mode', 0o644) in (0o600, 0o640, 0o644), 'Unsafe managed file mode')
        paths.extend([target, source])
    for key in ('nginx_vhosts', 'apache_vhosts'):
        for value in profile.get(key, []):
            path = absolute_path(value)
            require(not inside(path, site) and not inside(path, state), 'Vhost overlaps application/state')
            paths.append(path)
    if profile.get('cwp_metadata'):
        meta = absolute_path(profile['cwp_metadata'])
        require(inside(meta, home / '.conf' / 'webservers'), 'CWP metadata must belong to this account')
        paths.append(meta)
    if profile.get('php_socket'):
        paths.append(absolute_path(profile['php_socket']))
    for socket in profile.get('old_php_sockets', []):
        require(profile.get('php_socket'), 'A replacement PHP socket is required')
        paths.append(absolute_path(socket))
    antivirus = profile['antivirus']
    require(isinstance(antivirus.get('command'), list) and antivirus['command'] and
            all(isinstance(x, str) for x in antivirus['command']) and antivirus['command'][0].startswith('/'),
            'Antivirus command must be an absolute argv array')
    require(1 <= antivirus.get('batch_size', 25) <= 100, 'Antivirus batch_size out of range')
    require(1 <= antivirus.get('timeout_seconds', 12) <= 30, 'Antivirus timeout out of range')
    require(1 <= antivirus.get('budget_seconds', 25) <= 60, 'Antivirus budget out of range')
    probes = profile.get('health_checks', [])
    require(bool(probes), 'HTTP probes are required')
    require(any(str(p.get('status')) == '403' and p.get('path', '').endswith('.php') for p in probes),
            'Include a forbidden unknown-PHP probe to detect ineffective web reloads')
    for probe in probes:
        path = probe['path']
        require(isinstance(path, str) and path.startswith('/') and not path.startswith('//') and
                not re.search(r'[\x00-\x20#]', path), 'Invalid HTTP probe path')
        require(re.fullmatch(r'[1-5][0-9]{2}', str(probe['status'])), 'Invalid HTTP probe status')
    return paths


def configure(profile_path):
    global SITE, DATA, CONFIG, STATE, HOME, DOMAIN, PROFILE, NGINX_INCLUDE, APACHE_INCLUDE
    path = absolute_path(str(profile_path))
    protected_file(path)
    profile = json.loads(path.read_text())
    for item in validate_profile(profile):
        reject_symlinks(item)
    SITE = pathlib.Path(profile['site_dir'])
    DATA = pathlib.Path(profile['private_dir'])
    HOME = pathlib.Path(profile['account_home'])
    CONFIG = path.parent
    STATE = pathlib.Path(profile['state_dir'])
    DOMAIN = profile['domain']
    require(not inside(CONFIG, HOME) and not inside(CONFIG, STATE), 'Configuration must be outside account/state')
    for spec in profile.get('managed_files', {}).values():
        source = pathlib.Path(spec['source'])
        require(inside(source, CONFIG), 'Approved config sources must be inside the protected profile directory')
        protected_file(source)
        spec['content'] = source.read_text()
    for root in (HOME, SITE, DATA, SITE / 'cache', SITE / 'public'):
        require(root.is_dir() and not root.is_symlink(), 'Missing or symlinked application directory: ' + str(root))
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(STATE.stat().st_uid == 0 and not STATE.stat().st_mode & 0o077, 'State must be root-owned mode 0700')
    for parent in STATE.parents:
        st = parent.stat()
        require(st.st_uid == 0 and not st.st_mode & 0o022, 'State parent must be root-controlled')
    NGINX_INCLUDE = '\tinclude ' + profile['nginx_include'] + ';\n'
    APACHE_INCLUDE = '\tInclude "' + profile['apache_include'] + '"\n'
    PROFILE = profile
    return profile


def digest(path):
    result = hashlib.sha256()
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), 'Expected regular file')
        for block in iter(lambda: source.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def file_fingerprint(path):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode), 'Expected regular file: ' + str(path))
    return [st.st_ino, st.st_ctime_ns, st.st_size, st.st_mtime_ns]


def validate_baseline(baseline):
    require(baseline.get('files') and '.' in baseline.get('directories', []), 'Empty or invalid baseline')
    for relative in list(baseline['files']) + baseline['directories']:
        p = pathlib.PurePosixPath(relative)
        require(not p.is_absolute() and '..' not in p.parts and '\\' not in relative,
                'Unsafe baseline relative path')
        require(str(p) == relative, 'Non-canonical baseline relative path')
        require(relative == '.' or (p.parts and p.parts[0] not in RUNTIME), 'Runtime entry in code baseline')
    for relative, spec in baseline['files'].items():
        require(re.fullmatch('[a-f0-9]{64}', spec['sha256']), 'Invalid baseline hash')
        require(spec['uid'] == PROFILE['uid'] and spec['gid'] == PROFILE['gid'], 'Unexpected baseline owner')
        require(spec['mode'] == (0o400 if relative == 'config.inc.php' else 0o444), 'Unsafe baseline mode')
        parent = str(pathlib.PurePosixPath(relative).parent)
        require(parent in baseline['directories'], 'Baseline is missing a parent directory')
    return baseline


def immutable(path, enabled=None):
    """Use the kernel immutable flag without changing CWP-required ownership."""
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(stat.S_ISREG(os.fstat(descriptor).st_mode) or stat.S_ISDIR(os.fstat(descriptor).st_mode),
                'Immutable flags require a regular file or directory')
        flags = array.array('L', [0])
        fcntl.ioctl(descriptor, 0x80086601, flags, True)
        current = bool(flags[0] & 0x10)
        if enabled is not None and current != enabled:
            flags[0] = flags[0] | 0x10 if enabled else flags[0] & ~0x10
            fcntl.ioctl(descriptor, 0x40086602, flags, True)
        return current
    finally:
        os.close(descriptor)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def execute(argv, timeout=15):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=timeout)
    return result.returncode, result.stdout, result.stderr


def atomic(path, data, mode=0o600, gid=0, uid=0):
    path = pathlib.Path(path)
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    temporary = path.parent / ('.ojs-guard-' + uuid.uuid4().hex)
    parent_locked = immutable(path.parent)
    file_locked = path.is_file() and not path.is_symlink() and immutable(path)
    try:
        if parent_locked:
            immutable(path.parent, False)
        if file_locked:
            immutable(path, False)
        with temporary.open('xb') as output:
            output.write(data if isinstance(data, bytes) else data.encode())
            output.flush()
            os.fsync(output.fileno())
        os.chmod(str(temporary), mode)
        os.chown(str(temporary), uid, gid)
        os.replace(str(temporary), str(path))
        if file_locked:
            immutable(path, True)
    finally:
        if temporary.exists():
            temporary.unlink()
        if parent_locked:
            immutable(path.parent, True)


def jsonfile(path, value):
    atomic(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def event(kind, path, details=''):
    item = {'time': now(), 'kind': kind, 'path': str(path), 'details': details}
    with (STATE / 'events.jsonl').open('a') as output:
        output.write(json.dumps(item, ensure_ascii=False) + '\n')
    return item


def quarantine(path, reason):
    path = pathlib.Path(path)
    if not path.exists() and not path.is_symlink():
        return None
    item = STATE / 'quarantine' / (str(int(time.time())) + '-' + uuid.uuid4().hex)
    item.mkdir(mode=0o700, parents=True)
    metadata = {'original': str(path), 'reason': reason, 'time': now()}
    status = path.lstat()
    metadata.update({'uid': status.st_uid, 'mode': stat.S_IMODE(status.st_mode),
                     'bytes': status.st_size, 'mtime_ns': status.st_mtime_ns})
    if stat.S_ISREG(status.st_mode):
        metadata['sha256'] = digest(path)
    parent_locked = immutable(path.parent)
    if parent_locked:
        immutable(path.parent, False)
    if not path.is_symlink() and immutable(path):
        immutable(path, False)
    try:
        shutil.move(str(path), str(item / 'payload.disabled'))
    finally:
        if parent_locked:
            immutable(path.parent, True)
    jsonfile(item / 'metadata.json', metadata)
    return event('quarantined', path, reason)


def maintenance_active():
    try:
        p = STATE / 'maintenance.json'
        st = p.stat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            return False
        return json.loads(p.read_text()).get('until', 0) > time.time()
    except (OSError, ValueError):
        return False


def enforce_configs(profile):
    """Stage per-site changes, syntax-check all affected services, then reload."""
    before = {}
    changed = []
    need = set()

    def update(path, content, service=None, mode=0o644):
        p = pathlib.Path(path)
        reject_symlinks(p)
        require(not p.exists() or p.is_file(), 'Managed config is not a regular file')
        old = p.read_bytes() if p.exists() else None
        new = content.encode()
        if old == new:
            return
        old_stat = p.stat() if p.exists() else None
        before[str(p)] = (old, old_stat)
        atomic(p, new, mode)
        changed.append(str(p))
        if service:
            need.add(service)

    def rollback():
        for path, (old, old_stat) in reversed(list(before.items())):
            if old is None:
                pathlib.Path(path).unlink()
            else:
                atomic(path, old, stat.S_IMODE(old_stat.st_mode), old_stat.st_gid, old_stat.st_uid)

    try:
        for path, spec in profile.get('managed_files', {}).items():
            update(path, spec['content'], spec.get('service'), spec.get('mode', 0o644))
        if profile.get('cwp_metadata'):
            p = pathlib.Path(profile['cwp_metadata'])
            reject_symlinks(p)
            metadata = json.loads(p.read_text())
            if any(metadata.get(k) != v for k, v in profile.get('cwp_values', {}).items()):
                metadata.update(profile['cwp_values'])
                update(str(p), json.dumps(metadata, indent=4) + '\n', mode=0o600)
        for path in profile.get('nginx_vhosts', []):
            p = pathlib.Path(path)
            reject_symlinks(p)
            text = p.read_text()
            server_names = [line for line in text.splitlines(True)
                            if re.match(r'\s*server_name\s+' + re.escape(DOMAIN) + r'(?:\s|;)', line)]
            require(len(server_names) == 1, 'Expected one site-specific nginx server block: ' + str(p))
            if NGINX_INCLUDE.strip() not in text:
                text = text.replace(server_names[0], server_names[0] + NGINX_INCLUDE, 1)
            if profile.get('enforce_document_root'):
                text = re.sub(r'(?m)^(\s*root\s+)[^;\n]+;', lambda m: m.group(1) + str(SITE) + ';', text)
            update(str(p), text, 'nginx')
        for path in profile.get('apache_vhosts', []):
            p = pathlib.Path(path)
            reject_symlinks(p)
            text = p.read_text()
            names = [line for line in text.splitlines(True)
                     if re.match(r'\s*ServerName\s+' + re.escape(DOMAIN) + r'\s*$', line)]
            require(len(names) == 1, 'Expected one site-specific Apache virtual host: ' + str(p))
            if APACHE_INCLUDE.strip() not in text:
                text = text.replace(names[0], names[0] + APACHE_INCLUDE, 1)
            for old_socket in profile.get('old_php_sockets', []):
                text = text.replace(old_socket, profile['php_socket'])
            if profile.get('enforce_document_root'):
                text = re.sub(r'(?m)^(\s*DocumentRoot)\s+[^\n]+',
                              lambda m: m.group(1) + ' ' + str(SITE), text, count=1)
            update(str(p), text, 'httpd')
        for service in sorted(need):
            code, output, error = execute(profile['services'][service]['test'])
            require(code == 0, service + ' validation failed: ' + (error or output)[-400:])
    except Exception:
        rollback()
        raise
    try:
        for service in profile.get('reload_order', profile.get('services', {})):
            if service in need:
                code, output, error = execute(profile['services'][service]['reload'])
                require(code == 0, 'Graceful reload failed for ' + service + ': ' + (error or output)[-200:])
    except Exception:
        rollback()
        # Restore the old configuration in services already reloaded where possible.
        for service in need:
            code, _, _ = execute(profile['services'][service]['test'])
            if code == 0:
                execute(profile['services'][service]['reload'])
        raise
    return [event('config_repaired', path) for path in changed]


def approve(profile):
    require(os.geteuid() == 0 and maintenance_active(), 'Root maintenance window required')
    baseline = {'created_at': now(), 'release': profile['release'], 'files': {}, 'directories': []}
    archive_path = STATE / 'approved-code.tar'
    temporary = STATE / 'approved-code.pending.tar'
    gid = profile['gid']
    if temporary.exists():
        temporary.unlink()
    with temporary.open('xb'):
        os.chmod(str(temporary), 0o600)
    with tarfile.open(str(temporary), 'w') as archive:
        for directory, children, filenames in os.walk(str(SITE), followlinks=False):
            relative_dir = os.path.relpath(directory, str(SITE))
            if relative_dir == '.':
                children[:] = [d for d in children if d not in RUNTIME]
            require(not pathlib.Path(directory).is_symlink(), directory)
            for child in children:
                require(not (pathlib.Path(directory) / child).is_symlink(), 'Symlink in code directories')
            baseline['directories'].append(relative_dir)
            for name in filenames:
                path = pathlib.Path(directory) / name
                require(path.is_file() and not path.is_symlink(), 'Unexpected code entry: ' + str(path))
                relative = str(path.relative_to(SITE))
                mode = 0o400 if relative == 'config.inc.php' else 0o444
                st = path.stat()
                if st.st_uid != profile['uid'] or st.st_gid != gid or stat.S_IMODE(st.st_mode) != mode:
                    immutable(path, False)
                    os.chown(str(path), profile['uid'], gid)
                    os.chmod(str(path), mode)
                immutable(path, True)
                content_hash = digest(path)
                archive.add(str(path), arcname=relative, recursive=False)
                baseline['files'][relative] = {'sha256': content_hash,
                                               'mode': mode, 'gid': gid, 'uid': profile['uid']}
            st = os.stat(directory)
            if st.st_uid != profile['uid'] or st.st_gid != gid or stat.S_IMODE(st.st_mode) != 0o755:
                immutable(directory, False)
                os.chown(directory, profile['uid'], gid)
                os.chmod(directory, 0o755)
            immutable(directory, True)
    require(baseline['files'] and 'index.php' in baseline['files'] and 'config.inc.php' in baseline['files'],
            'OJS index.php and config.inc.php are required before approval')
    validate_baseline(baseline)
    os.replace(str(temporary), str(archive_path))
    immutable(HOME, False)
    os.chown(str(HOME), profile['uid'], profile['gid'])
    os.chmod(str(HOME), 0o755)
    immutable(HOME, True)
    jsonfile(STATE / 'baseline.json', baseline)
    jsonfile(STATE / 'seen.json', {})
    return {'baseline_approved_files': len(baseline['files']), 'release': baseline['release']}


def inspect_code(profile, baseline, seen):
    actions = []
    current_seen = {}
    archive = None
    try:
        require(SITE.is_dir() and not SITE.is_symlink(), 'Unexpected application root')
        # Validate parents before any privileged read or restore through them.
        for relative in sorted(baseline['directories'], key=lambda p: p.count('/')):
            path = SITE if relative == '.' else SITE / relative
            if path.is_symlink() or (path.exists() and not path.is_dir()):
                actions.append(quarantine(path, 'Unexpected code-directory replacement'))
            if not path.exists():
                parent_locked = immutable(path.parent)
                if parent_locked:
                    immutable(path.parent, False)
                try:
                    path.mkdir(mode=0o755, parents=True)
                    os.chown(str(path), profile['uid'], profile['gid'])
                finally:
                    if parent_locked:
                        immutable(path.parent, True)
        for relative, spec in baseline['files'].items():
            path = SITE / relative
            changed = True
            if path.is_file() and not path.is_symlink():
                st = path.stat()
                fingerprint = [st.st_ino, st.st_ctime_ns, st.st_size, st.st_mtime_ns]
                changed = seen.get('code', {}).get(relative) != fingerprint
                if changed:
                    changed = digest(path) != spec['sha256']
            if changed:
                if archive is None:
                    archive = tarfile.open(str(STATE / 'approved-code.tar'), 'r:')
                payload = archive.extractfile(relative).read()
                require(hashlib.sha256(payload).hexdigest() == spec['sha256'], 'Sealed baseline mismatch')
                action = quarantine(path, 'Approved application code changed')
                if action:
                    actions.append(action)
                path.parent.mkdir(parents=True, exist_ok=True)
                atomic(path, payload, spec['mode'], spec['gid'], spec['uid'])
                immutable(path, True)
                actions.append(event('code_restored', path))
            st = path.stat()
            if st.st_uid != spec['uid'] or st.st_gid != spec['gid'] or stat.S_IMODE(st.st_mode) != spec['mode']:
                immutable(path, False)
                os.chown(str(path), spec['uid'], spec['gid'])
                os.chmod(str(path), spec['mode'])
                actions.append(event('code_permissions_repaired', path))
            if not immutable(path):
                immutable(path, True)
                actions.append(event('kernel_lock_repaired', path))
            st = path.stat()
            current_seen[relative] = [st.st_ino, st.st_ctime_ns, st.st_size, st.st_mtime_ns]
        for directory, children, filenames in os.walk(str(SITE), followlinks=False):
            relative = os.path.relpath(directory, str(SITE))
            if relative == '.':
                children[:] = [d for d in children if d not in RUNTIME]
            for name in list(children):
                child = pathlib.Path(directory) / name
                if child.is_symlink() or str(child.relative_to(SITE)) not in baseline['directories']:
                    actions.append(quarantine(child, 'Unapproved directory or symlink in application code'))
                    children.remove(name)
            for filename in filenames:
                path = pathlib.Path(directory) / filename
                if str(path.relative_to(SITE)) not in baseline['files']:
                    actions.append(quarantine(path, 'Unapproved file outside runtime upload/cache directories'))
        for relative in baseline['directories']:
            path = SITE if relative == '.' else SITE / relative
            st = path.stat()
            if st.st_uid != profile['uid'] or st.st_gid != profile['gid'] or stat.S_IMODE(st.st_mode) != 0o755:
                immutable(path, False)
                os.chown(str(path), profile['uid'], profile['gid'])
                os.chmod(str(path), 0o755)
                actions.append(event('directory_permissions_repaired', path))
            if not immutable(path):
                immutable(path, True)
                actions.append(event('directory_kernel_lock_repaired', path))
        home = HOME
        if home.stat().st_uid != profile['uid'] or home.stat().st_gid != profile['gid'] or home.stat().st_mode & 0o022:
            immutable(home, False)
            os.chown(str(home), profile['uid'], profile['gid'])
            os.chmod(str(home), 0o755)
            actions.append(event('home_permissions_repaired', home))
        if not immutable(home):
            immutable(home, True)
            actions.append(event('home_kernel_lock_repaired', home))
        return current_seen, [a for a in actions if a]
    finally:
        if archive:
            archive.close()


def inspect_uploads(seen):
    actions = []
    checked = dict(seen.get('uploads', {}))
    candidates = []
    dangerous = re.compile(r'\.(php[0-9]*|phtml|phar|cgi|pl|py|sh)(?:\.|$)', re.I)
    for root in (SITE / 'public', DATA):
        require(root.is_dir() and not root.is_symlink(), 'Unexpected uploads root')
        for directory, children, filenames in os.walk(str(root), followlinks=False):
            for child in list(children):
                p = pathlib.Path(directory) / child
                if p.is_symlink():
                    actions.append(quarantine(p, 'Symlink in writable uploads'))
                    children.remove(child)
            for name in filenames:
                path = pathlib.Path(directory) / name
                if path.is_symlink() or dangerous.search(name):
                    actions.append(quarantine(path, 'Executable extension or symlink in uploaded documents'))
                    checked.pop(str(path), None)
                    continue
                st = path.stat()
                fingerprint = [st.st_ino, st.st_ctime_ns, st.st_size, st.st_mtime_ns]
                if checked.get(str(path)) != fingerprint:
                    candidates.append((path, fingerprint))
    pending = len(candidates)
    # A bounded batch leaves request handling and the existing mail antivirus responsive.
    antivirus = PROFILE['antivirus']
    started = time.monotonic()
    processed = 0
    for path, fingerprint in candidates[:antivirus.get('batch_size', 25)]:
        if time.monotonic() - started >= antivirus.get('budget_seconds', 25):
            break
        # Recheck after the daemon returns: an upload can change during a scan.
        code, output, error = execute(antivirus['command'] + [str(path)],
                                      timeout=antivirus.get('timeout_seconds', 12))
        processed += 1
        if code == 1 and output.rstrip().endswith(' FOUND'):
            actions.append(quarantine(path, 'Antivirus: ' + output.strip()[-180:]))
            checked.pop(str(path), None)
        elif code == 0:
            if path.is_file() and not path.is_symlink() and file_fingerprint(path) == fingerprint:
                checked[str(path)] = fingerprint
            else:
                processed -= 1
        else:
            raise RuntimeError('Upload antivirus unavailable: ' + (error or output)[-200:])
    checked = {path: fp for path, fp in checked.items() if pathlib.Path(path).exists()}
    return checked, actions, max(0, pending - processed)





def health_checks():
    results = []
    origin = PROFILE['origin_ip']
    if ':' in origin:
        origin = '[' + origin + ']'
    for probe in PROFILE['health_checks']:
        path, expected = probe['path'], str(probe['status'])
        code, output, error = execute(['/usr/bin/curl', '--silent', '--show-error',
            '--user-agent', 'OJS-Fix/0.2', '--connect-timeout', '3', '--max-time', '6',
            '--resolve', DOMAIN + ':443:' + origin, '--output', '/dev/null',
            '--write-out', '%{http_code}', 'https://' + DOMAIN + path], timeout=8)
        results.append({'path': path, 'status': output, 'ok': code == 0 and output == expected})
    return results


def maintenance_flag():
    return pathlib.Path(PROFILE['maintenance_flag'])


def begin_maintenance(minutes):
    require(1 <= minutes <= 120, 'Maintenance duration must be between 1 and 120 minutes')
    # The guard lock is already held. Keep the expired marker if a deployment fails.
    jsonfile(STATE / 'maintenance.json', {'until': time.time() + minutes * 60,
                                         'started_at': now(), 'release': PROFILE['release']})
    atomic(maintenance_flag(), 'OJS-Fix controlled maintenance\n', 0o644)
    return {'maintenance': True, 'minutes': minutes}


def unlock_code():
    require(maintenance_active(), 'An active root maintenance window is required')
    for directory, children, filenames in os.walk(str(SITE), topdown=False, followlinks=False):
        p = pathlib.Path(directory)
        if inside(p, SITE / 'cache') or inside(p, SITE / 'public'):
            continue
        require(not p.is_symlink(), 'Refusing to unlock a symlink')
        for name in filenames:
            child = p / name
            require(not child.is_symlink() and child.is_file(), 'Refusing unexpected code entry')
            immutable(child, False)
        immutable(p, False)
    immutable(HOME, False)
    event('maintenance_code_unlocked', SITE)
    return {'unlocked': True, 'maintenance': True}


def finish_maintenance():
    require(maintenance_active(), 'Renew the root maintenance window before finishing')
    baseline = validate_baseline(json.loads((STATE / 'baseline.json').read_text()))
    require(baseline['release'] == PROFILE['release'], 'Approve the intended release before finishing')
    expected = set(baseline['files'])
    actual = set()
    for directory, children, filenames in os.walk(str(SITE), followlinks=False):
        if pathlib.Path(directory) == SITE:
            children[:] = [x for x in children if x not in RUNTIME]
        require(not pathlib.Path(directory).is_symlink(), 'Symlink in code directory')
        require(str(pathlib.Path(directory).relative_to(SITE)) in baseline['directories'] or pathlib.Path(directory) == SITE,
                'Unapproved directory remains in code')
        for name in children:
            require(not (pathlib.Path(directory) / name).is_symlink(), 'Symlink in code directory')
        for name in filenames:
            p = pathlib.Path(directory) / name
            relative = str(p.relative_to(SITE))
            actual.add(relative)
            require(relative in expected and digest(p) == baseline['files'][relative]['sha256'],
                    'Unapproved code; finish is blocked')
    require(actual == expected, 'Missing approved code; finish is blocked')
    for relative in baseline['directories']:
        require(immutable(SITE / relative), 'Code directory has not been locked')
    for relative in baseline['files']:
        require(immutable(SITE / relative), 'Code file has not been locked')
    require(immutable(HOME), 'Account home has not been locked')
    enforce_configs(PROFILE)
    checks = health_checks()
    require(all(item['ok'] for item in checks), 'Local HTTP health check failed; maintenance retained')
    maintenance_flag().unlink()
    (STATE / 'maintenance.json').unlink()
    event('maintenance_finished', SITE)
    return {'maintenance': False, 'http_checks': checks}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', default='/etc/ojs-fix/profile.json')
    options = parser.add_mutually_exclusive_group()
    options.add_argument('--check-config', action='store_true')
    options.add_argument('--approve', action='store_true', help='Approve reviewed live code; root maintenance required')
    options.add_argument('--configs-only', action='store_true')
    options.add_argument('--maintenance-minutes', type=int)
    options.add_argument('--unlock-code', action='store_true')
    options.add_argument('--finish-maintenance', action='store_true')
    args = parser.parse_args(argv)
    require(os.geteuid() == 0, 'This guard runs only as root')
    profile = configure(args.profile)
    lock = (STATE / 'guard.lock').open('a')
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(json.dumps({'busy': True}))
            return 0
        if args.check_config:
            print(json.dumps({'valid': True, 'version': VERSION}))
            return 0
        if args.maintenance_minutes is not None:
            print(json.dumps(begin_maintenance(args.maintenance_minutes)))
            return 0
        if args.unlock_code:
            print(json.dumps(unlock_code()))
            return 0
        if args.approve:
            print(json.dumps(approve(profile)))
            return 0
        if args.finish_maintenance:
            print(json.dumps(finish_maintenance()))
            return 0
        if maintenance_active():
            print(json.dumps({'maintenance': True, 'time': now()}))
            return 0
        if (STATE / 'maintenance.json').exists() or maintenance_flag().exists():
            result = {'time': now(), 'healthy': False,
                      'errors': ['Maintenance expired or orphaned. Review the deployment, renew maintenance, and explicitly approve or roll back code AND database together.']}
            jsonfile(STATE / 'latest.json', result)
            jsonfile(STATE / 'ALERT.json', result)
            print(json.dumps(result))
            return 1
        result = {'time': now(), 'healthy': False, 'actions': [], 'errors': []}
        try:
            result['actions'] += enforce_configs(profile)
            if not args.configs_only:
                protected_file(STATE / 'baseline.json')
                protected_file(STATE / 'approved-code.tar')
                baseline = validate_baseline(json.loads((STATE / 'baseline.json').read_text()))
                require(baseline['release'] == profile['release'], 'Profile release differs from approved code; use maintenance')
                try:
                    seen = json.loads((STATE / 'seen.json').read_text())
                except (OSError, ValueError):
                    seen = {}
                code, actions = inspect_code(profile, baseline, seen)
                result['actions'] += actions
                uploads, actions, pending = inspect_uploads(seen)
                result['actions'] += actions
                jsonfile(STATE / 'seen.json', {'code': code, 'uploads': uploads})
                result.update({'code_files_checked': len(code), 'uploads_pending_scan': pending})
                result['http_checks'] = health_checks()
                require(all(item['ok'] for item in result['http_checks']), 'An OJS HTTP health check failed')
            result['healthy'] = True
        except Exception as error:
            result['errors'].append(type(error).__name__ + ': ' + str(error)[:500])
        jsonfile(STATE / 'latest.json', result)
        if result['actions'] or result['errors']:
            jsonfile(STATE / 'ALERT.json', result)
        elif (STATE / 'ALERT.json').exists():
            (STATE / 'ALERT.json').unlink()
        print(json.dumps({k: v for k, v in result.items() if k != 'actions'}, ensure_ascii=False))
        return 0 if result['healthy'] else 1
    finally:
        lock.close()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps({'healthy': False, 'errors': [type(error).__name__ + ': ' + str(error)[:500]]}))
        sys.exit(1)
