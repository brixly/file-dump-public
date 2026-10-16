#!/usr/bin/python3 -I
"""
cf7_rollback.py - find WordPress installs where Contact Form 7 was upgraded to a
release whose Composer platform check requires a newer PHP than the site runs
(CF7 6.2.x => PHP >= 8.3), roll CF7 back to a known-good release, and switch off
Softaculous plugin auto-upgrade for those installs so it is not re-applied.

DRY-RUN BY DEFAULT. Nothing is changed unless --apply is given.

  # full-server report, no changes
  ./cf7_rollback.py

  # pilot: only these accounts, make changes
  ./cf7_rollback.py --user petsandi --user shadiefinan --apply

  # also turn off Softaculous plugin auto-upgrade on every *other* Softaculous WP
  # install running PHP < 8.3 (the ones next in line to break)
  ./cf7_rollback.py --include-at-risk --apply

  # reverse a previous run
  ./cf7_rollback.py --undo /var/log/cf7-rollback/<run-id>/manifest.json --apply

How it works (per affected install):
  * Effective PHP = MultiPHP version for the vhost, unless the vhost is on the
    system-default version and not PHP-FPM, in which case CloudLinux PHP Selector
    governs (selectorctl --user-current).
  * Affected = contact-form-7/vendor/composer/platform_check.php requires a PHP
    version higher than the effective PHP.
  * Rollback package is downloaded once from downloads.wordpress.org and every file
    is verified against WordPress.org's published sha256 checksums.
  * All file operations inside customer homes run AS THE ACCOUNT USER (runuser),
    so ownership is correct and root never follows user-controlled symlinks.
  * The replaced plugin directory is kept in ~/.cf7-rollback/<run-id>/ and every
    change is recorded in a manifest so it can be undone with --undo.
  * Softaculous: sets auto_upgrade_plugins=0 on the matching installation in
    ~/.softaculous/installations.php (same method Softaculous' own
    enable_auto_upgrade.php uses), after taking a copy of the file.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor

SLUG = 'contact-form-7'
DEFAULT_TARGET = '6.1.7'
TARGET_MIN_PHP = '7.4'      # "Requires PHP" of the rollback target
TARGET_MIN_WP = '6.7'       # "Requires at least" of the rollback target
PKG_ROOT = '/usr/local/cf7-rollback'
LOG_ROOT = '/var/log/cf7-rollback'
LOCK_FILE = '/var/run/cf7-rollback.lock'
ROOT_PHP = '/usr/local/cpanel/3rdparty/bin/php'
USER_PHP_CANDIDATES = ['/opt/cpanel/ea-php81/root/usr/bin/php', '/opt/cpanel/ea-php82/root/usr/bin/php',
                       '/opt/cpanel/ea-php83/root/usr/bin/php', '/opt/cpanel/ea-php74/root/usr/bin/php']
# Softaculous' daily cron runs at 01:36 and works through users for a while; don't race it.
BLACKOUT = ((1, 20), (2, 30))

RUN_ID = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
LOG = None


def log(msg, also_print=True):
    line = f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    if also_print:
        print(line, flush=True)
    if LOG:
        LOG.write(line + '\n')
        LOG.flush()


def vnum(v):
    m = re.match(r'(\d+)\.(\d+)(?:\.(\d+))?', v or '')
    return tuple(int(x or 0) for x in m.groups()) if m else None


def vlt(a, b):
    return vnum(a) is not None and vnum(b) is not None and vnum(a) < vnum(b)


def run(cmd, user=None, home=None, input=None, timeout=120):
    home = home or ('/' if user else pwd.getpwuid(os.geteuid()).pw_dir)   # root keeps /root for ~/.my.cnf
    if user:
        cmd = ['runuser', '-u', user, '--'] + cmd
    env = {'PATH': '/usr/local/cpanel/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': home, 'LANG': 'C'}
    return subprocess.run(cmd, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout, cwd='/', env=env)


def read_header(path, n=4000):
    try:
        with open(path, errors='ignore') as f:
            return f.read(n)
    except OSError:
        return ''


# --------------------------------------------------------------------------- PHP map
class PhpMap:
    def __init__(self):
        r = run(['whmapi1', '--output=json', 'php_get_vhost_versions'], timeout=300)
        self.vhosts = []
        for v in json.loads(r.stdout)['data']['versions']:
            self.vhosts.append(dict(docroot=v['documentroot'].rstrip('/'), version=v['version'],
                                    account=v['account'], vhost=v['vhost'], fpm=int(v.get('php_fpm') or 0)))
        self.vhosts.sort(key=lambda v: -len(v['docroot']))
        self.default = 'ea-php81'
        try:
            m = re.search(r'^default:\s*(\S+)', open('/etc/cpanel/ea4/php.conf').read(), re.M)
            if m:
                self.default = m.group(1)
        except OSError:
            pass
        self._sel = {}

    def selector(self, user):
        if user not in self._sel:
            try:
                out = run(['selectorctl', '--user-current', f'--user={user}'], timeout=120).stdout.split()
                self._sel[user] = out[0] if out and re.match(r'^\d+\.\d+$', out[0]) else None
            except Exception:
                self._sel[user] = None
        return self._sel[user]

    def prefetch(self, users):
        with ThreadPoolExecutor(8) as ex:
            list(ex.map(self.selector, set(users) - set(self._sel)))

    def vhost_for(self, path):
        for v in self.vhosts:
            if path == v['docroot'] or path.startswith(v['docroot'] + '/'):
                return v
        return None

    def effective(self, path):
        """-> (php 'X.Y', source, vhost dict) or (None, reason, None)"""
        v = self.vhost_for(path)
        if not v:
            return None, 'no-vhost', None
        if not v['fpm'] and v['version'] == self.default:
            s = self.selector(v['account'])
            if s:
                return s, 'cl-selector', v
        m = re.search(r'php(\d)(\d+)', v['version'])
        return (f"{m.group(1)}.{m.group(2)}", 'multiphp', v) if m else (None, 'unknown-version', v)


# --------------------------------------------------------------------------- Softaculous
SOFT_READ_PHP = r'''<?php
$out = [];
foreach (array_filter(explode("\n", stream_get_contents(STDIN))) as $f) {
    if (is_link($f) || !is_file($f)) continue;
    $s = file_get_contents($f);
    if (strncmp($s, '<?php', 5) === 0) { $p = strpos($s, '?>'); $s = $p === false ? '' : substr($s, $p + 2); }
    $d = @unserialize($s, ['allowed_classes' => false]);
    if (!is_array($d)) { $out[$f] = null; continue; }
    $o = [];
    foreach ($d as $k => $v) {
        if (!is_array($v)) continue;
        $o[] = ['insid' => (string)$k, 'sid' => $v['sid'] ?? null, 'softpath' => rtrim($v['softpath'] ?? '', '/'),
                'softurl' => $v['softurl'] ?? '', 'aup' => $v['auto_upgrade_plugins'] ?? null];
    }
    $out[$f] = $o;
}
echo json_encode($out);
'''

# Runs as the account user. argv: file, json map {insid: value}. Prints {"prev": {insid: old}}.
SOFT_WRITE_PHP = r'''<?php
$f = $argv[1]; $want = json_decode($argv[2], true);
if (is_link($f)) { fwrite(STDERR, "refusing symlink\n"); exit(2); }
$raw = file_get_contents($f); $s = $raw; $prefix = '';
if (strncmp($s, '<?php', 5) === 0) { $p = strpos($s, '?>'); $prefix = substr($s, 0, $p + 2); $s = substr($s, $p + 2); }
$d = @unserialize($s, ['allowed_classes' => false]);
if (!is_array($d)) { fwrite(STDERR, "cannot unserialize\n"); exit(3); }
$prev = [];
foreach ($want as $id => $val) {
    if (!isset($d[$id]) || !is_array($d[$id])) { fwrite(STDERR, "insid $id missing\n"); exit(4); }
    $prev[$id] = $d[$id]['auto_upgrade_plugins'] ?? null;
    if ($val === null) unset($d[$id]['auto_upgrade_plugins']); else $d[$id]['auto_upgrade_plugins'] = (int)$val;
}
$tmp = $f . '.cf7rb.' . getmypid();
if (file_put_contents($tmp, $prefix . serialize($d)) === false) { fwrite(STDERR, "write failed\n"); exit(5); }
chmod($tmp, fileperms($f) & 0777);
if (!rename($tmp, $f)) { @unlink($tmp); fwrite(STDERR, "rename failed\n"); exit(6); }
echo json_encode(['prev' => $prev]);
'''


def load_softaculous(users=None):
    files = []
    for pw in pwd.getpwall():
        if users and pw.pw_name not in users:
            continue
        f = os.path.join(pw.pw_dir, '.softaculous', 'installations.php')
        if pw.pw_dir.startswith('/home') and os.path.isfile(f):
            files.append(f)
    if not files:
        return {}
    with tempfile.NamedTemporaryFile('w', suffix='.php', delete=False) as t:
        t.write(SOFT_READ_PHP)
    try:
        r = run([ROOT_PHP, '-d', 'display_errors=stderr', t.name], input='\n'.join(files), timeout=600)
    finally:
        os.unlink(t.name)
    if r.returncode or not r.stdout.startswith('{'):
        raise RuntimeError(f"could not read Softaculous installations: {r.stderr.strip()[:300]}")
    data = json.loads(r.stdout)
    by_path = {}
    for f, items in data.items():
        user = f.split('/')[2]
        for it in items or []:
            if str(it.get('sid')) == '26' and it['softpath']:   # 26 = WordPress
                it['user'], it['file'] = user, f
                by_path[it['softpath']] = it
    return by_path


def set_soft_flags(user, home, file, changes, backup_dir):
    """changes: {insid: value}. Returns previous values."""
    php = next(p for p in USER_PHP_CANDIDATES if os.path.exists(p))
    os.makedirs(PKG_ROOT, mode=0o755, exist_ok=True)
    r = run(['cp', '-p', file, os.path.join(backup_dir, 'installations.php.bak')], user=user, home=home)
    if r.returncode:
        raise RuntimeError(f"backup of {file} failed: {r.stderr.strip()}")
    with tempfile.NamedTemporaryFile('w', suffix='.php', delete=False, dir='/usr/local/cf7-rollback') as t:
        t.write(SOFT_WRITE_PHP)
    os.chmod(t.name, 0o644)
    try:
        r = run([php, '-d', 'display_errors=stderr', t.name, file, json.dumps(changes)], user=user, home=home)
    finally:
        os.unlink(t.name)
    if r.returncode:
        raise RuntimeError(f"softaculous update failed: {r.stderr.strip()}")
    return json.loads(r.stdout)['prev']


# --------------------------------------------------------------------------- package
def prepare_package(target):
    dest = os.path.join(PKG_ROOT, target)
    plugin_dir = os.path.join(dest, SLUG)
    os.makedirs(dest, mode=0o755, exist_ok=True)
    zpath, spath = os.path.join(dest, 'plugin.zip'), os.path.join(dest, 'checksums.json')
    if not os.path.exists(zpath):
        log(f"downloading {SLUG} {target}")
        urllib.request.urlretrieve(f"https://downloads.wordpress.org/plugin/{SLUG}.{target}.zip", zpath)
        urllib.request.urlretrieve(f"https://downloads.wordpress.org/plugin-checksums/{SLUG}/{target}.json", spath)
    sums = json.load(open(spath))['files']
    if os.path.exists(plugin_dir):
        shutil.rmtree(plugin_dir)
    with zipfile.ZipFile(zpath) as z:
        for n in z.namelist():
            if n.startswith('/') or '..' in n.split('/') or not n.startswith(SLUG + '/'):
                raise RuntimeError(f"unsafe path in zip: {n}")
        z.extractall(dest)
    seen = set()
    for root, dirs, files in os.walk(plugin_dir):
        os.chmod(root, 0o755)
        for fn in files:
            p = os.path.join(root, fn)
            os.chmod(p, 0o644)
            rel = os.path.relpath(p, plugin_dir)
            seen.add(rel)
            if rel not in sums:
                raise RuntimeError(f"file not in WordPress.org checksums: {rel}")
            if hashlib.sha256(open(p, 'rb').read()).hexdigest() != sums[rel]['sha256']:
                raise RuntimeError(f"checksum mismatch: {rel}")
    missing = set(sums) - seen
    if missing:
        raise RuntimeError(f"files missing from package: {sorted(missing)[:5]}")
    hdr = read_header(os.path.join(plugin_dir, 'wp-contact-form-7.php'))
    if f"Version: {target}" not in hdr:
        raise RuntimeError("package header version mismatch")
    log(f"package {target} verified against WordPress.org checksums ({len(seen)} files)")
    return plugin_dir


# --------------------------------------------------------------------------- discovery
def discover(php, soft, users, paths):
    cands = set(soft.keys())
    try:
        r = run(['wp-toolkit', '--list', '-format', 'json'], timeout=600)
        cands |= {i['fullPath'].rstrip('/') for i in json.loads(r.stdout)}
    except Exception as e:
        log(f"warning: WP Toolkit list unavailable ({e}); using docroots + Softaculous only")
    cands |= {v['docroot'] for v in php.vhosts if os.path.exists(v['docroot'] + '/wp-config.php')}
    out = []
    for p in sorted(cands):
        if not p.startswith('/home'):
            continue
        if paths and p not in paths:
            continue
        v = php.vhost_for(p)
        owner = v['account'] if v else p.split('/')[2]
        if users and owner not in users:
            continue
        out.append((p, owner))
    return out


def wp_home_url(path):
    """The site's public URL from the 'home' option (differs from the install path when
    WordPress lives in its own directory)."""
    cfg = read_header(os.path.join(path, 'wp-config.php'), 200000)
    db = re.search(r"define\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)", cfg)
    pre = re.search(r"^\s*\$table_prefix\s*=\s*['\"]([^'\"]+)", cfg, re.M)
    if not db or not pre or not re.match(r'^\w+$', db.group(1) + pre.group(1)):
        return None
    try:
        r = run(['mysql', '-N', '-B', '-e', f"SELECT option_value FROM `{db.group(1)}`.`{pre.group(1)}options` WHERE option_name='home'"], timeout=30)
        return r.stdout.strip() or None
    except Exception:
        return None


def probe(php, path, soft_item):
    v = php.vhost_for(path)
    if not v:
        return None
    url = wp_home_url(path) or (soft_item or {}).get('softurl') or f"https://{v['vhost']}{path[len(v['docroot']):]}"
    m = re.match(r'(https?)://([^/:]+)(.*)', url)
    if not m:
        return None
    scheme, host, rest = m.groups()
    ip = None
    try:
        ud = open(f"/var/cpanel/userdata/{v['account']}/{v['vhost']}").read()
        ip = re.search(r'^ip:\s*(\S+)', ud, re.M).group(1)
    except Exception:
        ip = open('/var/cpanel/mainip').read().strip() if os.path.exists('/var/cpanel/mainip') else socket.gethostbyname(socket.gethostname())
    bare = host[4:] if host.startswith('www.') else host
    resolves = []
    for h in (bare, 'www.' + bare):
        for port in (80, 443):
            resolves += ['--resolve', f"{h}:{port}:{ip}"]
    r = subprocess.run(['curl', '-sk', '-L', '--max-redirs', '3', '-m', '20'] + resolves +
                       ['-o', '-', '-w', '\n%{http_code}', f"{scheme}://{host}{rest.rstrip('/')}/"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    body = r.stdout.decode(errors='ignore')
    code = body.rsplit('\n', 1)[-1]
    return f"{code}{' composer-error' if 'Composer detected issues' in body else ''}"


def classify(php, soft, installs, include_at_risk, threshold):
    php.prefetch({o for _, o in installs})
    rows = []
    for path, owner in installs:
        pdir = os.path.join(path, 'wp-content/plugins', SLUG)
        eff, src, v = php.effective(path)
        si = soft.get(path)
        row = dict(path=path, user=owner, php=eff, php_source=src, cf7=None, requires=None, wp=None,
                   soft_insid=si and si['insid'], soft_aup=si and si['aup'], action='none', reason='')
        if os.path.isdir(pdir) or os.path.islink(pdir):
            m = re.search(r'Version:\s*([0-9.]+)', read_header(os.path.join(pdir, 'wp-contact-form-7.php')))
            row['cf7'] = m.group(1) if m else '?'
            m = re.search(r'PHP_VERSION_ID\s*>=\s*(\d+)', read_header(os.path.join(pdir, 'vendor/composer/platform_check.php')))
            if m:
                n = int(m.group(1))
                row['requires'] = f"{n // 10000}.{n // 100 % 100}"
        m = re.search(r"\$wp_version\s*=\s*'([^']+)'", read_header(os.path.join(path, 'wp-includes/version.php'), 20000))
        row['wp'] = m.group(1) if m else None

        if row['requires'] and eff and vlt(eff, row['requires']):
            why = []
            if os.path.islink(pdir):
                why.append('plugin dir is a symlink')
            try:
                if os.stat(pdir).st_uid != pwd.getpwnam(owner).pw_uid:
                    why.append('plugin dir not owned by account')
            except (KeyError, OSError) as e:
                why.append(f'owner check failed: {e}')
            if vlt(eff, TARGET_MIN_PHP):
                why.append(f'PHP {eff} < {TARGET_MIN_PHP} needed by {DEFAULT_TARGET}')
            if not row['wp'] or vlt(row['wp'], TARGET_MIN_WP):
                why.append(f"WP {row['wp']} < {TARGET_MIN_WP} needed by {DEFAULT_TARGET}")
            row['action'] = 'MANUAL' if why else 'ROLLBACK'
            row['reason'] = '; '.join(why) or f"CF7 {row['cf7']} needs PHP {row['requires']}, site runs {eff} ({src})"
        elif row['requires'] and not eff:
            row['action'], row['reason'] = 'MANUAL', f'could not determine effective PHP ({src})'
        elif include_at_risk and si and str(si['aup']) == '1' and eff and vlt(eff, threshold):
            row['action'], row['reason'] = 'DISABLE_SOFT_AUTOUPGRADE', f'Softaculous plugin auto-upgrade on, PHP {eff} < {threshold}'
        if row['action'] != 'none' or row['cf7']:
            rows.append(row)
    return rows


# --------------------------------------------------------------------------- actions
def user_home(user):
    return pwd.getpwnam(user).pw_dir


def backup_dir_for(user, path):
    home = user_home(user)
    d = os.path.join(home, '.cf7-rollback', RUN_ID, path[len(home):].strip('/').replace('/', '__') or 'root')
    r = run(['mkdir', '-p', '-m', '700', d], user=user, home=home)
    if r.returncode:
        raise RuntimeError(f"cannot create {d}: {r.stderr.strip()}")
    return d


def do_rollback(row, pkg_dir, target):
    user, path, home = row['user'], row['path'], user_home(row['user'])
    if not os.path.realpath(path).startswith(os.path.realpath(home) + '/'):
        raise RuntimeError('install path resolves outside the account home')
    pdir = os.path.join(path, 'wp-content/plugins', SLUG)
    bk = backup_dir_for(user, path)
    new, old = os.path.join(bk, 'new-' + SLUG), os.path.join(bk, f"old-{SLUG}-{row['cf7']}")
    for cmd in (['cp', '-R', pkg_dir, new], ['mv', '-T', pdir, old]):
        r = run(cmd, user=user, home=home)
        if r.returncode:
            raise RuntimeError(f"{' '.join(cmd[:2])} failed: {r.stderr.strip()}")
    r = run(['mv', '-T', new, pdir], user=user, home=home)
    if r.returncode:
        run(['mv', '-T', old, pdir], user=user, home=home)   # put the original back
        raise RuntimeError(f"swap failed, original restored: {r.stderr.strip()}")
    if f"Version: {target}" not in read_header(os.path.join(pdir, 'wp-contact-form-7.php')) or \
            os.path.exists(os.path.join(pdir, 'vendor/composer/platform_check.php')):
        raise RuntimeError('post-swap verification failed')
    return dict(type='rollback', user=user, path=path, plugin_dir=pdir, backup=old, backup_root=bk,
                from_version=row['cf7'], to_version=target)


def do_soft_disable(rows_for_user, soft):
    user = rows_for_user[0]['user']
    home = user_home(user)
    item0 = soft[rows_for_user[0]['path']]
    bk = backup_dir_for(user, os.path.join(home, '.softaculous'))
    changes = {soft[r['path']]['insid']: 0 for r in rows_for_user}
    prev = set_soft_flags(user, home, item0['file'], changes, bk)
    return [dict(type='softaculous', user=user, file=item0['file'], insid=i, path=soft_path,
                 prev=prev.get(i), new=0, backup=os.path.join(bk, 'installations.php.bak'))
            for soft_path, i in ((r['path'], soft[r['path']]['insid']) for r in rows_for_user)]


def undo(manifest_path, apply):
    entries = json.load(open(manifest_path))['entries']
    for e in reversed(entries):
        home = user_home(e['user'])
        if e['type'] == 'rollback':
            log(f"{'UNDO' if apply else 'would undo'} rollback {e['path']} -> restore {e['from_version']} from {e['backup']}")
            if apply:
                parked = os.path.join(e['backup_root'], f"undone-{SLUG}-{e['to_version']}")
                for cmd in (['mv', '-T', e['plugin_dir'], parked], ['mv', '-T', e['backup'], e['plugin_dir']]):
                    r = run(cmd, user=e['user'], home=home)
                    if r.returncode:
                        log(f"  ERROR {' '.join(cmd)}: {r.stderr.strip()}")
                        break
        elif e['type'] == 'softaculous':
            log(f"{'UNDO' if apply else 'would undo'} Softaculous {e['path']} auto_upgrade_plugins -> {e['prev']}")
            if apply:
                try:
                    bk = backup_dir_for(e['user'], os.path.join(home, '.softaculous'))
                    set_soft_flags(e['user'], home, e['file'], {e['insid']: e['prev']}, bk)
                except Exception as ex:
                    log(f"  ERROR {ex}")


# --------------------------------------------------------------------------- main
def main():
    global LOG
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--apply', action='store_true', help='make changes (default is a dry run)')
    ap.add_argument('--user', action='append', default=[], help='limit to this cPanel account (repeatable)')
    ap.add_argument('--path', action='append', default=[], help='limit to this install path (repeatable)')
    ap.add_argument('--include-at-risk', action='store_true',
                    help='also disable Softaculous plugin auto-upgrade on other Softaculous WP installs with PHP < --php-threshold')
    ap.add_argument('--php-threshold', default='8.3')
    ap.add_argument('--skip-softaculous', action='store_true', help='roll back only; leave Softaculous settings alone')
    ap.add_argument('--target', default=DEFAULT_TARGET, help=f'CF7 version to roll back to (default {DEFAULT_TARGET})')
    ap.add_argument('--no-probe', action='store_true', help='skip before/after HTTP checks')
    ap.add_argument('--force-window', action='store_true', help='allow --apply during the Softaculous cron window')
    ap.add_argument('--undo', metavar='MANIFEST')
    a = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit('must run as root')
    os.nice(10)
    lock = open(LOCK_FILE, 'w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit('another cf7_rollback run is in progress')

    now = datetime.datetime.now()
    if a.apply and not a.force_window and BLACKOUT[0] <= (now.hour, now.minute) <= BLACKOUT[1]:
        sys.exit('refusing to --apply while the Softaculous auto-upgrade cron may be running (01:20-02:30); use --force-window to override')

    if a.apply:
        os.makedirs(os.path.join(LOG_ROOT, RUN_ID), mode=0o700, exist_ok=True)
        LOG = open(os.path.join(LOG_ROOT, RUN_ID, 'actions.log'), 'a')
    log(f"cf7_rollback run {RUN_ID} on {socket.gethostname()} mode={'APPLY' if a.apply else 'DRY-RUN'}")

    if a.undo:
        return undo(a.undo, a.apply)

    t0 = time.time()
    php = PhpMap()
    users = set(a.user) or None
    soft = load_softaculous(users)
    installs = discover(php, soft, users, set(p.rstrip('/') for p in a.path))
    rows = classify(php, soft, installs, a.include_at_risk, a.php_threshold)
    todo = [r for r in rows if r['action'] in ('ROLLBACK', 'MANUAL', 'DISABLE_SOFT_AUTOUPGRADE')]
    log(f"scanned {len(installs)} WordPress installs, {len([r for r in rows if r['cf7']])} with {SLUG}, "
        f"{len(todo)} need attention ({time.time() - t0:.0f}s)")

    for r in todo:
        r['before'] = None if a.no_probe or r['action'] == 'DISABLE_SOFT_AUTOUPGRADE' else probe(php, r['path'], soft.get(r['path']))
        sflag = '-' if r['soft_insid'] is None else f"soft-aup={r['soft_aup']}"
        log(f"{r['action']:<25} {r['user']:<16} PHP {r['php'] or '?':<4} CF7 {r['cf7'] or '-':<8} {sflag:<11} "
            f"http={r['before'] or '-':<18} {r['path']}  [{r['reason']}]")

    if not a.apply:
        log("dry run only - nothing changed. Re-run with --apply (ideally with --user for a pilot).")
        return

    entries = []
    manifest = os.path.join(LOG_ROOT, RUN_ID, 'manifest.json')

    def save():
        json.dump(dict(run_id=RUN_ID, host=socket.gethostname(), args=vars(a), entries=entries, rows=rows),
                  open(manifest, 'w'), indent=1, default=str)

    if any(r['action'] == 'ROLLBACK' for r in rows):
        pkg = prepare_package(a.target)
    for r in rows:
        if r['action'] != 'ROLLBACK':
            continue
        try:
            entries.append(do_rollback(r, pkg, a.target))
            r['result'] = 'rolled back'
        except Exception as e:
            r['result'] = f'FAILED: {e}'
        log(f"rollback {r['path']}: {r['result']}")
        save()

    if not a.skip_softaculous:
        by_user = {}
        for r in rows:
            done_rb = r['action'] == 'ROLLBACK' and r.get('result') == 'rolled back'
            if (done_rb or r['action'] == 'DISABLE_SOFT_AUTOUPGRADE') and r['path'] in soft and str(soft[r['path']]['aup']) != '0':
                by_user.setdefault(r['user'], []).append(r)
        for user, urows in by_user.items():
            try:
                es = do_soft_disable(urows, soft)
                entries.extend(es)
                for r in urows:
                    r['soft_result'] = 'auto_upgrade_plugins=0'
            except Exception as e:
                for r in urows:
                    r['soft_result'] = f'FAILED: {e}'
            for r in urows:
                log(f"softaculous {r['path']}: {r['soft_result']}")
            save()

    if not a.no_probe:
        time.sleep(2)
        for r in rows:
            if r.get('result') == 'rolled back':
                r['after'] = probe(php, r['path'], soft.get(r['path']))
                log(f"after  http={r['after']:<18} (before {r['before']}) {r['path']}")
    save()
    log(f"manifest: {manifest}   undo with: {sys.argv[0]} --undo {manifest} --apply")


if __name__ == '__main__':
    main()
