#!/bin/bash
# enable_opcache.sh - make sure OPcache is installed and enabled for every PHP that sites can run:
#   * cPanel EA4 PHP (ea-phpXX, 7.0+): install ea-phpXX-php-opcache where missing, and write a tuning ini.
#   * CloudLinux alt-php (PHP Selector, 7.0-8.4): add opcache to each version's default extension set,
#     and enable it for users who are currently running that version with opcache switched off.
#   PHP 8.5+ has OPcache built in; PHP 5.x is skipped.
#
#   ./enable_opcache.sh            # report only, no changes
#   ./enable_opcache.sh --apply    # make the changes, then one graceful web server restart
#
# Safe to re-run: anything already in place is skipped.
set -u
APPLY=0; [ "${1:-}" = "--apply" ] && APPLY=1
INI_NAME=zz-opcache-tuning.ini          # sorts after the package's 10-opcache.ini, so these values win
read -r -d '' TUNING <<'EOF'
; Managed by enable_opcache.sh (fleet optimiser) - local edits will be overwritten
opcache.enable=1
opcache.memory_consumption=192
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=20000
opcache.validate_timestamps=1
opcache.revalidate_freq=2
EOF

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -d /etc/cpanel/ea4 ] || { echo "not a cPanel EA4 server - nothing to do"; exit 0; }
echo "enable_opcache on $(hostname) mode=$([ $APPLY = 1 ] && echo APPLY || echo DRY-RUN)"
CHANGED=0; FAIL=0

# ---------------------------------------------------------------- cPanel ea-php
echo "== ea-php"
VERSIONS=(); TO_INSTALL=()
for d in /opt/cpanel/ea-php*/; do
  v=$(basename "$d"); bin=$d/root/usr/bin/php
  [ -x "$bin" ] || continue                                   # leftover dir, PHP not installed
  num=${v#ea-php}; [ "$num" -ge 70 ] 2>/dev/null || { echo "  $v: skipped (PHP 5.x)"; continue; }
  VERSIONS+=("$v")
  if [ "$num" -ge 85 ]; then
    echo "  $v: OPcache built in"
  elif rpm -q "$v-php-opcache" >/dev/null 2>&1; then
    echo "  $v: package installed"
  elif dnf -q list available "$v-php-opcache" >/dev/null 2>&1; then
    echo "  $v: package MISSING - will install $v-php-opcache"; TO_INSTALL+=("$v-php-opcache")
  else
    echo "  $v: package MISSING and not available in repos - skipped"
  fi
done

if [ $APPLY = 1 ]; then
  if [ ${#TO_INSTALL[@]} -gt 0 ]; then
    dnf -y -q install "${TO_INSTALL[@]}" || { echo "dnf install failed - aborting before any restart"; exit 1; }
  fi
  for v in "${VERSIONS[@]}"; do
    dir=/opt/cpanel/$v/root/etc/php.d; bin=/opt/cpanel/$v/root/usr/bin/php
    [ -d "$dir" ] || continue
    if [ "$(cat "$dir/$INI_NAME" 2>/dev/null)" != "$TUNING" ]; then
      printf '%s\n' "$TUNING" > "$dir/$INI_NAME"; chmod 644 "$dir/$INI_NAME"; CHANGED=1
    fi
    got=$("$bin" -d display_errors=0 -d opcache.enable_cli=1 -r 'echo extension_loaded("Zend OPcache") ? "loaded files=".ini_get("opcache.max_accelerated_files")." mem=".ini_get("opcache.memory_consumption") : "NOT LOADED";' 2>/dev/null)
    echo "  $v: $got"
    case "$got" in loaded*) ;; *) FAIL=1 ;; esac
  done
  [ ${#TO_INSTALL[@]} -gt 0 ] && CHANGED=1
fi

# ---------------------------------------------------------------- CloudLinux alt-php
if command -v selectorctl >/dev/null 2>&1 && [ -f /etc/cl.selector/defaults.cfg ]; then
  echo "== alt-php (PHP Selector)"
  # which users run which selector version (only users actually on 7.0-8.4 matter)
  declare -A USER_VER
  for f in /home/*/.cl.selector/defaults.cfg; do
    u=$(echo "$f" | cut -d/ -f3); ver=$(grep -m1 -oP '^php\s*=\s*\K[0-9]+\.[0-9]+' "$f" 2>/dev/null) || continue
    USER_VER[$u]=$ver
  done
  for dir in /opt/alt/php[0-9][0-9]; do
    n=${dir#/opt/alt/php}; ver="${n:0:1}.${n:1}"
    [ "$n" -ge 70 ] && [ "$n" -lt 85 ] || continue              # 5.x skipped, 8.5+ built in
    [ -f "$dir/usr/lib64/php/modules/opcache.so" ] || { echo "  alt-php$n: no opcache module - skipped"; continue; }
    in_default=$(awk -v s="[php$ver]" '$0==s{f=1;next} /^\[/{f=0} f && /^modules/{print ($0 ~ /(^|[ =,])opcache(,|$)/)?"yes":"no"}' /etc/cl.selector/defaults.cfg)
    users=()
    for u in "${!USER_VER[@]}"; do
      [ "${USER_VER[$u]}" = "$ver" ] || continue
      ini=$(ls /var/cagefs/*/"$u"/etc/cl.php.d/alt-php$n/alt_php.ini 2>/dev/null | head -1)
      [ -n "$ini" ] && ! grep -q 'opcache' "$ini" && users+=("$u")
    done
    echo "  alt-php$n: in version defaults=${in_default:-no}; users on $ver without opcache: ${#users[@]}${users:+ (${users[*]})}"
    [ $APPLY = 1 ] || continue
    if [ "${in_default:-no}" != "yes" ]; then
      selectorctl --enable-extensions=opcache --version="$ver" >/dev/null 2>&1 && { echo "    defaults: opcache enabled"; CHANGED=1; } || { echo "    defaults: FAILED"; FAIL=1; }
    fi
    for u in "${users[@]}"; do
      selectorctl --enable-user-extensions=opcache --version="$ver" --user="$u" >/dev/null 2>&1 && { echo "    $u: opcache enabled"; CHANGED=1; } || { echo "    $u: FAILED"; FAIL=1; }
    done
  done
fi

if [ $APPLY = 0 ]; then
  echo "dry run - nothing changed. Re-run with --apply."
  exit 0
fi

# ---------------------------------------------------------------- restart
# lsphp/mod_lsapi processes restart with the web server; PHP-FPM pools need their own restart.
if [ $CHANGED = 1 ]; then
  if [ -x /usr/local/lsws/bin/lswsctrl ]; then
    /usr/local/lsws/bin/lswsctrl restart >/dev/null && echo "LiteSpeed graceful restart sent"
  else
    /scripts/restartsrv_httpd --graceful >/dev/null 2>&1 && echo "Apache graceful restart sent"
  fi
  if ls /var/cpanel/userdata/*/*.php-fpm.yaml >/dev/null 2>&1; then
    /scripts/restartsrv_apache_php_fpm >/dev/null 2>&1 && echo "PHP-FPM pools restarted"
  fi
else
  echo "nothing changed - no restart needed"
fi

[ $FAIL = 0 ] && echo "done" || { echo "WARNING: at least one step failed (see above)"; exit 2; }
