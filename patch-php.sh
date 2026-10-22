#!/usr/bin/env bash
# php2shell-response.sh - interactive response for CVE-2026-109618 / CVE-2026-109619 ("php2shell").
#
#   1. Scan for signs of compromise (read-only, nothing changed)
#   2. Wizard: detect platform -> apply mitigation -> patch PHP -> restart -> verify
#
# Usage:  php2shell-response.sh              interactive: status -> mitigate -> patch -> verify -> optional scan
#         php2shell-response.sh --yes        answer yes to everything except the scan (Ansible / unattended)
#         php2shell-response.sh --yes --scan unattended, scan included
#         php2shell-response.sh --check      status report only, change nothing (add --scan to include the scan)
#         php2shell-response.sh --since DATE scan for changes since DATE (default 2026-10-20)
#
# Safe to re-run: every step is idempotent. Re-run when a vendor (e.g. CloudLinux) publishes new packages.
#
# Platforms: cPanel (with or without CloudLinux), DirectAdmin, Debian/Ubuntu, plain RHEL-family.
# Exit code: 0 when every PHP binary found is patched, 1 otherwise.

SINCE="2026-10-20"
AUTO_YES=0; CHECK_ONLY=0; DO_SCAN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y)   AUTO_YES=1 ;;
    --check)    CHECK_ONLY=1 ;;
    --scan)     DO_SCAN=1 ;;
    --since)    SINCE="$2"; shift ;;
    *) echo "Unknown option: $1"; exit 2 ;;
  esac; shift
done

CVE_RE='CVE-2026-10961[89]'
declare -A FIXED=([8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12)
MITIG_FILE='99-php2shell-mitigation.ini'
MITIG_BODY='; php2shell (CVE-2026-109618/109619) interim mitigation - safe to leave in place after patching
session.upload_progress.enabled = Off'

# ---------- helpers ----------
c_red=$'\e[31m'; c_grn=$'\e[32m'; c_yel=$'\e[33m'; c_bld=$'\e[1m'; c_off=$'\e[0m'
[ -t 1 ] || c_red= c_grn= c_yel= c_bld= c_off=
hdr()  { echo; echo "${c_bld}== $* ==${c_off}"; }
warn() { echo "${c_yel}[!]${c_off} $*"; }
bad()  { echo "${c_red}[X]${c_off} $*"; }
ok()   { echo "${c_grn}[+]${c_off} $*"; }
ask()  { # ask "question" -> 0 yes / 1 no
  [ $AUTO_YES = 1 ] && { echo "$1 [auto-yes]"; return 0; }
  local a; while true; do read -r -p "$1 [y/n] " a </dev/tty
    case "$a" in [Yy]*) return 0 ;; [Nn]*) return 1 ;; esac; done; }
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }
have()   { command -v "$1" >/dev/null 2>&1; }

# ---------- platform detection ----------
PLATFORM=other; CL=0; LSWS=0; PKG=none
[ -f /etc/cloudlinux-release ] && CL=1
[ -x /usr/local/lsws/bin/lswsctrl ] && LSWS=1
if   [ -x /usr/local/cpanel/cpanel ];          then PLATFORM=cpanel
elif [ -d /usr/local/directadmin/custombuild ]; then PLATFORM=directadmin
elif have apt-get;                              then PLATFORM=debian
elif have yum || have dnf;                      then PLATFORM=rhel
fi
if have dnf; then PKG=dnf; elif have yum; then PKG=yum; elif have apt-get; then PKG=apt; fi
WEBROOTS=(/home/*/public_html /home/*/domains/*/public_html /var/www /usr/share/nginx/html /srv/www)

php_binaries() {
  local b; for b in /opt/cpanel/ea-php*/root/usr/bin/php /opt/alt/php*/usr/bin/php \
                    /usr/local/php*/bin/php /usr/bin/php[0-9]*.[0-9]* /opt/remi/php*/root/usr/bin/php /usr/bin/php \
                    /opt/cpguard/cpg-php-fpm/bin/php /opt/cpguard/cpg-php-fpm/sbin/php-fpm /usr/local/lsws/lsphp*/bin/php; do
    [ -x "$b" ] && echo "$(readlink -f "$b")"; done | sort -u; }

# ---------- 1. compromise scan ----------
scan() {
  local findings=0 t
  hdr "Compromise scan on $(hostname) (changes since $SINCE)"

  echo "-- PHP workers spawning other processes"
  t=$(ps -eo pid,ppid,user,comm,args --no-headers | awk '
    { pid[$1]=1; comm[$1]=$4; ppid[$1]=$2; line[$1]=$0 }
    END { for (p in pid) { q=ppid[p]; if (q in comm && comm[q] ~ /^(php-fpm|php-cgi|lsphp|httpd|apache2|php[0-9.]*)$/ \
            && comm[p] !~ /^(php-fpm|php-cgi|lsphp|httpd|apache2|php[0-9.]*|suexec|cgi-sys|logrotate)$/) print line[p] } }')
  if [ -n "$t" ]; then bad "Unexpected children of PHP/web processes:"; echo "$t" | head -30; findings=1; else ok "none"; fi

  echo "-- Reverse-shell / dropper patterns in running processes"
  t=$(ps -eo pid,user,args --no-headers | grep -E '/dev/tcp/|mkfifo|fsockopen|nc (-e|-c)|socat .*exec|base64 (-d|--decode)|python[0-9.]* -c .*socket|perl -e .*socket' | grep -v grep)
  if [ -n "$t" ]; then bad "Suspicious command lines:"; echo "$t" | head -20; findings=1; else ok "none"; fi

  echo "-- Outbound connections from PHP workers"
  t=$(ss -tnp 2>/dev/null | grep -E 'users:\(\("(php|lsphp)' | grep -vE ':(3306|6379|11211|25|465|587|443|80|53) ' | head -20)
  if [ -n "$t" ]; then warn "Review these (DB/mail/HTTP ports are filtered out):"; echo "$t"; else ok "none unusual"; fi

  echo "-- PHP files created/modified in web roots since $SINCE (first 40)"
  t=$(timeout 180 find "${WEBROOTS[@]}" -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '.htaccess' \) \
        -newermt "$SINCE" -printf '%TY-%Tm-%Td %TH:%TM %u %p\n' 2>/dev/null | sort | head -40)
  if [ -n "$t" ]; then warn "Recently changed - normal for updates/deploys, abnormal for odd names or wp-content/uploads:"; echo "$t"; else ok "none"; fi

  echo "-- Likely webshells in web roots (first 20)"
  t=$(timeout 180 grep -rlE --include='*.php' --include='*.phtml' \
        '(eval|assert|system|passthru|shell_exec|popen|proc_open)\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress|\$_(GET|POST|REQUEST|COOKIE))' \
        "${WEBROOTS[@]}" 2>/dev/null | head -20)
  if [ -n "$t" ]; then bad "Review these files:"; echo "$t"; findings=1; else ok "none matched"; fi

  echo "-- Executables / PHP in temp dirs since $SINCE"
  t=$(find /tmp /var/tmp /dev/shm -xdev -type f -newermt "$SINCE" \( -perm -u+x -o -name '*.php' -o -name '*.sh' -o -name '*.pl' -o -name '*.py' \) -printf '%TY-%Tm-%Td %TH:%TM %u %p\n' 2>/dev/null | head -20)
  if [ -n "$t" ]; then bad "Found:"; echo "$t"; findings=1; else ok "none"; fi

  echo "-- Crontabs changed since $SINCE / suspicious cron lines"
  t=$(find /var/spool/cron /etc/cron.d /etc/crontab -newermt "$SINCE" 2>/dev/null)
  [ -n "$t" ] && { warn "Modified recently:"; echo "$t"; }
  t=$(grep -rE 'curl|wget|base64|/dev/tcp|/tmp/|/dev/shm' /var/spool/cron /etc/cron.d /etc/crontab 2>/dev/null | head -20)
  if [ -n "$t" ]; then warn "Cron lines worth a look:"; echo "$t"; else ok "no suspicious cron lines"; fi

  echo "-- Account / SSH key changes since $SINCE"
  t=$(find /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d /root/.ssh /home/*/.ssh -newermt "$SINCE" 2>/dev/null)
  if [ -n "$t" ]; then warn "Changed:"; echo "$t"; else ok "none"; fi

  echo
  if [ $findings = 1 ]; then
    bad "${c_bld}Possible compromise indicators found. Preserve logs before changing anything if you intend to investigate.${c_off}"
  else
    ok "No strong indicators. (This is a quick triage, not a forensic audit.)"
  fi
}

# ---------- 2. mitigation ----------
mitigation_dirs() {
  local d
  for d in /opt/cpanel/ea-php*/root/etc/php.d /opt/alt/php*/etc/php.d /opt/alt/php*/link/conf \
           /usr/local/php*/lib/php.conf.d /etc/php/[0-9]*/*/conf.d /etc/php.d /etc/opt/remi/php*/php.d; do
    [ -d "$d" ] && echo "$d"; done; }

mitigate() {
  hdr "Applying interim mitigation (session.upload_progress.enabled = Off)"
  local d n=0
  while read -r d; do
    [ -n "$d" ] || continue
    printf '%s\n' "$MITIG_BODY" > "$d/$MITIG_FILE" && { echo "  wrote $d/$MITIG_FILE"; n=$((n+1)); }
  done < <(mitigation_dirs)
  [ $n = 0 ] && warn "No PHP conf.d directories found - add the setting to php.ini by hand."
  echo "Checking nothing re-enables it per site/user..."
  local t
  t=$(grep -rsl 'upload_progress.enabled *= *\(1\|on\|true\)' /home/*/public_html/.user.ini /home/*/public_html/php.ini \
        /home/*/php.ini /etc/php/*/fpm/pool.d /etc/apache2 /etc/httpd /usr/local/apache/conf /etc/php-fpm.d 2>/dev/null | head)
  [ -n "$t" ] && warn "These re-enable it and need editing:"$'\n'"$t" || ok "no overrides found"
  restart_php
}

# CL's fixed alt-php is now in the stable repos; the temporary TuxCare ELS repo (php-els) can be disabled.
els_repo_cleanup() {
  [ $CL = 1 ] || return 0
  if $PKG repolist --enabled 2>/dev/null | grep -q '^php-els'; then
    warn "Temporary ELS ALT PHP repo (php-els) is enabled - fixed alt-php is now in CL stable, disabling it as CL advises"
    if have dnf; then dnf config-manager --set-disabled php-els; else yum-config-manager --disable php-els >/dev/null; fi
  fi
}

# ---------- 3. patch ----------
patch() {
  hdr "Patching PHP ($PLATFORM${CL:+, CloudLinux=$CL})"
  local pkgs
  case $PLATFORM in
    cpanel)
      # cPanel 138.0.18 carries the fix for cPanel's own internal PHP (CPANEL-57977); skip upcp if already there
      local cpv; cpv=$(/usr/local/cpanel/cpanel -V 2>/dev/null | sed -E 's/ \(build ([0-9]+)\)/.\1/')
      if ver_ge "${cpv:-0}" 138.0.18; then echo "cPanel $cpv already >= 138.0.18, skipping upcp"
      else echo "cPanel ${cpv:-unknown} < 138.0.18, running upcp"; /scripts/upcp; fi
      els_repo_cleanup
      $PKG clean all -q
      # ea-php, alt-php, and the OS's own php packages (CL is rolling native php fixes separately)
      pkgs=$(rpm -qa --qf '%{NAME}\n' 'ea-php*' 'alt-php*' 'php' 'php-*' | sort -u)
      [ -n "$pkgs" ] && $PKG -y update $pkgs || warn "no PHP packages installed"
      [ $CL = 1 ] && have cagefsctl && cagefsctl --force-update ;;
    directadmin)
      ( cd /usr/local/directadmin/custombuild && ./build update && ./build php )
      if [ $CL = 1 ]; then
        els_repo_cleanup
        $PKG clean all -q
        pkgs=$(rpm -qa --qf '%{NAME}\n' 'alt-php*' 'php' 'php-*' | sort -u)
        [ -n "$pkgs" ] && $PKG -y update $pkgs
        have cagefsctl && cagefsctl --force-update
      fi ;;
    debian)
      apt-get update -q || warn "apt-get update reported errors - new packages may be missed"
      pkgs=$(dpkg-query -W -f='${binary:Package} ${db:Status-Status}\n' 'php[0-9]*' 'libapache2-mod-php*' 'alt-php*' 2>/dev/null | awk '$2=="installed"{print $1}')
      [ -n "$pkgs" ] && DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade -o Dpkg::Options::=--force-confold $pkgs \
        || warn "no PHP packages installed via apt" ;;
    rhel)
      $PKG clean metadata -q
      pkgs=$(rpm -qa --qf '%{NAME}\n' 'php*' | sort -u)
      [ -n "$pkgs" ] && $PKG -y update $pkgs || warn "no PHP packages installed via rpm"
      rpm -qa | grep -q remi && warn "remi packages: the remi repo may lag behind - verify below" ;;
    *) bad "Unrecognised platform - patch manually"; return 1 ;;
  esac
  restart_php
}

restart_php() {
  echo "Restarting PHP services..."
  case $PLATFORM in
    cpanel)
      /scripts/restartsrv_apache_php_fpm >/dev/null 2>&1; /scripts/restartsrv_httpd >/dev/null 2>&1 ;;
    directadmin)
      systemctl list-units --type=service --no-legend --plain 'php-fpm*' | awk '{print $1}' | xargs -r systemctl restart
      systemctl try-restart httpd 2>/dev/null ;;
    debian)
      systemctl list-units --type=service --no-legend --plain 'php*-fpm*' | awk '{print $1}' | xargs -r systemctl reload
      systemctl try-reload-or-restart apache2 2>/dev/null ;;
    rhel)
      systemctl list-units --type=service --no-legend --plain 'php*-fpm*' | awk '{print $1}' | xargs -r systemctl restart
      systemctl try-restart httpd 2>/dev/null ;;
  esac
  [ $LSWS = 1 ] && /usr/local/lsws/bin/lswsctrl restart >/dev/null 2>&1
  ok "done"
}

# ---------- 3b. cPGuard WAF check ----------
cpguard_check() {
  local root="" d f newest hits
  for d in /usr/local/cpguard /opt/cpguard /etc/cpguard; do [ -d "$d" ] && { root="$d"; break; }; done
  have cpguard && root="${root:-$(dirname "$(readlink -f "$(command -v cpguard)")")}"
  [ -n "$root" ] || return 0            # cPGuard not installed - nothing to check
  hdr "cPGuard WAF"
  # rule files cPGuard may have dropped, in its own tree or the server's ModSecurity include dirs
  # cPGuard installs its ModSecurity rules under /etc/cpguard/ (included from modsec2.user.conf on cPanel)
  hits=$(grep -rslE 'PHP_SESSION_UPLOAD_PROGRESS|upload_progress|php2shell|CVE-2026-10961' \
          /etc/cpguard "$root" /etc/apache2/conf.d /etc/httpd/conf.d /usr/local/apache/conf /etc/modsecurity /usr/local/lsws/conf \
          /etc/nginx/modsec /usr/local/directadmin/custombuild/custom/modsecurity 2>/dev/null | grep -vE '/cpg-php-fpm/|\.log$|\.h$' | head -5)
  if [ -n "$hits" ]; then
    ok "php2shell WAF rule present:"; echo "$hits" | sed 's/^/    /'
    newest=$(stat -c '%y %n' $hits 2>/dev/null | sort | tail -1 | cut -c1-16)
    echo "    newest rule file: $newest"
  else
    warn "cPGuard is installed ($root) but no php2shell rule was found in the usual rule locations."
    warn "Force a rule refresh: cPGuard UI -> WAF module -> disable, then enable. Then re-run with --check."
  fi
  f=$(ls -t "$root"/*.log "$root"/logs/*.log /var/log/cpguard*.log 2>/dev/null | head -1)
  [ -n "$f" ] && echo "    last cPGuard log activity: $(stat -c %y "$f" | cut -c1-16)  ($f)"
  # cPGuard ships its own PHP-FPM for its UI; it is reported in the PHP status table above
  [ -x "$root/cpg-php-fpm/sbin/php-fpm" ] && \
    warn "cPGuard's bundled PHP-FPM ($("$root/cpg-php-fpm/sbin/php-fpm" -v 2>/dev/null | head -1 | cut -d' ' -f2)) can only be fixed by an OpsShield update - see table above"
}

# Any PHP worker started before the newest PHP binary was installed is still running old code.
stale_process_check() {
  local newest=0 t p stale="" pid exe
  for p in $(php_binaries); do t=$(stat -c %Y "$p" 2>/dev/null); [ "${t:-0}" -gt $newest ] && newest=$t; done
  [ $newest = 0 ] && return
  while read -r pid; do
    [ -n "$pid" ] || continue
    t=$(stat -c %Y "/proc/$pid" 2>/dev/null) || continue
    [ "$t" -lt $newest ] && stale="$stale $pid"
  done < <(pgrep -x 'php-fpm|php-fpm[0-9.]*|lsphp|lsphp[0-9]*|php-cgi|httpd|apache2|lshttpd|litespeed|openlitespeed' 2>/dev/null)
  if [ -n "$stale" ]; then
    bad "PHP/web processes started BEFORE the newest PHP package was installed (still running old code):"
    ps -o pid,lstart,user,comm --no-headers -p ${stale// /,} | head -15
    bad=1
  else
    ok "all PHP/web worker processes started after the newest PHP package install"
  fi
}

# ---------- 4. verify ----------
verify() {
  hdr "PHP status on $(hostname)"
  local bad=0 found=0 bin ver br pkg log st mit
  printf '%-30s %-9s %-10s %s\n' "PATCH STATUS" "MITIG." "VERSION" "BINARY"
  while read -r bin; do
    [ -n "$bin" ] || continue; found=1
    # CloudLinux's /usr/bin/php is a selector wrapper that dispatches to an alt-php build already listed above
    if [ "$bin" = /usr/bin/php ] && [ $CL = 1 ]; then
      pkg=$(rpm -qf --qf '%{NAME}' "$bin" 2>/dev/null)
      if [[ "$pkg" != php && "$pkg" != php-cli ]]; then
        printf '%-30s %-9s %-10s %s\n' "SKIPPED (CL selector wrapper)" "-" "-" "$bin"; continue; fi
    fi
    ver=$("$bin" -n -r 'echo PHP_VERSION;' 2>/dev/null | head -1)
    [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] || ver=$("$bin" -n -v 2>/dev/null | sed -nE 's/^PHP ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -1)   # php-fpm has no -r
    [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] || ver=""
    if [ -z "$ver" ]; then
      pkg=$(rpm -qf --qf '%{NAME}' "$bin" 2>/dev/null)
      if [ "$bin" = /usr/bin/php ] && [ $CL = 1 ] && [[ "$pkg" != php && "$pkg" != php-cli ]]; then
        printf '%-30s %-9s %-10s %s\n' "SKIPPED (CL selector wrapper)" "-" "-" "$bin"
      else
        printf '%-30s %-9s %-10s %s\n' "UNKNOWN (will not run)" "-" "-" "$bin"; bad=1
      fi; continue; fi
    br=${ver%.*}
    log=""
    if pkg=$(rpm -qf --qf '%{NAME}' "$bin" 2>/dev/null); then
      # CL puts the CVE note in the package that owns the binary and/or its -common package; check both
      log=$(rpm -q --changelog "$pkg" 2>/dev/null | head -300)
      case $pkg in
        alt-php[0-9]*) log+=$'\n'$(rpm -q --changelog "${pkg%%-php-*}-common" "${pkg}-common" 2>/dev/null | head -300) ;;
        ea-php[0-9]*)  log+=$'\n'$(rpm -q --changelog "${pkg%%-php-*}-php-common" 2>/dev/null | head -300) ;;
      esac
    else pkg=$(dpkg -S "$bin" 2>/dev/null | head -1 | cut -d: -f1)
         [ -n "$pkg" ] && log=$(zcat "/usr/share/doc/$pkg/changelog.Debian.gz" 2>/dev/null | head -300); fi
    if   [ -n "${FIXED[$br]}" ] && ver_ge "$ver" "${FIXED[$br]}"; then st="PATCHED"
    elif grep -qE "$CVE_RE" <<<"$log";                             then st="PATCHED (backport)"
    elif [[ "$bin" == /opt/alt/php-internal/* ]];                   then st="INFO: CL internal, not web"
    elif [[ "$bin" == /opt/cpguard/* ]];                            then st="NOT PATCHED (cPGuard bundled)"; bad=1
    elif ! ver_ge "$br" 7.4;                                        then st="NOT PATCHED (EOL upstream)"; bad=1
    elif [ -z "$log" ] && [ -z "${FIXED[$br]}" ];                   then st="CHECK MANUALLY"; bad=1
    else st="NOT PATCHED"; bad=1; fi
    mit=$("$bin" -r 'echo ini_get("session.upload_progress.enabled") ? "on" : "off";' 2>/dev/null | head -1)
    [[ "$mit" == on || "$mit" == off ]] || mit="?"
    [[ "$bin" == */php-fpm ]] && mit="n/a"
    printf '%-30s %-9s %-10s %s\n' "$st" "${mit:-?}" "$ver" "$bin"
  done < <(php_binaries)
  [ $found = 1 ] || { warn "No PHP binaries found"; bad=1; }
  stale_process_check
  echo
  if [ $bad = 0 ]; then ok "${c_bld}RESULT: all PHP binaries patched${c_off}"
  else bad "${c_bld}RESULT: action still needed - unpatched binaries need the mitigation ('off' column) until a fix lands${c_off}"; fi
  [ "$PLATFORM" = cpanel ] && echo "Note: a user's own .user.ini/php.ini can override the mitigation; the 'MITIG.' column shows the server default."
  kernel_check
  return $bad
}

# Informational: the separate CL kernel advisory (KEV-listed CVE-2025-39964 / CVE-2026-53266 / CVE-2025-39682).
kernel_check() {
  have kcarectl || return 0
  echo
  echo "-- Kernel (CloudLinux advisory q1t6qbd5jjy5, separate from php2shell) --"
  local info k clv c inkernel
  info=$(kcarectl --patch-info 2>/dev/null); k=$(uname -r)
  clv=$(grep -oE '[0-9]+' /etc/cloudlinux-release 2>/dev/null | head -1)
  # Fixes already compiled into the running kernel, per CL advisory q1t6qbd5jjy5 (22 Oct 2026)
  inkernel=""
  case $clv in
    7|8)  ver_ge "${k%%.lve*}" 4.18.0-553.142.1 && inkernel="CVE-2026-53266" ;;
    9)    ver_ge "${k%%.el9*}" 5.14.0-687.23.1  && inkernel="CVE-2026-53266 CVE-2025-39682" ;;
    10)   ver_ge "${k%%.el10*}" 6.12.0-211.59.1 && inkernel="CVE-2025-39964 CVE-2026-53266 CVE-2025-39682" ;;
  esac
  for c in CVE-2025-39964 CVE-2026-53266 CVE-2025-39682; do
    if   grep -q "$c" <<<"$info";     then ok "$c livepatched (KernelCare)"
    elif grep -q "$c" <<<"$inkernel"; then ok "$c fixed in running kernel"
    elif [ "$c" = CVE-2025-39682 ] && [[ "$clv" == 7 || "$clv" == 8 ]] && ! grep -q lts <<<"$k"; then ok "$c does not affect CloudLinux $clv"
    else warn "$c not covered: try 'kcarectl --update'; otherwise needs kernel update + reboot (see CL advisory)"; fi
  done
  echo "   CloudLinux $clv, running kernel $k, kcarectl effective: $(kcarectl --uname 2>/dev/null | head -1)"
}

# ---------- main ----------
hdr "php2shell response - $(hostname)"
echo "Platform: $PLATFORM | CloudLinux: $CL | LiteSpeed: $LSWS | Package manager: $PKG"
echo "PHP binaries: $(php_binaries | wc -l)"
if [ $CHECK_ONLY = 1 ]; then verify; RC=$?; cpguard_check; [ $DO_SCAN = 1 ] && scan; exit $RC; fi

verify; RC=$?
cpguard_check
echo
if [ $RC != 0 ]; then
  ask "Apply the interim mitigation (upload_progress off + service reload)?" && mitigate
  echo
  ask "Attempt to patch PHP now via $PKG and restart PHP services?" && { patch; echo; verify; RC=$?; }
else
  ask "Everything is patched. Apply the mitigation anyway as belt-and-braces?" && mitigate
fi
echo
if [ $DO_SCAN = 1 ]; then scan
elif [ $AUTO_YES = 0 ]; then ask "Run the compromise scan now (read-only, can take a few minutes)?" && scan
fi
exit $RC
