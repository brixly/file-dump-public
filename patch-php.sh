#!/usr/bin/env bash
# php2shell-response.sh - interactive response for CVE-2026-109618 / CVE-2026-109619 ("php2shell").
#
#   1. Scan for signs of compromise (read-only, nothing changed)
#   2. Wizard: detect platform -> apply mitigation -> patch PHP -> restart -> verify
#
# Usage:  php2shell-response.sh              interactive (asks y/n at each step)
#         php2shell-response.sh --yes        answer yes to everything (Ansible / unattended)
#         php2shell-response.sh --check      scan + report only, change nothing
#         php2shell-response.sh --since DATE look for changes since DATE (default 2026-10-20)
#
# Platforms: cPanel (with or without CloudLinux), DirectAdmin, Debian/Ubuntu, plain RHEL-family.
# Exit code: 0 when every PHP binary found is patched, 1 otherwise.

SINCE="2026-10-20"
AUTO_YES=0; CHECK_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y)   AUTO_YES=1 ;;
    --check)    CHECK_ONLY=1 ;;
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
                    /usr/local/php*/bin/php /usr/bin/php[0-9]*.[0-9]* /opt/remi/php*/root/usr/bin/php /usr/bin/php; do
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

# ---------- 3. patch ----------
patch() {
  hdr "Patching PHP ($PLATFORM${CL:+, CloudLinux=$CL})"
  local pkgs
  case $PLATFORM in
    cpanel)
      /scripts/upcp
      $PKG clean metadata -q
      pkgs=$(rpm -qa --qf '%{NAME}\n' 'ea-php*' 'alt-php*' | sort -u)
      [ -n "$pkgs" ] && $PKG -y update $pkgs || warn "no ea-php/alt-php packages installed"
      [ $CL = 1 ] && have cagefsctl && cagefsctl --force-update ;;
    directadmin)
      ( cd /usr/local/directadmin/custombuild && ./build update && ./build php )
      if [ $CL = 1 ]; then
        $PKG clean metadata -q
        pkgs=$(rpm -qa --qf '%{NAME}\n' 'alt-php*' | sort -u)
        [ -n "$pkgs" ] && $PKG -y update $pkgs
        have cagefsctl && cagefsctl --force-update
      fi ;;
    debian)
      apt-get update -q || warn "apt-get update reported errors - new packages may be missed"
      pkgs=$(dpkg-query -W -f='${binary:Package} ${db:Status-Status}\n' 'php[0-9]*' 'libapache2-mod-php*' 2>/dev/null | awk '$2=="installed"{print $1}')
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

# ---------- 4. verify ----------
verify() {
  hdr "PHP status on $(hostname)"
  local bad=0 found=0 bin ver br pkg log st mit
  printf '%-30s %-9s %-10s %s\n' "PATCH STATUS" "MITIG." "VERSION" "BINARY"
  while read -r bin; do
    [ -n "$bin" ] || continue; found=1
    if ! ver=$("$bin" -n -r 'echo PHP_VERSION;' 2>/dev/null) || [ -z "$ver" ]; then
      printf '%-30s %-9s %-10s %s\n' "UNKNOWN (will not run)" "-" "-" "$bin"; bad=1; continue; fi
    br=${ver%.*}
    log=""
    if pkg=$(rpm -qf "$bin" 2>/dev/null); then log=$(rpm -q --changelog "$pkg" 2>/dev/null | head -300)
    else pkg=$(dpkg -S "$bin" 2>/dev/null | head -1 | cut -d: -f1)
         [ -n "$pkg" ] && log=$(zcat "/usr/share/doc/$pkg/changelog.Debian.gz" 2>/dev/null | head -300); fi
    if   [ -n "${FIXED[$br]}" ] && ver_ge "$ver" "${FIXED[$br]}"; then st="PATCHED"
    elif grep -qE "$CVE_RE" <<<"$log";                             then st="PATCHED (backport)"
    elif ! ver_ge "$br" 7.4;                                        then st="NO FIX - EOL"; bad=1
    elif [ -z "$log" ] && [ -z "${FIXED[$br]}" ];                   then st="CHECK MANUALLY"; bad=1
    else st="NOT PATCHED"; bad=1; fi
    mit=$("$bin" -r 'echo ini_get("session.upload_progress.enabled") ? "on" : "off";' 2>/dev/null)
    printf '%-30s %-9s %-10s %s\n' "$st" "${mit:-?}" "$ver" "$bin"
  done < <(php_binaries)
  [ $found = 1 ] || { warn "No PHP binaries found"; bad=1; }
  echo
  if [ $bad = 0 ]; then ok "${c_bld}RESULT: all PHP binaries patched${c_off}"
  else bad "${c_bld}RESULT: action still needed - unpatched binaries need the mitigation ('off' column) until a fix lands${c_off}"; fi
  [ "$PLATFORM" = cpanel ] && echo "Note: a user's own .user.ini/php.ini can override the mitigation; the 'MITIG.' column shows the server default."
  return $bad
}

# ---------- main ----------
hdr "php2shell response - $(hostname)"
echo "Platform: $PLATFORM | CloudLinux: $CL | LiteSpeed: $LSWS | Package manager: $PKG"
echo "PHP binaries: $(php_binaries | wc -l)"
if [ $CHECK_ONLY = 1 ]; then scan; verify; exit $?; fi

ask "Run the compromise scan (read-only)?" && scan
echo
verify; RC=$?
echo
if [ $RC != 0 ]; then
  ask "Apply the interim mitigation (upload_progress off + service reload)?" && mitigate
  echo
  ask "Attempt to patch PHP now via $PKG and restart PHP services?" && { patch; echo; verify; RC=$?; }
else
  ask "Everything is patched. Apply the mitigation anyway as belt-and-braces?" && mitigate
fi
exit $RC
