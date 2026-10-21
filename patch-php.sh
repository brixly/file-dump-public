#!/usr/bin/env bash
# patch-php.sh - update PHP for CVE-2026-109618 / CVE-2026-109619, then report per-binary status.
#
# Usage:  patch-php.sh            update, restart PHP services, report
#         patch-php.sh --check    report only, change nothing
#
# Exit code: 0 if every PHP binary found is patched, 1 otherwise (handy for Ansible).
#
# Platforms: cPanel (incl. CloudLinux ea-php / alt-php), DirectAdmin (incl. CloudLinux alt-php),
#            Debian/Ubuntu (Ondrej PPA or distro PHP). Anything else is reported as unrecognised.

CVE_RE='CVE-2026-10961[89]'
# First fixed upstream release per branch. 7.4 / 8.0 / 8.1 rely on vendor backports (detected via changelog).
declare -A FIXED=([8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12)

# ver_ge A B -> true if version A >= version B
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

update() {
  local pkgs
  if [ -x /usr/local/cpanel/cpanel ]; then
    /scripts/upcp
    yum clean metadata -q
    pkgs=$(rpm -qa --qf '%{NAME}\n' 'ea-php*' 'alt-php*' | sort -u)
    [ -n "$pkgs" ] && yum -y update $pkgs          # guard: an empty list would update everything
    command -v cagefsctl >/dev/null && cagefsctl --force-update
    /scripts/restartsrv_apache_php_fpm
    /scripts/restartsrv_httpd
    [ -x /usr/local/lsws/bin/lswsctrl ] && /usr/local/lsws/bin/lswsctrl restart

  elif [ -d /usr/local/directadmin/custombuild ]; then
    ( cd /usr/local/directadmin/custombuild && ./build update && ./build php )
    if command -v cagefsctl >/dev/null; then
      yum clean metadata -q
      pkgs=$(rpm -qa --qf '%{NAME}\n' 'alt-php*' | sort -u)
      [ -n "$pkgs" ] && yum -y update $pkgs
      cagefsctl --force-update
    fi

  elif command -v apt-get >/dev/null; then
    apt-get update -q
    dpkg-query -W -f='${binary:Package} ${db:Status-Status}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null \
      | awk '$2=="installed"{print $1}' | xargs -r apt-get install -y --only-upgrade
    systemctl list-units --type=service --no-legend --plain 'php*-fpm*' | awk '{print $1}' | xargs -r systemctl reload
    systemctl try-restart apache2 2>/dev/null

  else
    echo "Unrecognised platform - patch manually"
    return 1
  fi
}

check() {
  local bad=0 found=0 bin ver br pkg log st
  for bin in /opt/cpanel/ea-php*/root/usr/bin/php \
             /opt/alt/php*/usr/bin/php \
             /usr/local/php*/bin/php \
             /usr/bin/php[0-9]*.[0-9]*; do
    [ -x "$bin" ] || continue
    found=1

    if ! ver=$("$bin" -n -r 'echo PHP_VERSION;' 2>/dev/null) || [ -z "$ver" ]; then
      printf '%-44s %-10s %s\n' "UNKNOWN - binary would not run" "-" "$bin"; bad=1; continue
    fi
    br=${ver%.*}

    # Pull the owning package's changelog, if the binary belongs to a package.
    log=""
    if pkg=$(rpm -qf "$bin" 2>/dev/null); then
      log=$(rpm -q --changelog "$pkg" 2>/dev/null | head -300)
    else
      pkg=$(dpkg -S "$(readlink -f "$bin")" 2>/dev/null | head -1 | cut -d: -f1)
      [ -n "$pkg" ] && log=$(zcat "/usr/share/doc/$pkg/changelog.Debian.gz" 2>/dev/null | head -300)
    fi

    if [ -n "${FIXED[$br]}" ] && ver_ge "$ver" "${FIXED[$br]}"; then
      st="PATCHED"
    elif grep -qE "$CVE_RE" <<<"$log"; then
      st="PATCHED (vendor backport)"
    elif ! ver_ge "$br" 7.4; then
      st="NO FIX AVAILABLE - EOL, move sites off it"; bad=1
    elif [ -z "$log" ] && [ -z "${FIXED[$br]}" ]; then
      st="CHECK MANUALLY - source build, no changelog"; bad=1
    else
      st="NOT PATCHED"; bad=1
    fi
    printf '%-44s %-10s %s\n' "$st" "$ver" "$bin"
  done

  [ "$found" = 1 ] || { echo "No PHP binaries found in the usual locations"; bad=1; }
  return $bad
}

[ "$1" = "--check" ] || update
echo
echo "== PHP status on $(hostname) =="
check
rc=$?
[ $rc -eq 0 ] && echo "RESULT: all PHP binaries patched" || echo "RESULT: action needed (see above)"
exit $rc
