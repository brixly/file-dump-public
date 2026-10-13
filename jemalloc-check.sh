#!/bin/bash
# mysql-memcheck.sh v2 - Assess MariaDB/MySQL memory creep and buffer pool sizing on shared hosting
# servers, then optionally apply fixes, each behind a typed "yes":
#   jemalloc  enable jemalloc (restarts the database)
#   pool      resize innodb_buffer_pool_size (online)
#   settings  innodb_log_file_size 4G, innodb_flush_log_at_trx_commit=2, table_definition_cache (online)
#   logger    install a 15-minute memory logger (/root/mariadb-memlog.csv)
#
# Usage:  bash mysql-memcheck.sh                    report, then offer every step
#         bash mysql-memcheck.sh --report           checks only, never changes anything
#         bash mysql-memcheck.sh --only jemalloc    report, then offer just that step (jemalloc|pool|settings|logger)
#         bash mysql-memcheck.sh --tdc 2000         suggest this table_definition_cache value (fleet standard)
#
# Every run is logged to /root/mysql-memcheck-<date>.log; config files are backed up before any edit.

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }
REPORT_ONLY=0; ONLY=all; TDC_SUGGEST=""
while [ $# -gt 0 ]; do
  case "$1" in
    --report) REPORT_ONLY=1 ;;
    --only) ONLY=$2; shift ;;
    --tdc) TDC_SUGGEST=$2; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1 (try --help)"; exit 1 ;;
  esac; shift
done
case "$ONLY" in all|jemalloc|pool|settings|logger) ;; *) echo "--only must be jemalloc, pool, settings or logger"; exit 1 ;; esac
[ "$(id -u)" = 0 ] || { echo "Run as root."; exit 1; }
[ -t 0 ] || { [ $REPORT_ONLY = 1 ] || echo "No terminal for prompts: running in report-only mode."; REPORT_ONLY=1; }
exec 9>/run/mysql-memcheck.lock; flock -n 9 || { echo "Another mysql-memcheck run is in progress."; exit 1; }

LOG=/root/mysql-memcheck-$(date +%Y%m%d-%H%M%S).log
if [ -t 1 ]; then B=$(tput bold); G=$(tput setaf 2); Y=$(tput setaf 3); R=$(tput setaf 1); N=$(tput sgr0); else B=; G=; Y=; R=; N=; fi
say()  { echo "$*" | tee -a "$LOG"; }
hdr()  { say ""; say "${B}== $* ==${N}"; }
ok()   { say "  ${G}OK${N}    $*"; }
warn() { say "  ${Y}WARN${N}  $*"; }
bad()  { say "  ${R}FIX${N}   $*"; }
info() { say "        $*"; }
ask()  { # ask "question" -> 0 only if the user types exactly "yes"
  [ $REPORT_ONLY = 1 ] && return 1
  local a; read -r -p "  ${B}$1 [type yes to proceed]: ${N}" a; echo "  answer: ${a:-<none>}" >> "$LOG"; [ "$a" = "yes" ]; }
gib()  { awk -v b="$1" 'BEGIN{printf "%.1f", b/1073741824}'; }
want() { [ "$ONLY" = all ] || [ "$ONLY" = "$1" ]; }
DONE=(); SKIPPED=(); NEXT=()
done_()  { DONE+=("$*"); }
skip_()  { SKIPPED+=("$*"); }
next_()  { NEXT+=("$*"); }

# ---------------------------------------------------------------- connection
hdr "Environment"
PANEL=unknown; MY=""
if [ -f /usr/local/directadmin/conf/my.cnf ]; then PANEL=DirectAdmin; MY="mysql --defaults-extra-file=/usr/local/directadmin/conf/my.cnf"
elif [ -d /usr/local/cpanel ] && [ -f /root/.my.cnf ]; then PANEL=cPanel; MY="mysql"
elif [ -f /etc/psa/.psa.shadow ]; then PANEL=Plesk; export MYSQL_PWD="$(cat /etc/psa/.psa.shadow)"; MY="mysql -uadmin"
elif [ -f /root/.my.cnf ]; then PANEL="other (/root/.my.cnf)"; MY="mysql"
fi
[ -n "$MY" ] && $MY -N -e "SELECT 1" >/dev/null 2>&1 || { echo "Cannot log in to MySQL (panel: $PANEL). Create /root/.my.cnf and re-run."; exit 1; }
q()  { $MY -N -e "$1" 2>/dev/null; }
gv() { q "SELECT @@$1" ; }
gs() { q "SHOW GLOBAL STATUS LIKE '$1'" | awk '{print $2}'; }

VERSION=$(gv version); IS_MARIADB=0; echo "$VERSION" | grep -qi mariadb && IS_MARIADB=1
PROC=$(pgrep -xo mariadbd || pgrep -xo mysqld); [ -n "$PROC" ] || { echo "Database process not found."; exit 1; }
UNIT=""
for u in mariadb mysqld mysql; do
  if systemctl cat "$u.service" >/dev/null 2>&1; then UNIT=$(systemctl show -p Id --value "$u.service"); break; fi
done
info "Host: $(hostname)   Panel: $PANEL"
info "Server: $VERSION   Unit: ${UNIT:-NOT FOUND}   PID: $PROC"

# ---------------------------------------------------------------- figures
RAM=$(( $(awk '/MemTotal/{print $2}' /proc/meminfo) * 1024 )); AVAIL=$(( $(awk '/MemAvailable/{print $2}' /proc/meminfo) * 1024 ))
RSS=$(( $(awk '/VmRSS/{print $2}' /proc/$PROC/status) * 1024 )); HWM=$(( $(awk '/VmHWM/{print $2}' /proc/$PROC/status) * 1024 ))
UPTIME=$(gs Uptime); POOL=$(gv innodb_buffer_pool_size); KEYBUF=$(gv key_buffer_size)
ARIA=0; [ $IS_MARIADB = 1 ] && ARIA=$(gv aria_pagecache_buffer_size)
THP=$(sed -E 's/.*\[(.*)\].*/\1/' /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null)
if [ $IS_MARIADB = 1 ]; then ALLOC=$(gv version_malloc_library); else grep -q jemalloc /proc/$PROC/maps && ALLOC=jemalloc || ALLOC=system; fi
JEMALLOC=0; echo "$ALLOC" | grep -qi jemalloc && JEMALLOC=1
DATADIR=$(gv datadir)
INNODB_DATA=$(find "$DATADIR" -name '*.ibd' -printf '%s\n' 2>/dev/null | awk '{s+=$1} END{print s+0}')
PFREE=$(gs Innodb_buffer_pool_pages_free); PTOTAL=$(gs Innodb_buffer_pool_pages_total)
POOLFREE_PCT=$(( PFREE * 100 / (PTOTAL > 0 ? PTOTAL : 1) ))
UP_H=$(awk -v u=$UPTIME 'BEGIN{printf "%.1f", u/3600}'); UP_D=$(awk -v u=$UPTIME 'BEGIN{printf "%.1f", u/86400}')
# Cold = up < 1 day, or pool < 95% full within the first 3 days (after that, free pages just mean the pool is bigger than the data)
WARM=1; { [ "$UPTIME" -lt 86400 ] || { [ $POOLFREE_PCT -gt 5 ] && [ "$UPTIME" -lt 259200 ]; }; } && WARM=0

hdr "Memory"
info "RAM total $(gib $RAM) GiB, available $(gib $AVAIL) GiB, transparent huge pages: ${THP:-n/a}"
info "Database resident (RSS) $(gib $RSS) GiB, peak (HWM) $(gib $HWM) GiB, up $UP_D days"
info "Configured caches: buffer pool $(gib $POOL) GiB ($((100-POOLFREE_PCT))% filled), key buffer $(gib $KEYBUF) GiB, Aria $(gib $ARIA) GiB"
info "Allocator: $ALLOC"
if [ $IS_MARIADB = 1 ]; then USED=$(gs Memory_used); LABEL="Tracked by the database (Memory_used)"
else USED=$((POOL+KEYBUF)); LABEL="Configured caches (MySQL has no Memory_used; rough)"; fi
GAP=$((RSS-USED)); [ $GAP -lt 0 ] && GAP=0      # negative while the pool is still filling (Memory_used counts the full pool)
RATE=$(awk -v g=$GAP -v u=$UPTIME 'BEGIN{printf "%.2f", (g/1073741824)/(u/86400)}')
info "$LABEL $(gib $USED) GiB -> untracked gap $(gib $GAP) GiB ($(awk -v g=$GAP -v u=$USED 'BEGIN{printf "%.0f", 100*g/u}')% of tracked), ~$RATE GiB/day since start"

CREEP=none
if [ $JEMALLOC = 1 ]; then ok "jemalloc already in use."; CREEP=done
  [ $WARM = 0 ] && info "Still warming up (up $UP_H h, pool $((100-POOLFREE_PCT))% filled): gap figures settle after ~1 day."
elif [ $GAP -gt 8589934592 ] || [ $GAP -gt $USED ]; then
  bad "STRONG memory creep: $(gib $GAP) GiB untracked after $UP_D days. jemalloc recommended."; CREEP=strong
  ROOM=$(( AVAIL - RAM/10 ))
  awk -v r=$ROOM -v g=$RATE 'BEGIN{exit !(g>0.05 && r>0)}' && \
    warn "If growth continued at ~$RATE GiB/day (rough; it usually slows), the remaining headroom ($(gib $ROOM) GiB above a 10% floor) lasts roughly $(awk -v r=$ROOM -v g=$RATE 'BEGIN{printf "%.0f", (r/1073741824)/g}') days."  
elif [ $WARM = 0 ]; then warn "Up only $UP_H h; small gaps aren't meaningful yet. Re-run after 3 days."
elif [ "$UPTIME" -lt 259200 ] && [ $GAP -le 4294967296 ]; then warn "Up < 3 days with a small gap; creep may not be visible yet. Re-run later."
elif [ $GAP -gt 2147483648 ] && [ $((GAP*10)) -gt $((USED*3)) ]; then warn "Moderate memory creep. jemalloc recommended."; CREEP=recommended
else ok "Little untracked memory; jemalloc optional (low benefit)."; CREEP=low; fi
[ "$THP" = "always" ] && warn "Transparent huge pages = always: jemalloc can use more memory with this. Consider 'madvise' or 'never'."

hdr "Buffer pool"
R1=$(gs Innodb_buffer_pool_reads); Q1=$(gs Innodb_buffer_pool_read_requests)
info "Sampling 30 seconds..."; sleep 30
R2=$(gs Innodb_buffer_pool_reads); Q2=$(gs Innodb_buffer_pool_read_requests)
LIFE_RPS=$(awk -v r=$R2 -v u=$UPTIME 'BEGIN{printf "%.0f", r/u}')
NOW_RPS=$(awk -v a=$R1 -v b=$R2 'BEGIN{printf "%.1f", (b-a)/30}')
HIT=$(awk -v a=$R1 -v b=$R2 -v c=$Q1 -v d=$Q2 'BEGIN{ if(d-c>0) printf "%.3f", 100*(1-(b-a)/(d-c)); else print "n/a"}')
ERRLOG=$(gv log_error); case "$ERRLOG" in /*) ;; *) ERRLOG="$DATADIR/${ERRLOG#./}";; esac
START_LINE=$(grep -n 'ready for connections' "$ERRLOG" 2>/dev/null | tail -1 | cut -d: -f1)
NOFREE=$(tail -n +"${START_LINE:-1}" "$ERRLOG" 2>/dev/null | grep -c 'Could not free any blocks'); NOFREE=${NOFREE:-0}
info "InnoDB data on disk $(gib $INNODB_DATA) GiB; pool $(gib $POOL) GiB, $((100-POOLFREE_PCT))% filled"
info "Disk reads: $LIFE_RPS/s average since start, $NOW_RPS/s now; hit ratio now $HIT%; 'could not free' warnings since start: $NOFREE"

RESERVE=$(( RAM/5 > 17179869184 ? RAM/5 : 17179869184 ))       # keep max(20% RAM, 16 GiB) free
HEADROOM=$(( AVAIL - RESERVE )); [ $HEADROOM -lt 0 ] && HEADROOM=0
CAND=$(( POOL + HEADROOM/2 )); CAP=$(( RAM/4 ))                 # spend half the headroom, cap at 25% of RAM
[ $CAND -gt $CAP ] && CAND=$CAP
[ $INNODB_DATA -gt 0 ] && [ $CAND -gt $INNODB_DATA ] && CAND=$INNODB_DATA
REC_GB=$(( CAND/1073741824 )); [ $REC_GB -lt 1 ] && REC_GB=1
POOL_GB=$(( POOL/1073741824 ))
POOL_ACTION=none
if [ $WARM = 0 ] && [ $JEMALLOC = 1 ]; then warn "Pool still warming up; disk reads are expected to be high. Re-run after 24 h before resizing."
elif [ $NOFREE -gt 0 ] || awk -v l=$LIFE_RPS 'BEGIN{exit !(l>50)}'; then
  if [ $REC_GB -gt $POOL_GB ]; then bad "Pool too small ($LIFE_RPS disk reads/s average). Suggested: ${REC_GB}G (now ${POOL_GB}G)."; POOL_ACTION=grow
  else warn "Pool looks too small but there's no memory headroom (available $(gib $AVAIL) GiB, reserve $(gib $RESERVE) GiB)."; fi
else ok "Pool is serving reads well; no increase needed."; fi
if [ $POOL_ACTION = grow ] && [ $JEMALLOC = 0 ] && [ $CREEP != low ]; then
  warn "Grow the pool only after jemalloc is on and memory is stable for a few days (OOM risk on glibc)."
  [ $CREEP = strong ] && info "(Suggestion uses today's free memory; re-run '--only pool' after jemalloc, when more should be free.)"
fi

hdr "Other settings"
LOGSZ=$(gv innodb_log_file_size); FLUSH=$(gv innodb_flush_log_at_trx_commit); TDC=$(gv table_definition_cache)
info "innodb_log_file_size $(gib $LOGSZ) GiB   innodb_flush_log_at_trx_commit $FLUSH   table_definition_cache $TDC"
KU=$(gs Key_blocks_used); KBS=$(gv key_cache_block_size)
[ -n "$KU" ] && info "Key buffer actually used: $(gib $((KU*KBS))) GiB of $(gib $KEYBUF) GiB"
TMPD=$(gs Created_tmp_disk_tables); TMPT=$(gs Created_tmp_tables)
[ "${TMPT:-0}" -gt 0 ] && info "Temp tables on disk: $(awk -v d=$TMPD -v t=$TMPT 'BEGIN{printf "%.0f", 100*d/t}')%"

# ---------------------------------------------------------------- plan
BK=$(pgrep -af 'jetbackup5d-backup|mysqldump|mariadb-dump|acronis|bacula|r1soft|cpbackup|pkgacct' | grep -v mysql-memcheck | awk '{print $2, $3, $4}' | head -3)
hdr "Plan"
[ $JEMALLOC = 0 ] && [ $CREEP != low ] && [ $CREEP != none ] && info "jemalloc:  RECOMMENDED ($CREEP creep). Needs a database restart.${BK:+ Note: a backup is running ($(echo "$BK" | head -1)); the restart will interrupt it.}" 
[ $JEMALLOC = 0 ] && { [ $CREEP = low ] || [ $CREEP = none ]; } && info "jemalloc:  optional (creep: $CREEP)."
[ $POOL_ACTION = grow ] && info "pool:      grow to ~${REC_GB}G$( [ $JEMALLOC = 0 ] && [ $CREEP != low ] && echo ' (after jemalloc has run stable for a few days)')"
[ "$LOGSZ" -lt 4294967296 ] && [ $IS_MARIADB = 1 ] && info "settings:  redo log $(gib $LOGSZ) -> 4 GiB (fewer flush storms)"
[ "$FLUSH" = 1 ] && info "settings:  flush_log_at_trx_commit 1 -> 2 (fewer disk syncs; up to 1 s of commits at risk on an OS crash)"
[ -n "$TDC_SUGGEST" ] && [ "$TDC_SUGGEST" != "$TDC" ] && info "settings:  table_definition_cache $TDC -> $TDC_SUGGEST (fleet standard)"
[ ! -f /etc/cron.d/mariadb-memlog ] && [ $IS_MARIADB = 1 ] && info "logger:    install the 15-minute memory logger (baseline before/after changes)"

[ $JEMALLOC = 1 ] && [ $POOL_ACTION != grow ] && [ "$LOGSZ" -ge 4294967296 -o $IS_MARIADB = 0 ] && [ "$FLUSH" != 1 ] && [ -f /etc/cron.d/mariadb-memlog -o $IS_MARIADB = 0 ] && \
  { [ -z "$TDC_SUGGEST" ] || [ "$TDC_SUGGEST" = "$TDC" ]; } && ok "Nothing to change."
if [ $REPORT_ONLY = 1 ]; then say ""; say "Report only - nothing changed. Log: $LOG"; exit 0; fi

# ---------------------------------------------------------------- helpers for changes
CNF=""
for f in /etc/my.cnf /etc/my.cnf.d/server.cnf /etc/mysql/my.cnf /etc/mysql/mariadb.conf.d/50-server.cnf; do
  [ -f "$f" ] && grep -qE '^\s*\[(mysqld|mariadb|server)\]' "$f" && { CNF=$f; break; }
done
persist() { # persist key value -> edit the [mysqld] config file (backed up once per run)
  local k=$1 v=$2 kp=${1//_/[-_]}
  [ -n "$CNF" ] || { warn "No config file with a [mysqld] section found; add '$k = $v' manually."; next_ "Add '$k = $v' to the [mysqld] section of my.cnf"; return; }
  [ -f "$CNF.bak-memcheck-$$" ] || cp -p "$CNF" "$CNF.bak-memcheck-$$"
  if grep -qE "^\s*$kp\s*=" "$CNF"; then sed -i -E "s|^(\s*$kp\s*=\s*).*|\1$v|" "$CNF"
  else sed -i -E "0,/^\s*\[(mysqld|mariadb|server)\]/s||&\n$k = $v|" "$CNF"; fi
  ok "Persisted $k = $v in $CNF (backup: $CNF.bak-memcheck-$$)"
  local dup; dup=$(grep -rlsE "^\s*$kp\s*=" /etc/my.cnf /etc/my.cnf.d/ /etc/mysql/ 2>/dev/null | grep -vxF "$CNF" | grep -v 'bak-memcheck')
  [ -n "$dup" ] && warn "$k is also set in: $dup (a later file can override this one at restart)."
}

# ---------------------------------------------------------------- logger first, so a baseline exists before any restart
install_logger() {
  cat > /root/mariadb-memlog.sh <<EOF
#!/bin/bash
# Logs MariaDB tracked memory (Memory_used) vs actual RSS, in MiB, to spot allocator growth.
M="$MY -N -e"
P=\$(pgrep -xo mariadbd || pgrep -xo mysqld) || exit 0
read used up otd ot thr <<<\$(\$M "SELECT MAX(IF(variable_name='MEMORY_USED',variable_value,NULL)), MAX(IF(variable_name='UPTIME',variable_value,NULL)), MAX(IF(variable_name='OPEN_TABLE_DEFINITIONS',variable_value,NULL)), MAX(IF(variable_name='OPEN_TABLES',variable_value,NULL)), MAX(IF(variable_name='THREADS_CONNECTED',variable_value,NULL)) FROM information_schema.global_status WHERE variable_name IN ('MEMORY_USED','UPTIME','OPE          E          EN_TABLE_DEFINITIONS','OPEN_TABLES','THREADS_CONNECTED')" | tr '\t' ' ')
[ -n "\$used" ] || exit 0
rss=\$(awk '/VmRSS/{print \$2*1024}' /proc/\$P/status)
echo "\$(date '+%F %T'),\$up,\$((used/1048576)),\$((rss/1048576)),\$(((rss-used)/1048576)),\$otd,\$ot,\$thr" >> /root/mariadb-memlog.csv
EOF
  [ "$PANEL" = Plesk ] && sed -i '2a export MYSQL_PWD="$(cat /etc/psa/.psa.shadow)"' /root/mariadb-memlog.sh
  chmod 700 /root/mariadb-memlog.sh
  [ -f /root/mariadb-memlog.csv ] || echo "time,uptime_s,tracked_mib,rss_mib,gap_mib,table_defs,open_tables,connections" > /root/mariadb-memlog.csv
  echo '*/15 * * * * root /root/mariadb-memlog.sh' > /etc/cron.d/mariadb-memlog
  /root/mariadb-memlog.sh; ok "Logger installed; first row: $(tail -1 /root/mariadb-memlog.csv)"
}
if want logger; then
  hdr "Memory logger (every 15 min to /root/mariadb-memlog.csv)"
  if [ -f /etc/cron.d/mariadb-memlog ]; then ok "Already installed."
  elif [ $IS_MARIADB = 0 ]; then info "Needs MariaDB's Memory_used counter; skipping on MySQL."
  elif ask "Install the memory logger?"; then install_logger; done_ "Memory logger installed"
  else skip_ "Memory logger (declined)"; fi
fi

# ---------------------------------------------------------------- jemalloc
if want jemalloc; then
  hdr "jemalloc (needs a database restart)"
  if [ $JEMALLOC = 1 ]; then ok "Already enabled."
  elif [ -z "$UNIT" ]; then bad "No systemd unit found."; skip_ "jemalloc (no systemd unit)"
  else
    PRE=1
    CUR_ENV=$(systemctl show -p Environment --value "$UNIT")
    echo "$CUR_ENV" | grep -q LD_PRELOAD && { bad "Unit already sets LD_PRELOAD ($CUR_ENV); not overriding."; PRE=0; skip_ "jemalloc (existing LD_PRELOAD)"; }
    STARTED=$(date -d "$(ps -o lstart= -p $PROC)" +%s)
    for f in /etc/my.cnf /etc/my.cnf.d/*.cnf /etc/mysql/my.cnf /etc/mysql/mariadb.conf.d/*.cnf; do
      [ -f "$f" ] && [ "$(stat -c %Y "$f")" -gt "$STARTED" ] && warn "$f changed since the database started; the restart will apply those edits too."
    done
    q "SHOW SLAVE STATUS" | grep -q . && warn "This server is a replica; a restart affects replication."
    BKACCTS=$(pgrep -af 'jetbackup5d-backup Account' | awk '{print $NF}' | sort -u | tr '\n' ' ')
    if [ -n "$BK" ]; then
      warn "Backup/dump running: $(echo "$BK" | tr '\n' ';')"
      warn "ADVISORY: restarting now will interrupt the database dump in progress${BKACCTS:+ for: $BKACCTS}."
      info "Those accounts' backups will likely fail for this run; other accounts carry on after the restart."
      [ $CREEP != strong ] && info "Creep is not severe here, so waiting for the backup to finish is the safer choice."
    fi
    if [ $PRE = 1 ]; then
      info "Recommendation: $CREEP creep. The restart interrupts database access briefly; the pool starts cold."
      if ask "Install jemalloc and restart $UNIT now${BK:+ (backup running - see advisory above)}?"; then
        [ -n "$BK" ] && next_ "Re-run the backup for accounts interrupted by the restart: ${BKACCTS:-see the JetBackup job log}"
        rpm -q jemalloc >/dev/null 2>&1 || dnf install -y jemalloc >> "$LOG" 2>&1 || yum install -y jemalloc >> "$LOG" 2>&1
        LIB=$(rpm -ql jemalloc 2>/dev/null | grep -m1 'libjemalloc\.so\.2$')
        if [ -z "$LIB" ]; then bad "jemalloc library not available (is EPEL enabled?). Nothing changed."; skip_ "jemalloc (package unavailable)"
        else
          D=/etc/systemd/system/$UNIT.d; mkdir -p "$D"
          printf '[Service]\nEnvironment="LD_PRELOAD=%s"\n' "$LIB" > "$D/jemalloc.conf"
          systemctl daemon-reload; say "  Restarting $UNIT ..."; T0=$(date +%s); systemctl restart "$UNIT"
          for i in $(seq 1 90); do $MY -e "SELECT 1" >/dev/null 2>&1 && break; sleep 2; done
          if $MY -e "SELECT 1" >/dev/null 2>&1; then
            NEWPID=$(pgrep -xo mariadbd || pgrep -xo mysqld)
            if grep -q jemalloc /proc/$NEWPID/maps; then
              ok "jemalloc active after a $(( $(date +%s) - T0 ))s restart ($( [ $IS_MARIADB = 1 ] && gv version_malloc_library || echo mapped ))."
              JEMALLOC=1; done_ "jemalloc enabled ($D/jemalloc.conf)"
              next_ "Check memory in 3-7 days: daily peak gap should level off (see /root/mariadb-memlog.csv)"
              [ $POOL_ACTION = grow ] && next_ "Then grow the pool:  bash $0 --only pool   (suggested ~${REC_GB}G)"
            else bad "Database is up but jemalloc is not loaded. Check $D/jemalloc.conf."; skip_ "jemalloc (not loaded after restart)"; fi
          else
            bad "Database did not come back. Rolling back: removing $D/jemalloc.conf and restarting."
            rm -f "$D/jemalloc.conf"; systemctl daemon-reload; systemctl restart "$UNIT"; sleep 5
            if $MY -e "SELECT 1" >/dev/null 2>&1; then ok "Rolled back; database is up."; skip_ "jemalloc (rolled back after failed start)"
            else bad "Database still down: check 'journalctl -u $UNIT' NOW."; next_ "URGENT: database down - journalctl -u $UNIT"; fi
          fi
        fi
      else skip_ "jemalloc (declined)"; fi
    fi
  fi
fi

# ---------------------------------------------------------------- buffer pool
if want pool; then
  hdr "innodb_buffer_pool_size (online, no restart)"
  if [ $POOL_ACTION != grow ]; then info "No increase recommended."
  elif [ $JEMALLOC = 0 ] && [ $CREEP != low ]; then warn "Not now: enable jemalloc and confirm stable memory first."; skip_ "Pool resize (waiting for jemalloc)"
  else
    read -r -p "  Size in GB [suggested ${REC_GB}, current ${POOL_GB}, Enter = skip]: " NEWGB; echo "  size entered: ${NEWGB:-skip}" >> "$LOG"
    if [[ "$NEWGB" =~ ^[0-9]+$ ]] && [ "$NEWGB" -gt "$POOL_GB" ] && ask "Set innodb_buffer_pool_size to ${NEWGB}G now and persist it?"; then
      q "SET GLOBAL innodb_buffer_pool_size = $((NEWGB*1073741824))"
      for i in $(seq 1 30); do [ "$(gv innodb_buffer_pool_size)" = "$((NEWGB*1073741824))" ] && break; sleep 2; done
      if [ "$(gv innodb_buffer_pool_size)" = "$((NEWGB*1073741824))" ]; then ok "Buffer pool now ${NEWGB}G"; persist innodb_buffer_pool_size "${NEWGB}G"; done_ "Buffer pool ${POOL_GB}G -> ${NEWGB}G"
        next_ "In 24 h: disk reads should fall well below 50/s (bash $0 --report)"
      else bad "Resize not confirmed yet: check SHOW STATUS LIKE 'Innodb_buffer_pool_resize_status'."; skip_ "Pool resize (not confirmed)"; fi
    else skip_ "Pool resize (declined)"; fi
  fi
fi

# ---------------------------------------------------------------- other settings
if want settings; then
  hdr "Other settings (online)"
  FREE_DISK=$(df -B1 --output=avail "$DATADIR" | tail -1)
  if [ $IS_MARIADB = 0 ]; then info "Redo log: MySQL uses innodb_redo_log_capacity; skipping."
  elif [ "$LOGSZ" -ge 4294967296 ]; then ok "innodb_log_file_size already $(gib $LOGSZ) GiB"
  elif [ "$FREE_DISK" -lt 10737418240 ]; then warn "Less than 10 GiB free on the data disk; not growing the redo log."; skip_ "Redo log (low disk)"
  elif ask "Redo log $(gib $LOGSZ) -> 4 GiB (uses ~4 GiB disk; fewer flush storms)?"; then
    q "SET GLOBAL innodb_log_file_size = 4294967296"
    for i in $(seq 1 60); do [ "$(gv innodb_log_file_size)" = 4294967296 ] && break; sleep 2; done
    if [ "$(gv innodb_log_file_size)" = 4294967296 ]; then ok "Redo log now 4G (online)"
    else warn "Online resize not confirmed (older MariaDB?); it will apply at the next restart."; fi
    persist innodb_log_file_size 4G; done_ "Redo log -> 4G"
  else skip_ "Redo log (declined)"; fi
  if [ "$FLUSH" = 1 ]; then
    if ask "flush_log_at_trx_commit 1 -> 2 (fewer disk syncs; up to 1 s of commits lost on an OS crash)?"; then
      q "SET GLOBAL innodb_flush_log_at_trx_commit = 2"; ok "Set to $(gv innodb_flush_log_at_trx_commit)"; persist innodb_flush_log_at_trx_commit 2; done_ "flush_log_at_trx_commit -> 2"
    else skip_ "flush_log_at_trx_commit (declined)"; fi
  else ok "innodb_flush_log_at_trx_commit already $FLUSH"; fi
  read -r -p "  table_definition_cache is $TDC. New value${TDC_SUGGEST:+ [suggested $TDC_SUGGEST]}, Enter = keep: " NEWTDC; echo "  tdc entered: ${NEWTDC:-keep}" >> "$LOG"
  if [[ "$NEWTDC" =~ ^[0-9]+$ ]] && [ "$NEWTDC" != "$TDC" ] && ask "Set table_definition_cache = $NEWTDC?"; then
    q "SET GLOBAL table_definition_cache = $NEWTDC"; ok "Set to $(gv table_definition_cache)"; persist table_definition_cache "$NEWTDC"; done_ "table_definition_cache $TDC -> $NEWTDC"
  fi
fi

# ---------------------------------------------------------------- summary
hdr "Summary"
[ ${#DONE[@]} -gt 0 ]    && { say "  Changed:";  for x in "${DONE[@]}";    do say "    - $x"; done; } || say "  Changed: nothing"
[ ${#SKIPPED[@]} -gt 0 ] && { say "  Skipped:";  for x in "${SKIPPED[@]}"; do say "    - $x"; done; }
[ ${#NEXT[@]} -gt 0 ]    && { say "  Next:";     for x in "${NEXT[@]}";    do say "    - $x"; done; }
say ""; say "Full log: $LOG"
