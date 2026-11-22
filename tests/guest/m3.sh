#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Guest side of the M3 VM tests (docs/verification-plan.md 4.4 to 4.7:
# VT-30 to VT-38, VT-40, VT-50 after installing 3X-UI, VT-51, VT-55 and the
# 3X-UI part of VT-71). tests/vm.py runs the first phase of VT-36 before apply,
# hardens and confirms the guest, then runs one phase of this script per SSH
# session; VT-51 runs on overlays of the disk after VT-55, one drift each.

# shellcheck source=m2.sh
. "${BASH_SOURCE[0]%/*}/m2.sh"

readonly JOURNALMATCH='_SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session + SYSLOG_IDENTIFIER=sshd _UID=0 + SYSLOG_IDENTIFIER=sshd-session _UID=0'
# The value v0.1.0 to v0.2.0 wrote (VT-38, requirements D84).
readonly OLD_JOURNALMATCH='_SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session'
readonly F2B_JAIL=/etc/fail2ban/jail.d/99-vps-hardening.local
readonly F2B_DB=/var/lib/fail2ban/fail2ban.sqlite3
# Wait for a package run the APT timers started; unlike settle, the timers
# stay running, as verify requires after apply.
apt_idle() {
  local deadline=$((SECONDS + 1200))
  while apt_busy; do
    [ "$SECONDS" -lt "$deadline" ] || fail 'package manager still busy after 20 minutes'
    sleep 5
  done
}

# Second-source addresses of the M3 cases, one per case so that neither a
# Fail2ban ban nor Debian 13's sshd penalties carry over between cases.
readonly REGEX_SRC=192.0.2.6 BAN_SRC=192.0.2.7 INC_SRC=192.0.2.8 AGENT_SRC=192.0.2.9 PREAUTH_SRC=192.0.2.10
readonly BACKLOG_SRC=192.0.2.11
# VT-37: one attempt each; VT-38: the control under the old journalmatch.
readonly VT37_SOURCES='192.0.2.13 192.0.2.14 192.0.2.15 192.0.2.16' VT38_SOURCES='192.0.2.17 192.0.2.18'
readonly M3_SOURCES="$REGEX_SRC $BAN_SRC $INC_SRC $AGENT_SRC $PREAUTH_SRC $BACKLOG_SRC $VT37_SOURCES $VT38_SOURCES"
# 192.0.2.12 is m2.sh's BAD_SHELL_KEY.
# VT-32: a documentation address that never sends traffic.
readonly MANUAL_BAN=203.0.113.123
# Invalid-user attempts this far apart stay below Debian 13's sshd penalties
# (authfail 5 s, enforced from 15 s accrued), so every attempt reaches sshd.
readonly ATTEMPT_GAP=6

m3_netns_up() {
  local addr
  netns_up
  for addr in $M3_SOURCES; do
    ip -n "$NETNS" addr replace "$addr/24" dev vh-peer
  done
}

f2b_total_failed() {
  fail2ban-client status sshd | sed -n 's/^.*Total failed:[[:space:]]*//p'
}

# Wait until Fail2ban has read the journal: the counter stops changing.
f2b_settled_count() {
  local last now same=0 _
  last="$(f2b_total_failed)"
  for _ in $(seq 30); do
    sleep 1
    now="$(f2b_total_failed)"
    if [ "$now" = "$last" ]; then
      same=$((same + 1))
      [ "$same" -lt 3 ] || break
    else
      same=0
      last="$now"
    fi
  done
  printf '%s\n' "$last"
}

banned() {
  fail2ban-client get sshd banip | tr ' ' '\n' | grep -qxF -- "$1"
}

# Seconds of the current ban of an address: "ADDR <tab>START + SECONDS = END".
ban_seconds() {
  fail2ban-client get sshd banip --with-time |
    awk -v a="$1" '$1 == a { for (i = 1; i < NF; i++) if ($i == "+") { split($(i + 1), s, "."); print s[1] } }'
}

unban_test_addresses() {
  local addr
  for addr in $M3_SOURCES $MANUAL_BAN; do
    fail2ban-client set sshd unbanip "$addr" >/dev/null 2>&1 || true
  done
}

# attempt BIND USER [SSH OPTION...]: one login as a user that does not exist
# (or as root with the given options), no retries. Prints denied, ok, refused
# or error.
attempt() {
  local bind="$1" user="$2" out rc=0
  shift 2
  out="$(ip netns exec "$NETNS" ssh -p "$GUEST_SSH_PORT" -b "$bind" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 -o LogLevel=ERROR -o BatchMode=yes "$@" "$user@$DST4" true </dev/null 2>&1)" || rc=$?
  if [ "$rc" -eq 0 ]; then
    printf 'ok\n'
  else
    case "$out" in
      *'Permission denied'*) printf 'denied\n' ;;
      *'Connection refused'* | *'timed out'* | *'No route'*) printf 'refused\n' ;;
      *) printf 'error\n' ;;
    esac
  fi
}

# invalid_attempt BIND N: attempt N as a user that does not exist, with a key
# as a scanner's client would offer one. It ends denied, or cut off by the
# ban it caused; other connection failures (sshd penalties) are retried.
# Each try is logged.
invalid_attempt() {
  local bind="$1" n="$2" got _
  for _ in 1 2 3; do
    got="$(attempt "$bind" "vh-nouser-$n" -i "$PRIVATE/ed25519" -o IdentitiesOnly=yes -o PreferredAuthentications=publickey)"
    printf '%s invalid-user-%s %s %s\n' "$(date +%s)" "$n" "$bind" "$got" >>"$phase_dir/attempts.txt"
    [ "$got" != denied ] || return 0
    sleep 2
    ! banned "$bind" || return 0
    sleep "$ATTEMPT_GAP"
  done
  fail "attempt $n from $bind: $got, expected denied"
}

# ban_by_failures BIND LABEL: invalid-user attempts until the address is
# banned. Records attempts and the counter after each in LABEL.txt.
ban_by_failures() {
  local bind="$1" label="$2" n=0 count
  while ! banned "$bind"; do
    [ "$n" -lt 8 ] || fail "$bind not banned after $n attempts"
    n=$((n + 1))
    invalid_attempt "$bind" "$n"
    count="$(f2b_settled_count)"
    printf 'attempt %s total-failed %s banned %s\n' "$n" "$count" "$(banned "$bind" && echo yes || echo no)" >>"$phase_dir/$label.txt"
    banned "$bind" || sleep "$ATTEMPT_GAP"
  done
  printf '%s\n' "$n" >"$phase_dir/$label.attempts"
  log "$bind banned after $n attempts"
}

# journal_entries ADDR: journal entries mentioning ADDR since the phase began,
# as "_COMM SYSLOG_IDENTIFIER _SYSTEMD_UNIT _UID | MESSAGE" (VT-35).
journal_entries() {
  journalctl --since "@$phase_start" --no-pager -o json | python3 -c '
import json, sys
addr = sys.argv[1]
for line in sys.stdin:
    e = json.loads(line)
    msg = e.get("MESSAGE")
    if isinstance(msg, str) and (" " + addr + " ") in (" " + msg.replace(",", " ") + " "):
        print(e.get("_COMM"), e.get("SYSLOG_IDENTIFIER"), e.get("_SYSTEMD_UNIT"), e.get("_UID"), "|", msg)
' "$1"
}

# VT-35: every log line about the address is inside FR-08's journalmatch: the
# unit, the command, or the identifier sent by a root process (D84).
check_journal_scope() {
  local addr="$1" outside
  journal_entries "$addr" >"$phase_dir/journal-$addr.txt"
  awk '{ print $1, $2, $3, $4 }' "$phase_dir/journal-$addr.txt" | sort | uniq -c >"$phase_dir/journal-$addr.fields"
  cat "$phase_dir/journal-$addr.fields"
  [ -s "$phase_dir/journal-$addr.txt" ] || fail "no journal entries mention $addr"
  outside="$(awk '!($3 == "ssh.service" || $1 == "sshd" || $1 == "sshd-session" ||
    (($2 == "sshd" || $2 == "sshd-session") && $4 == "0"))' "$phase_dir/journal-$addr.txt")"
  [ -z "$outside" ] || fail "log lines about $addr outside the journalmatch: $outside"
  log "every log line about $addr is inside the journalmatch"
}

# VT-30: configuration and service, and the values the server reports, read
# here independently of verify's own parser.
phase_m3_fail2ban() {
  local args want name
  wait_fail2ban
  record_state "$phase_dir/state"
  capture vt30-test fail2ban-client -t
  expect_rc vt30-test 0
  [ "$(systemctl is-enabled fail2ban.service)" = enabled ] || fail 'fail2ban.service is not enabled'
  [ "$(systemctl is-active fail2ban.service)" = active ] || fail 'fail2ban.service is not active'
  capture vt30-ping fail2ban-client ping
  expect_text vt30-ping pong
  capture vt30-status fail2ban-client status sshd
  [ "$(sed -n 's/^.*Journal matches:[[:space:]]*//p' "$phase_dir/vt30-status.out")" = "$JOURNALMATCH" ] ||
    fail 'Journal matches is not the journalmatch of FR-08'
  capture vt30-jails fail2ban-client status
  expect_match vt30-jails 'Jail list:[[:space:]]+sshd$'
  while IFS='|' read -r args want; do
    name="vt30-get-${args// /-}"
    # shellcheck disable=SC2086 # ARGS is several words.
    capture "$name" fail2ban-client get $args
    expect_rc "$name" 0
    [ "$args" != "sshd action nftables port" ] || want="$GUEST_SSH_PORT"
    [ "$(cat "$phase_dir/$name.out")" = "$(printf '%b' "$want")" ] || fail "$args: unexpected value"
  done <<'EOF'
sshd bantime|86400
sshd findtime|600
sshd maxretry|5
sshd bantime.increment|True
sshd bantime.maxtime|2419200
sshd bantime.rndtime|600
sshd ignoreself|True
sshd ignoreip|These IP addresses/networks are ignored:\n|- 127.0.0.0/8\n`- ::1
sshd usedns|no
sshd journalmatch|Current match filter:\n_SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session + SYSLOG_IDENTIFIER=sshd _UID=0 + SYSLOG_IDENTIFIER=sshd-session _UID=0
sshd actions|The jail sshd has the following actions:\nnftables
sshd action nftables port|22
sshd action nftables protocol|tcp
dbpurgeage|Current database purge age is:\n`- 2592000seconds
EOF
  f2b_mainconf_as_package
  same_as_baseline sysctl.txt qdisc.txt
  ufw_sysctl_unchanged
  verify_passes vt30-verify
  for name in f2b.config f2b.jails f2b.values f2b.files f2b.mainconf uu.dropin; do
    expect_report vt30-verify PASS "$name"
  done
}

# VT-31: the filter in normal mode finds every failure in samples made from
# a second source, as many as the jail counted for them. A second sample is
# made only if it cannot reach maxretry, so the source is never banned here.
phase_m3_regex() {
  local before after counted matched attempts=1
  m3_netns_up
  wait_fail2ban
  phase_start="$(date +%s)"
  before="$(f2b_settled_count)"
  invalid_attempt "$REGEX_SRC" 1
  after="$(f2b_settled_count)"
  if [ $((2 * (after - before))) -lt 5 ]; then
    sleep "$ATTEMPT_GAP"
    invalid_attempt "$REGEX_SRC" 2
    after="$(f2b_settled_count)"
    attempts=2
  fi
  counted=$((after - before))
  journal_entries "$REGEX_SRC" >"$phase_dir/samples.txt"
  cat "$phase_dir/samples.txt"
  [ "$(grep -c 'Invalid user vh-nouser-' "$phase_dir/samples.txt")" -eq "$attempts" ] ||
    fail "the journal lacks the $attempts samples"
  fail2ban-regex -o ip --journalmatch "$JOURNALMATCH" systemd-journal 'sshd[mode=normal]' \
    >"$phase_dir/regex-ip.txt" 2>"$phase_dir/regex.err" || fail "fail2ban-regex: $(cat "$phase_dir/regex.err")"
  matched="$(grep -cxF "$REGEX_SRC" "$phase_dir/regex-ip.txt" || true)"
  printf 'attempts %s\ncounted %s\nmatched %s\n' "$attempts" "$counted" "$matched" | tee "$phase_dir/result.txt"
  [ "$matched" -ge "$attempts" ] || fail "fail2ban-regex matched $matched failures for $attempts samples"
  [ "$matched" -eq "$counted" ] || fail "fail2ban-regex matched $matched failures, the jail counted $counted"
  ! banned "$REGEX_SRC" || fail "$REGEX_SRC was banned"
}

# VT-36, before apply: maxretry failures from a second source while fail2ban
# is not installed yet, for apply's first start of the jail to find in the
# journal.
phase_m3_backlog_before() {
  local n
  [ "$(dpkg-query -W -f='${db:Status-Status}' fail2ban 2>/dev/null)" != installed ] ||
    fail 'fail2ban is installed before apply; the case needs apply to install it'
  m3_netns_up
  for n in 1 2 3 4 5; do
    invalid_attempt "$BACKLOG_SRC" "$n"
    [ "$n" -eq 5 ] || sleep "$ATTEMPT_GAP"
  done
  log "5 failures from $BACKLOG_SRC before apply"
}

# VT-36, after apply and confirm: the backlog source is banned with FR-08's
# bantime, not the package's own 600 s from the jail it ran during the
# install (design 8.8).
phase_m3_backlog() {
  local seconds
  wait_fail2ban
  trap unban_test_addresses EXIT
  banned "$BACKLOG_SRC" || fail "$BACKLOG_SRC from the backlog is not banned"
  seconds="$(ban_seconds "$BACKLOG_SRC")"
  printf 'backlog ban %s s\n' "$seconds" | tee "$phase_dir/ban-time.txt"
  [ "$seconds" -ge 86400 ] && [ "$seconds" -le 87000 ] || fail "backlog ban of $seconds s, expected bantime 86400 s"
}

# VT-33 and VT-35: a source with more than maxretry failures is banned for
# bantime; a repeated ban is longer (bantime.increment). The second part runs
# with a short runtime bantime so that the first ban expires during the test,
# then reloads the jail from its configuration.
phase_m3_ban() {
  local seconds first second
  m3_netns_up
  wait_fail2ban
  trap unban_test_addresses EXIT
  phase_start="$(date +%s)"

  ban_by_failures "$BAN_SRC" first-ban
  # Written before the check: run 44879164019 (debian12) counted 5 of 6
  # failures and left no journal to show which record Fail2ban did not match.
  journal_entries "$BAN_SRC" >"$phase_dir/journal-first-ban.txt"
  [ "$(cat "$phase_dir/first-ban.attempts")" -le 5 ] ||
    fail "banned only after more than maxretry attempts; see $phase_dir/journal-first-ban.txt"
  seconds="$(ban_seconds "$BAN_SRC")"
  printf 'first ban %s s\n' "$seconds" | tee "$phase_dir/ban-time.txt"
  [ "$seconds" -ge 86400 ] && [ "$seconds" -le 87000 ] || fail "ban of $seconds s, expected bantime 86400 s"
  nft list table inet f2b-table >"$phase_dir/f2b-table.txt"
  grep -qF "$BAN_SRC" "$phase_dir/f2b-table.txt" || fail "$BAN_SRC is not in inet f2b-table"
  [ "$(attempt "$BAN_SRC" root -i "$PRIVATE/rsa" -o IdentitiesOnly=yes)" = refused ] || fail "$BAN_SRC still reaches sshd"
  expect_login after-ban-ok4 ok "$OK4" "root@$DST4" key rsa
  check_journal_scope "$BAN_SRC"
  fail2ban-client set sshd unbanip "$BAN_SRC" >/dev/null
  ! banned "$BAN_SRC" || fail "$BAN_SRC remains in the jail after unban"
  expect_login same-source-after-unban ok "$BAN_SRC" "root@$DST4" key rsa

  fail2ban-client set sshd bantime 20 >/dev/null
  ban_by_failures "$INC_SRC" increment-1
  first="$(ban_seconds "$INC_SRC")"
  for _ in $(seq 60); do
    banned "$INC_SRC" || break
    sleep 1
  done
  ! banned "$INC_SRC" || fail "$INC_SRC still banned after the 20 s ban"
  sleep "$ATTEMPT_GAP"
  ban_by_failures "$INC_SRC" increment-2
  second="$(ban_seconds "$INC_SRC")"
  printf 'runtime bantime 20 s: first ban %s s, second ban %s s\n' "$first" "$second" | tee -a "$phase_dir/ban-time.txt"
  fail2ban-client reload sshd >/dev/null
  wait_fail2ban
  [ "$(fail2ban-client get sshd bantime)" = 86400 ] || fail 'bantime not back to 86400 after the reload'
  [ "$first" -eq 20 ] || fail "first ban of $first s with a runtime bantime of 20 s"
  # bantime.formula doubles per earlier ban; bantime.rndtime adds up to 600 s.
  [ "$second" -ge 40 ] && [ "$second" -le 640 ] || fail "second ban of $second s, expected 40 to 640 s"
  log 'bans as bantime, bantime.increment and bantime.rndtime require'
}

# VT-32: a manual ban appears in the nftables set and goes away on unban; an
# interrupted run still unbans. Logins keep working throughout.
phase_m3_manual_ban() {
  local pid _
  m3_netns_up
  wait_fail2ban
  fail2ban-client set sshd banip "$MANUAL_BAN" >/dev/null
  nft list table inet f2b-table >"$phase_dir/banned.txt"
  grep -qF "$MANUAL_BAN" "$phase_dir/banned.txt" || fail "$MANUAL_BAN is not in inet f2b-table after banip"
  expect_login banned-ok4 ok "$OK4" "root@$DST4" key rsa
  fail2ban-client set sshd unbanip "$MANUAL_BAN" >/dev/null
  nft list table inet f2b-table >"$phase_dir/unbanned.txt"
  ! grep -qF "$MANUAL_BAN" "$phase_dir/unbanned.txt" || fail "$MANUAL_BAN is still in inet f2b-table after unbanip"
  expect_login unbanned-ok4 ok "$OK4" "root@$DST4" key rsa
  log 'manual ban and unban'

  # The same steps, interrupted while the address is banned.
  rm -f "$PRIVATE/manual-banned"
  (
    sleeper=''
    trap 'fail2ban-client set sshd unbanip "$MANUAL_BAN" >/dev/null 2>&1' EXIT
    trap '[ -z "$sleeper" ] || kill "$sleeper" 2>/dev/null; exit 130' INT TERM HUP
    fail2ban-client set sshd banip "$MANUAL_BAN" >/dev/null
    touch "$PRIVATE/manual-banned"
    sleep 300 &
    sleeper=$!
    wait "$sleeper"
  ) &
  pid=$!
  for _ in $(seq 30); do
    [ -e "$PRIVATE/manual-banned" ] && break
    sleep 1
  done
  banned "$MANUAL_BAN" || fail 'the interrupted run did not ban'
  kill -TERM "$pid"
  wait "$pid" 2>/dev/null || true
  ! banned "$MANUAL_BAN" || fail 'the interrupted run left the address banned'
  expect_login interrupted-ok4 ok "$OK4" "root@$DST4" key rsa
  log 'an interrupted run unbanned the address'
}

# VT-34: root logins through an agent holding wrong keys before the right
# one, the IdentitiesOnly control, and connections closed before
# authentication (requirements U11) are not counted as failures.
phase_m3_agent() {
  local before after i result=() agent_sock
  m3_netns_up
  wait_fail2ban
  phase_start="$(date +%s)"
  for i in 1 2 3; do
    rm -f "$PRIVATE/wrong$i" "$PRIVATE/wrong$i.pub"
    ssh-keygen -q -t ed25519 -N '' -C "vh-wrong-$i" -f "$PRIVATE/wrong$i"
  done
  eval "$(ssh-agent -s)" >/dev/null
  agent_sock="$SSH_AUTH_SOCK"
  trap 'ssh-agent -k >/dev/null 2>&1' EXIT
  ssh-add -q "$PRIVATE/wrong1" "$PRIVATE/wrong2" "$PRIVATE/wrong3" "$PRIVATE/rsa" 2>/dev/null
  ssh-add -l >"$phase_dir/agent-keys.txt"

  before="$(f2b_settled_count)"
  for i in $(seq 6); do
    [ "$(attempt "$AGENT_SRC" root -o IdentitiesOnly=no -o PreferredAuthentications=publickey \
      -o IdentityAgent="$agent_sock")" = ok ] || fail "agent login $i failed"
    sleep 2
  done
  after="$(f2b_settled_count)"
  result+=("agent $((after - before))")

  before="$after"
  for i in $(seq 6); do
    [ "$(attempt "$AGENT_SRC" root -i "$PRIVATE/rsa" -o IdentitiesOnly=yes -o IdentityAgent=none)" = ok ] ||
      fail "IdentitiesOnly login $i failed"
    sleep 2
  done
  after="$(f2b_settled_count)"
  result+=("identities-only $((after - before))")

  before="$after"
  for i in $(seq 6); do
    ip netns exec "$NETNS" python3 -c '
import socket, sys
s = socket.create_connection((sys.argv[2], int(sys.argv[3])), timeout=5, source_address=(sys.argv[1], 0))
s.recv(64)
s.close()
' "$PREAUTH_SRC" "$DST4" "$GUEST_SSH_PORT" || fail "banner connection $i failed"
    sleep 2
    [ "$(attempt "$PREAUTH_SRC" root -o PreferredAuthentications=keyboard-interactive -o IdentityAgent=none)" = denied ] ||
      fail "connection $i closed before authentication did not end as expected"
    sleep 2
  done
  after="$(f2b_settled_count)"
  result+=("closed-before-auth $((after - before))")

  printf '%s\n' "${result[@]}" | tee "$phase_dir/counted.txt"
  journalctl --since "@$phase_start" --no-pager -o short-iso _SYSTEMD_UNIT=ssh.service |
    grep -iE 'penalt|drop connection' >"$phase_dir/sshd-penalties.txt" || true
  journal_entries "$AGENT_SRC" >"$phase_dir/journal-$AGENT_SRC.txt"
  journal_entries "$PREAUTH_SRC" >"$phase_dir/journal-$PREAUTH_SRC.txt"
  ! banned "$AGENT_SRC" || fail "$AGENT_SRC was banned"
  ! banned "$PREAUTH_SRC" || fail "$PREAUTH_SRC was banned"
  [ "$(awk '{ s += $2 } END { print s }' "$phase_dir/counted.txt")" -eq 0 ] || fail 'some of these logins were counted as failures'
  log 'none of these logins were counted as failures'
}

# VT-40: configuration, timers and the origins a dry run allows (D19).
phase_m3_updates() {
  local codename want got
  codename="$(sed -n 's/^VERSION_CODENAME=//p' /etc/os-release)"
  apt-config dump >"$phase_dir/apt-config.txt"
  grep -qx 'APT::Periodic::Update-Package-Lists "1";' "$phase_dir/apt-config.txt" || fail 'Update-Package-Lists is not 1'
  grep -qx 'APT::Periodic::Unattended-Upgrade "1";' "$phase_dir/apt-config.txt" || fail 'Unattended-Upgrade is not 1'
  grep -qx 'Unattended-Upgrade::Automatic-Reboot "false";' "$phase_dir/apt-config.txt" || fail 'Automatic-Reboot is not false'
  for timer in apt-daily.timer apt-daily-upgrade.timer; do
    [ "$(systemctl is-enabled "$timer")" = enabled ] && [ "$(systemctl is-active "$timer")" = active ] ||
      fail "$timer is not enabled and active"
  done
  apt_idle
  capture vt40-dry-run timeout 900 unattended-upgrade --dry-run --debug
  expect_rc vt40-dry-run 0
  case "$(os_id)" in
    debian) want="origin=Debian,codename=$codename,label=Debian
origin=Debian,codename=$codename,label=Debian-Security
origin=Debian,codename=$codename-security,label=Debian-Security" ;;
    ubuntu) want="o=Ubuntu,a=$codename-security
o=UbuntuESMApps,a=$codename-apps-security
o=UbuntuESM,a=$codename-infra-security" ;;
  esac
  got="$(sed -n 's/^.*Allowed origins are: //p' "$phase_dir/vt40-dry-run.out" | head -n 1 | sed 's/, /\n/g' | sort)"
  printf '%s\n' "$got" >"$phase_dir/allowed-origins.txt"
  [ "$got" = "$(sort <<<"$want")" ] || fail "allowed origins: $got"
  log "allowed origins as D19 requires: $(paste -sd ' ' "$phase_dir/allowed-origins.txt")"
}

# VT-55 (first part), VT-50 and VT-71: 3X-UI installed on the hardened host
# leaves FR-04, FR-06 and FR-08 as they were; verify passes and changes
# nothing, 3X-UI's files included.
phase_m3_xui() {
  local file user
  user="$(default_user)"
  wait_fail2ban
  record_state "$phase_dir/before"
  fail2ban_values >"$phase_dir/before/f2b-values.txt"
  apt_idle
  install_xui_fixture
  wait_fail2ban
  record_state "$phase_dir/after"
  fail2ban_values >"$phase_dir/after/f2b-values.txt"
  for file in "sshd-root.txt" "sshd-$user.txt" ufw.txt files.txt units.txt f2b-values.txt sysctl.txt qdisc.txt; do
    diff -u "$phase_dir/before/$file" "$phase_dir/after/$file" || fail "$file changed when 3X-UI was installed"
  done
  log 'SSH, UFW, Fail2ban and the managed files as before installing 3X-UI'
  xui_verify vt55-verify
}

# VT-55 (second part): after the reboot.
phase_m3_xui_rebooted() {
  cloud-init status --wait >/dev/null 2>&1 || true
  quiet_apt_upgrades
  [ "$(cat /proc/sys/kernel/random/boot_id)" != "$(cat "$EVIDENCE/m3-xui/after/boot_id")" ] ||
    fail 'the boot ID did not change'
  wait_fail2ban
  wait_listen 2053
  xui_verify vt55-reboot-verify
}

fail2ban_values() {
  local key
  for key in bantime findtime maxretry ignoreip journalmatch actions; do
    printf '%s: %s\n' "$key" "$(fail2ban-client get sshd "$key" | paste -sd ' ')"
  done
}

# verify with 3X-UI installed: everything passes, the panel on loopback.
xui_verify() {
  verify_passes "$1"
  expect_report "$1" PASS boundary.panel-listen
  if grep -qE '^\[(FAIL|WARN|SKIP)\]' "$phase_dir/$1.out"; then
    fail "$1: not every check passed"
  fi
}

# xui_menu NAME INPUT: the v3.10.2 menu script, answered with INPUT (printf %b
# escapes). Its menus call themselves again on unexpected input, so the run
# is bounded.
xui_menu() {
  local rc=0
  printf '%b' "$2" | timeout 300 /usr/bin/x-ui >"$phase_dir/$1.out" 2>&1 || rc=$?
  sed 's/^/    /' "$phase_dir/$1.out"
  [ "$rc" -eq 0 ] || fail "x-ui menu $1: exit $rc"
}

# VT-51 DRIFT: one drift on an overlay of the disk after VT-55; verify reports
# exactly the expected failures (or only the warning) and changes nothing.
phase_m3_drift() {
  local drift="${1-}" want_fail='' want_warn='' want_rc=1 got
  cloud-init status --wait >/dev/null 2>&1 || true
  quiet_apt_upgrades
  wait_fail2ban
  wait_listen 2053
  ufw status verbose >"$phase_dir/ufw-before.txt"
  case "$drift" in
    firewall-install)
      # As requirements FR-10 describes it; with UFW active the menu changes nothing.
      xui_menu menu '23\n1\n0\n0\n'
      want_rc=0
      ;;
    firewall-reinstall)
      xui_menu menu '23\n6\n1\n0\n0\n'
      want_fail='ufw.panel ufw.port80 ufw.rules ufw.userrules'
      ;;
    iplimit)
      xui_menu menu '22\n1\ny\n\n0\n'
      wait_fail2ban
      want_fail='f2b.files f2b.jails f2b.mainconf'
      ;;
    listen-all)
      /usr/local/x-ui/x-ui setting -listenIP 0.0.0.0 >/dev/null
      systemctl restart x-ui
      wait_listen 2053
      want_fail='boundary.panel-listen'
      ;;
    bbr)
      xui_menu menu '26\n1\n0\n0\n'
      want_fail='boundary.xui-bbr'
      ;;
    ufw-rule)
      ufw allow 8080/tcp
      want_fail='ufw.rules ufw.userrules'
      ;;
    nftables)
      systemctl enable nftables.service
      want_fail='nft.service'
      ;;
    other-firewall)
      # Requirements D68: another firewall service beside UFW (a transient
      # unit under firewalld's name) and a table of its own.
      systemd-run --quiet --unit firewalld --remain-after-exit /bin/true
      nft add table inet vh-drift
      want_fail='firewall.others'
      want_warn='nft.tables'
      ;;
    sshd-dropin)
      printf '# drift\n' >>/etc/ssh/sshd_config.d/00-vps-hardening.conf
      want_fail='ssh.dropin'
      ;;
    sshd-match)
      # Passwords for one source range; sshd -T for the placeholder connection
      # still says no, so ssh.passwordauthentication alone would pass (FR-04).
      printf 'Match Address 198.51.100.0/24\n    PasswordAuthentication yes\n' >/etc/ssh/sshd_config.d/99-match.conf
      want_fail='ssh.match'
      ;;
    ufw-framework)
      # A rule `ufw status` does not show; the next UFW reload loads it (FR-06).
      sed -i '/^COMMIT$/i -A ufw6-before-input -p tcp --dport 8081 -j ACCEPT' /etc/ufw/before6.rules
      want_fail='ufw.framework'
      ;;
    ufw-userrules)
      # A rule written straight into user.rules, without the tuple comment:
      # UFW loads it at its next start, `ufw status` does not list it, so
      # ufw.rules alone would pass (FR-06).
      sed -i '/^COMMIT$/i -A ufw-user-input -p tcp --dport 8081 -j ACCEPT' /etc/ufw/user.rules
      want_fail='ufw.userrules'
      ;;
    reboot-required)
      touch /var/run/reboot-required
      want_rc=0
      want_warn='reboot.required'
      ;;
    ufw-disable | ufw-mask)
      # Requirements D60: the rules stay loaded and ufw.active passes, but the
      # next boot no longer starts ufw.service, which loads them.
      systemctl "${drift#ufw-}" ufw.service
      grep -qx 'Status: active' <<<"$(ufw status)" || fail 'UFW is no longer active'
      want_fail='ufw.service'
      ;;
    shell-account)
      # Requirements D61: an account sshd admits whose shell /etc/shells does not list.
      add_shell_account
      want_fail='accounts.nopasswd'
      ;;
    *) fail "unknown drift: $drift" ;;
  esac
  ufw status verbose >"$phase_dir/ufw-after.txt"
  snapshot drift-before
  capture vt51-verify "$VH" verify
  snapshot drift-after
  same_snapshot drift-before drift-after
  expect_rc vt51-verify "$want_rc"
  expect_clean vt51-verify
  got="$(sed -n 's/^\[FAIL\] \([^ ]*\).*/\1/p' "$phase_dir/vt51-verify.out" | sort | paste -sd ' ')"
  [ "$got" = "$want_fail" ] || fail "failed checks: ${got:-none}, expected ${want_fail:-none}"
  got="$(sed -n 's/^\[WARN\] \([^ ]*\).*/\1/p' "$phase_dir/vt51-verify.out" | sort | paste -sd ' ')"
  [ "$got" = "$want_warn" ] || fail "warnings: ${got:-none}, expected ${want_warn:-none}"
  if [ "$drift" = firewall-install ]; then
    diff -u "$phase_dir/ufw-before.txt" "$phase_dir/ufw-after.txt" || fail 'the firewall menu changed UFW'
    expect_text menu 'Firewall is already active'
  fi
  log "$drift: verify reported ${want_fail:-no failure}${want_warn:+, warning $want_warn}"
}

# stopped_attempt BIND N: attempt N as a user that does not exist, with
# journald stopped until a second after it, so that the sshd process has
# exited when journald reads its records and cannot give them _COMM and
# _SYSTEMD_UNIT (detailed design 8.36, group E). Prints the result.
stopped_attempt() {
  local jpid got
  jpid="$(systemctl show -p MainPID --value systemd-journald.service)"
  [ "${jpid:-0}" -gt 0 ] || fail 'systemd-journald has no main PID'
  kill -STOP "$jpid"
  got="$(attempt "$1" "vh-nouser-$2" -i "$PRIVATE/ed25519" -o IdentitiesOnly=yes -o PreferredAuthentications=publickey)" ||
    got=error
  sleep 1
  kill -CONT "$jpid"
  printf '%s stopped-invalid-user-%s %s %s\n' "$(date +%s)" "$2" "$1" "$got" >>"$phase_dir/attempts.txt"
  sleep 1
  printf '%s\n' "$got"
}

# stopped_failures LABEL ADDR...: one stopped attempt from each address. Writes
# the attempts, the change of Fail2ban's counter and the "Invalid user"
# records that lack both _COMM and _SYSTEMD_UNIT to LABEL.txt; sets
# STOPPED_COUNTED and STOPPED_UNATTRIBUTED.
STOPPED_COUNTED=0 STOPPED_UNATTRIBUTED=0
stopped_failures() {
  local label="$1" addr n=0 before after got
  shift
  before="$(f2b_settled_count)"
  for addr in "$@"; do
    n=$((n + 1))
    got="$(stopped_attempt "$addr" "$n")"
    [ "$got" = denied ] || fail "attempt from $addr with journald stopped: $got, expected denied"
  done
  after="$(f2b_settled_count)"
  STOPPED_COUNTED=$((after - before))
  STOPPED_UNATTRIBUTED="$(for addr in "$@"; do journal_entries "$addr"; done |
    awk '$1 == "None" && $3 == "None" && / [|] Invalid user /' | wc -l)"
  printf 'attempts %s counted %s unattributed %s\n' "$n" "$STOPPED_COUNTED" "$STOPPED_UNATTRIBUTED" |
    tee "$phase_dir/$label.txt"
  [ "$STOPPED_UNATTRIBUTED" -ge 1 ] || fail 'no record lacks _COMM and _SYSTEMD_UNIT: the case was not produced'
}

# VT-37 (requirements D84): failures journald cannot attribute to sshd are
# counted all the same, through the identifier and the kernel-attested UID.
phase_m3_journald() {
  local addr n
  m3_netns_up
  wait_fail2ban
  phase_start="$(date +%s)"
  # shellcheck disable=SC2086 # one argument per address
  stopped_failures vt37 $VT37_SOURCES
  n="$(wc -w <<<"$VT37_SOURCES")"
  [ "$STOPPED_COUNTED" -eq "$n" ] || fail "Fail2ban counted $STOPPED_COUNTED of $n failures"
  for addr in $VT37_SOURCES; do
    check_journal_scope "$addr"
    ! banned "$addr" || fail "$addr was banned"
  done
  log "all $n failures counted, $STOPPED_UNATTRIBUTED records without _COMM and _SYSTEMD_UNIT"
}

# What update-fail2ban may change: the jail file, the record and the running
# journalmatch.
f2b_material() {
  sha256sum "$F2B_JAIL" "$STATE_DIR/state"
  fail2ban-client get sshd journalmatch
}

# wait_banned_in_db ADDR: Fail2ban writes a ban to its database from another
# thread; a restart restores the bans it finds there.
wait_banned_in_db() {
  local _
  for _ in $(seq 30); do
    if python3 -c '
import sqlite3, sys
db = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True, timeout=10)
sys.exit(0 if db.execute("SELECT 1 FROM bans WHERE jail = ? AND ip = ?", ("sshd", sys.argv[2])).fetchone() else 1)
' "$F2B_DB" "$1"; then
      return 0
    fi
    sleep 1
  done
  fail "$1 is not in the Fail2ban database"
}

# VT-38 (requirements D84), first part: a host hardened by v0.2.0 and then
# upgraded, simulated: the jail file and its recorded digest as v0.2.0 wrote
# them, and Fail2ban restarted with it. The control repeats VT-37 under the
# old journalmatch. verify warns; update-fail2ban without a terminal, and
# cancelled, changes nothing. Last, a file without a section header in
# jail.d makes the configuration check of the next update fail.
phase_m3_f2b_old() {
  local n
  m3_netns_up
  wait_fail2ban
  sed -i "s/^journalmatch = .*/journalmatch = $OLD_JOURNALMATCH/" "$F2B_JAIL"
  sed -i "s|^digest\.5=.*|digest.5=$(sha256sum <"$F2B_JAIL" | awk '{print $1}') $F2B_JAIL|" "$STATE_DIR/state"
  systemctl restart fail2ban.service
  wait_fail2ban
  [ "$(fail2ban-client get sshd journalmatch | sed 1d)" = "$OLD_JOURNALMATCH" ] || fail 'the old journalmatch is not running'
  phase_start="$(date +%s)"
  # shellcheck disable=SC2086 # one argument per address
  stopped_failures control $VT38_SOURCES
  n="$(wc -w <<<"$VT38_SOURCES")"
  [ "$STOPPED_COUNTED" -lt "$n" ] || fail "the old journalmatch counted all $n failures"
  fail2ban-client set sshd banip "$MANUAL_BAN" >/dev/null
  wait_banned_in_db "$MANUAL_BAN"
  cp -p "$STATE_DIR/state" "$PRIVATE/vt38-state"
  f2b_material >"$PRIVATE/vt38-material"
  capture verify-old "$VH" verify
  expect_rc verify-old 0
  expect_clean verify-old
  expect_report verify-old WARN f2b.values
  expect_text verify-old 'vps-hardening update-fail2ban'
  expect_report verify-old PASS f2b.files
  capture no-tty "$VH" update-fail2ban
  expect_rc no-tty 2
  capture cancelled on_tty "$VH" update-fail2ban
  expect_rc cancelled 1
  expect_report cancelled PASS update.jail
  expect_text cancelled '已取消，未做任何变更'
  for name in no-tty cancelled; do
    expect_clean "$name"
  done
  f2b_material >"$phase_dir/material.txt"
  diff -u "$PRIVATE/vt38-material" "$phase_dir/material.txt" || fail 'a refused or cancelled update left changes'
  printf 'not a configuration file\n' >/etc/fail2ban/jail.d/vh-broken.local
}

# VT-38: after the update that failed its configuration check, the old file,
# record and running value are back.
phase_m3_f2b_restored() {
  rm -f /etc/fail2ban/jail.d/vh-broken.local
  f2b_material >"$phase_dir/material.txt"
  diff -u "$PRIVATE/vt38-material" "$phase_dir/material.txt" || fail 'the failed update left changes'
  capture f2b-test fail2ban-client -t
  expect_rc f2b-test 0
  banned "$MANUAL_BAN" || fail "$MANUAL_BAN is no longer banned"
}

# VT-38, after the update: the new value runs, only digest.5 changed in the
# record, the ban survived the restart and verify passes. A second run has
# nothing to do and asks nothing; a changed jail file is refused.
phase_m3_f2b_updated() {
  wait_fail2ban
  [ "$(fail2ban-client get sshd journalmatch | sed 1d)" = "$JOURNALMATCH" ] || fail 'the new journalmatch is not running'
  grep -qxF "journalmatch = $JOURNALMATCH" "$F2B_JAIL" || fail 'the jail file lacks the new journalmatch'
  [ "$(sed -n 's/^digest\.5=\([0-9a-f]*\) .*/\1/p' "$STATE_DIR/state")" = "$(sha256sum <"$F2B_JAIL" | awk '{print $1}')" ] ||
    fail 'digest.5 is not the digest of the new jail file'
  diff -u <(grep -v '^digest\.5=' "$PRIVATE/vt38-state") <(grep -v '^digest\.5=' "$STATE_DIR/state") ||
    fail 'update-fail2ban changed other lines of the record'
  banned "$MANUAL_BAN" || fail "$MANUAL_BAN was not restored after the restart"
  fail2ban-client set sshd unbanip "$MANUAL_BAN" >/dev/null
  verify_passes vt38-verify
  expect_report vt38-verify PASS f2b.values
  expect_report vt38-verify PASS f2b.files
  f2b_material >"$phase_dir/material-before.txt"
  capture again on_tty "$VH" update-fail2ban
  expect_rc again 0
  expect_text again '无需更新'
  ! grep -qF '确认更新请输入 yes' "$phase_dir/again.out" || fail 'asked although there was nothing to update'
  cp -p "$F2B_JAIL" "$PRIVATE/jail.saved"
  printf '# changed\n' >>"$F2B_JAIL"
  capture changed on_tty "$VH" update-fail2ban
  cp -p "$PRIVATE/jail.saved" "$F2B_JAIL"
  expect_rc changed 1
  expect_report changed FAIL update.jail
  for name in again changed; do
    expect_clean "$name"
  done
  f2b_material >"$phase_dir/material-after.txt"
  diff -u "$phase_dir/material-before.txt" "$phase_dir/material-after.txt" || fail 'a second or refused update left changes'
}

m3_main() {
  local phase="${1-}"
  [ "$#" -eq 0 ] || shift
  [ "$(id -u)" -eq 0 ] || fail 'run as root'
  phase_dir="$EVIDENCE/$phase"
  install -d -m 0700 "$EVIDENCE" "$PRIVATE"
  rm -rf "$phase_dir"
  install -d -m 0700 "$phase_dir"
  case "$phase" in
    m3-backlog-before) phase_m3_backlog_before ;;
    m3-backlog) phase_m3_backlog ;;
    m3-fail2ban) phase_m3_fail2ban ;;
    m3-regex) phase_m3_regex ;;
    m3-ban) phase_m3_ban ;;
    m3-manual-ban) phase_m3_manual_ban ;;
    m3-agent) phase_m3_agent ;;
    m3-updates) phase_m3_updates ;;
    m3-journald) phase_m3_journald ;;
    m3-f2b-old) phase_m3_f2b_old ;;
    m3-f2b-restored) phase_m3_f2b_restored ;;
    m3-f2b-updated) phase_m3_f2b_updated ;;
    m3-xui) phase_m3_xui ;;
    m3-xui-rebooted) phase_m3_xui_rebooted ;;
    m3-drift) phase_m3_drift "$@" ;;
    *) fail "unknown phase: $phase" ;;
  esac
  log "phase $phase passed"
}

m3_main "$@"
