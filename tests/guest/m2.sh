#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Guest side of the M2 VM tests (docs/verification-plan.md 4.2 and 4.3:
# VT-10 to VT-15, VT-20 to VT-24, VT-62, VT-70 and the SSH and UFW part of
# VT-71). tests/vm.py runs apply and confirm over SSH as an administrator
# would, and one phase of this script per SSH session in between.

# shellcheck source=m1.sh
. "${BASH_SOURCE[0]%/*}/m1.sh"

readonly STATE_DIR=/var/lib/vps-hardening
readonly BASELINE="$EVIDENCE/m2-baseline/state"
readonly BOOT_UNIT=vps-hardening-rollback.service
readonly NETNS=vh-src
# Second source (verification plan 3.3). Logins that must work come from the
# .2 addresses; each deliberately failing login has an address of its own, so
# neither sshd's penalties nor a Fail2ban ban can affect a later check.
readonly DST4=192.0.2.1 DST6=2001:db8::1 OK4=192.0.2.2 OK6=2001:db8::2
readonly BAD_ROOT_PW=192.0.2.3 BAD_USER_PW=192.0.2.4 BAD_USER_KEY=192.0.2.5
# The tool's VH_MANAGED_FILES and VH_MANAGED_UNITS (lib/vps-hardening/state.sh).
readonly MANAGED_FILES=(
  /etc/ssh/sshd_config.d/00-vps-hardening.conf
  /etc/default/ufw
  /etc/ufw/ufw.conf
  /etc/ufw/user.rules
  /etc/ufw/user6.rules
  /etc/fail2ban/jail.d/99-vps-hardening.local
  /etc/fail2ban/fail2ban.local
  /etc/apt/apt.conf.d/52vps-hardening
)
# Files only the tool writes; every restore removes them.
readonly TOOL_FILES=' /etc/ssh/sshd_config.d/00-vps-hardening.conf /etc/fail2ban/jail.d/99-vps-hardening.local /etc/fail2ban/fail2ban.local /etc/apt/apt.conf.d/52vps-hardening '
readonly MANAGED_UNITS=(ufw.service fail2ban.service apt-daily.timer apt-daily-upgrade.timer)
# vps-tuning's PROFILE_SYSCTL_KEYS (tools/profile-template.sh.in at tag v0.2.0-rc.4).
readonly TUNING_SYSCTLS=(
  net.core.default_qdisc net.ipv4.tcp_congestion_control
  net.core.rmem_max net.core.wmem_max net.core.rmem_default net.core.wmem_default
  net.ipv4.tcp_rmem net.ipv4.tcp_wmem
  net.core.netdev_max_backlog net.core.somaxconn net.ipv4.tcp_max_syn_backlog
  net.ipv4.tcp_fastopen net.ipv4.tcp_mtu_probing
  net.ipv4.tcp_keepalive_time net.ipv4.tcp_keepalive_intvl net.ipv4.tcp_keepalive_probes
  vm.swappiness
)
# The rules `ufw status` lists, runs of spaces squeezed, for the ports
# tests/vm.py opens in the lifecycle flow (LIFECYCLE_OPEN there).
readonly LIFECYCLE_RULES='22/tcp ALLOW IN Anywhere # vps-hardening
443/tcp ALLOW IN Anywhere # vps-hardening
8443/udp ALLOW IN Anywhere # vps-hardening
22/tcp (v6) ALLOW IN Anywhere (v6) # vps-hardening
443/tcp (v6) ALLOW IN Anywhere (v6) # vps-hardening
2096/tcp (v6) ALLOW IN Anywhere (v6) # vps-hardening'

state_value() {
  awk -v key="$1=" 'index($0, key) == 1 { print substr($0, length(key) + 1); exit }' "$STATE_DIR/state" 2>/dev/null
}

file_sha() {
  if [ -f "$1" ]; then
    sha256sum <"$1" | awk '{print $1}'
  else
    printf 'absent\n'
  fi
}

pkg_ok() {
  [ "$(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null)" = installed ]
}

default_iface() {
  ip route show default | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1) }'
}

unit_state() {
  local enabled active
  enabled="$(systemctl is-enabled "$1" 2>/dev/null)" || true
  active="$(systemctl is-active "$1" 2>/dev/null)" || true
  case "$enabled" in
    '' | not-found) enabled=absent ;;
  esac
  printf '%s %s %s\n' "$1" "$enabled" "${active:-inactive}"
}

ufw_state() {
  if command -v ufw >/dev/null; then
    ufw status verbose 2>&1 | sed '/^$/d'
  else
    printf 'absent\n'
  fi
}

# record_state DIR: everything the M2 cases compare with the baseline.
record_state() {
  local dir="$1" user account path unit key
  user="$(default_user)"
  install -d -m 0700 "$dir"
  for account in root "$user"; do
    /usr/sbin/sshd -T -C "user=$account,host=vh-test.invalid,addr=198.51.100.10,laddr=192.0.2.1,lport=22" \
      >"$dir/sshd-$account.txt"
  done
  ufw_state >"$dir/ufw.txt"
  for path in "${MANAGED_FILES[@]}"; do
    printf '%s %s\n' "$(file_sha "$path")" "$path"
  done >"$dir/files.txt"
  for unit in "${MANAGED_UNITS[@]}"; do
    unit_state "$unit"
  done >"$dir/units.txt"
  for key in "${TUNING_SYSCTLS[@]}"; do
    printf '%s = %s\n' "$key" "$(sysctl -n "$key")"
  done >"$dir/sysctl.txt"
  tc qdisc show dev "$(default_iface)" >"$dir/qdisc.txt"
  file_sha /etc/ufw/sysctl.conf >"$dir/ufw-sysctl.txt"
  # VT-70: APT sources and keyrings.
  find /etc/apt/sources.list /etc/apt/sources.list.d /etc/apt/trusted.gpg /etc/apt/trusted.gpg.d \
    /etc/apt/keyrings /usr/share/keyrings -type f -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum \
    >"$dir/apt.txt" || true
  # VT-11: root's keys, sudoers and the default user's sudo rules.
  {
    sha256sum /root/.ssh/authorized_keys /etc/sudoers
    find /etc/sudoers.d -type f -print0 | sort -z | xargs -0 -r sha256sum
    sudo -n -l -U "$user"
  } >"$dir/access.txt"
  ss -H -ltn 'sport = :22' | awk '{print $4}' | sort >"$dir/listen22.txt"
  cat /proc/sys/kernel/random/boot_id >"$dir/boot_id"
}

# same_as_baseline FILE...: this phase's recorded files equal the baseline's.
same_as_baseline() {
  local file
  for file in "$@"; do
    if ! diff -u "$BASELINE/$file" "$phase_dir/state/$file" >"$phase_dir/$file.diff"; then
      cat "$phase_dir/$file.diff"
      fail "$file differs from the baseline"
    fi
  done
  log "same as the baseline: $*"
}

# The APT timers stay enabled and running as apply leaves them, but an
# unattended upgrade during a test could restart sshd and break the
# continuous probe (VT-25). A drop-in in /run makes the upgrade a no-op until
# the next boot and leaves /etc untouched.
quiet_apt_upgrades() {
  install -d -m 0755 /run/systemd/system/apt-daily-upgrade.service.d
  printf '[Service]\nExecStart=\nExecStart=/bin/true\n' >/run/systemd/system/apt-daily-upgrade.service.d/vh-test.conf
  systemctl daemon-reload
}

# The second source: a network namespace behind a veth pair. Not persistent,
# so every phase that uses it after a boot sets it up again.
netns_up() {
  local addr
  ip netns list | grep -qw "$NETNS" && return 0
  ip netns add "$NETNS"
  ip link add vh-host type veth peer name vh-peer
  ip link set vh-peer netns "$NETNS"
  ip addr add "$DST4/24" dev vh-host
  ip -6 addr add "$DST6/64" dev vh-host nodad
  ip link set vh-host up
  ip -n "$NETNS" link set lo up
  for addr in "$OK4" "$BAD_ROOT_PW" "$BAD_USER_PW" "$BAD_USER_KEY"; do
    ip -n "$NETNS" addr add "$addr/24" dev vh-peer
  done
  ip -n "$NETNS" -6 addr add "$OK6/64" dev vh-peer nodad
  ip -n "$NETNS" link set vh-peer up
  log "second source up: $DST4 and $DST6 reachable from namespace $NETNS"
}

# src_login BIND DEST METHOD [KEY]: ok, denied (sshd refused the credentials)
# or error. METHOD is key (KEY names a file in $PRIVATE) or password, which
# askpass answers with the test password. Connection-level failures, such as
# Debian 13 penalising a source after failed logins, are retried.
src_login() {
  local bind="$1" dest="$2" method="$3" key="${4-}" out rc opts=() _
  case "$method" in
    key) opts=(-i "$PRIVATE/$key" -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o BatchMode=yes) ;;
    password) opts=(-o 'PreferredAuthentications=password,keyboard-interactive' -o PubkeyAuthentication=no
      -o NumberOfPasswordPrompts=1) ;;
  esac
  for _ in $(seq 12); do
    rc=0
    out="$(ip netns exec "$NETNS" env SSH_ASKPASS="$PRIVATE/askpass" SSH_ASKPASS_REQUIRE=force \
      ssh -b "$bind" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
      -o LogLevel=ERROR "${opts[@]}" "$dest" true </dev/null 2>&1)" || rc=$?
    if [ "$rc" -eq 0 ]; then
      printf 'ok\n'
      return 0
    fi
    case "$out" in
      *'Permission denied'*)
        printf 'denied\n'
        return 0
        ;;
    esac
    sleep 5
  done
  printf 'error\n'
}

# expect_login NAME WANT BIND DEST METHOD [KEY]
expect_login() {
  local name="$1" want="$2" got
  shift 2
  got="$(src_login "$@")"
  printf '%s %s %s\n' "$name" "$got" "$*" >>"$phase_dir/logins.txt"
  [ "$got" = "$want" ] || fail "$name: login $got, expected $want"
  log "$name: login $got"
}

# expect_port NAME WANT BIND HOST PORT: open when an HTTP server answers
# through the firewall, closed otherwise.
expect_port() {
  local name="$1" want="$2" got
  shift 2
  got="$(ip netns exec "$NETNS" python3 -c '
import socket, sys
try:
    s = socket.create_connection((sys.argv[2], int(sys.argv[3])), timeout=4, source_address=(sys.argv[1], 0))
    s.sendall(b"GET / HTTP/1.0\r\n\r\n")
    print("open" if s.recv(16).startswith(b"HTTP/") else "closed")
except OSError:
    print("closed")
' "$@")"
  printf '%s %s %s\n' "$name" "$got" "$*" >>"$phase_dir/ports.txt"
  [ "$got" = "$want" ] || fail "$name: port $got, expected $want"
  log "$name: port $got"
}

wait_listen() {
  local port missing _
  for _ in $(seq 60); do
    missing=''
    for port in "$@"; do
      [ -n "$(ss -H -ltn "sport = :$port")" ] || missing="$missing $port"
    done
    [ -n "$missing" ] || return 0
    sleep 1
  done
  fail "no listener on:$missing"
}

wait_fail2ban() {
  local _
  for _ in $(seq 90); do
    fail2ban-client status sshd >/dev/null 2>&1 && return 0
    sleep 2
  done
  fail 'fail2ban did not start its sshd jail'
}

sshd_is() {
  grep -qx -- "$2 $3" "$phase_dir/state/sshd-$1.txt" || fail "sshd for $1: $2 is not $3"
}

restore_armed() {
  [ -e "$STATE_DIR/pending" ] || fail 'the pending marker is missing'
  [ "$(systemctl is-enabled "$BOOT_UNIT" 2>/dev/null)" = enabled ] || fail "$BOOT_UNIT is not enabled"
  [ "$(systemctl list-units --no-legend --state=active 'vps-hardening-timeout-*.timer' | wc -l)" -eq 1 ] ||
    fail 'not exactly one restore timer is active'
}

no_restore_armed() {
  [ ! -e "$STATE_DIR/pending" ] || fail 'the pending marker is still there'
  [ "$(systemctl is-enabled "$BOOT_UNIT" 2>/dev/null || true)" != enabled ] || fail "$BOOT_UNIT is still enabled"
  [ -z "$(systemctl list-units --no-legend --state=active 'vps-hardening-timeout-*.timer')" ] ||
    fail 'a restore timer is still active'
}

# VT-12: no test password or private key in the state directory, the evidence
# or the journal since apply; root's public keys only as fingerprints.
leak_checks() {
  local since="$1" secrets="$PRIVATE/secrets" pubkeys="$PRIVATE/pubkeys"
  { cat "$PRIVATE/password" && printf '\n' && grep -hv -- '-----' "$PRIVATE/ed25519" "$PRIVATE/rsa"; } |
    sed '/^$/d' >"$secrets"
  awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^AAAA[0-9A-Za-z+\/]+=*$/) print $i }' /root/.ssh/authorized_keys >"$pubkeys"
  if grep -rlFf "$secrets" "$STATE_DIR" "$EVIDENCE"; then
    fail 'a test secret is in the files above'
  fi
  if grep -rlFf "$pubkeys" "$STATE_DIR"; then
    fail 'a full public key is in the state directory'
  fi
  if journalctl --since "@$since" --no-pager -o cat | grep -Ff "$secrets" >/dev/null; then
    fail 'a test secret is in the journal'
  fi
  log 'no test secret in the state directory, evidence or journal; public keys only as fingerprints'
}

# VT-62: permissions and content of the state directory.
state_dir_checks() {
  local key i bad
  find "$STATE_DIR" -printf '%y %m %u:%g %p\n' | sort -k4 >"$phase_dir/state-perms.txt"
  bad="$(awk '!(($1 == "d" && $2 == "700") || ($1 == "f" && $2 == "600")) || $3 != "root:root"' "$phase_dir/state-perms.txt")"
  [ -z "$bad" ] || fail "state directory permissions: $bad"
  for key in version started_at applied_at confirmed_at panel_port open confirm_timeout apply_session \
    root_keys denied_users packages_added; do
    grep -q "^$key=" "$STATE_DIR/state" || fail "the state file lacks $key"
  done
  for i in $(seq 0 7); do
    grep -qE "^digest\.$i=([0-9a-f]{64}|absent) /" "$STATE_DIR/state" || fail "the state file lacks digest.$i"
  done
  grep -qx 'open=443/tcp/both 2096/tcp/ipv6 8443/udp/ipv4' "$STATE_DIR/state" || fail 'open ports not recorded'
  grep -qxE 'root_keys=SHA256:[A-Za-z0-9+/]+( SHA256:[A-Za-z0-9+/]+)*' "$STATE_DIR/state" ||
    fail 'root keys are not recorded as fingerprints only'
  [ "$(wc -l <"$STATE_DIR/snapshot/index")" -eq 8 ] || fail 'the snapshot index does not list 8 files'
  log 'state directory: 0700 and 0600, root only; times, version, inputs and digests recorded'
}

# /etc/ufw/sysctl.conf is unchanged, or as the package shipped it when apply installed UFW.
ufw_sysctl_unchanged() {
  local want
  if [ "$(cat "$BASELINE/ufw-sysctl.txt")" != absent ]; then
    same_as_baseline ufw-sysctl.txt
    return 0
  fi
  want="$(dpkg-query -W -f='${Conffiles}\n' ufw | awk '$1 == "/etc/ufw/sysctl.conf" { print $2 }')"
  if [ -z "$want" ] || [ "$(md5sum </etc/ufw/sysctl.conf | awk '{print $1}')" != "$want" ]; then
    fail '/etc/ufw/sysctl.conf differs from the package'
  fi
  log '/etc/ufw/sysctl.conf as the package shipped it'
}

check_ufw_restored() {
  local before now
  before="$(cat "$BASELINE/ufw.txt")"
  now="$(cat "$phase_dir/state/ufw.txt")"
  # Packages stay after a restore (design 4.4): UFW may now be installed, inactive.
  if [ "$before" = absent ]; then
    before='Status: inactive'
  fi
  [ "$now" = "$before" ] || fail "UFW after the restore: $now"
  log "UFW as before: $(head -n 1 "$phase_dir/state/ufw.txt")"
}

check_files_restored() {
  local digest path want
  while read -r digest path; do
    case "$TOOL_FILES" in
      *" $path "*)
        [ ! -e "$path" ] || fail "$path is still there"
        continue
        ;;
    esac
    if [ "$digest" = absent ]; then
      # Installed with a package by apply: back to the package's version,
      # which the snapshot after package installation recorded.
      want="$(awk -v p="$path" '$NF == p { print ($2 == "present") ? $3 : "absent" }' "$STATE_DIR/snapshot/index")"
    else
      want="$digest"
    fi
    [ "$(file_sha "$path")" = "$want" ] || fail "$path is not as before apply"
  done <"$BASELINE/files.txt"
  log 'managed files as before apply'
}

# check_units_restored MODE: at boot, activity before the reboot does not
# carry over, so only enablement is compared, plus that units apply
# introduced are not running.
check_units_restored() {
  local mode="$1" unit before_e before_a name now_e now_a
  while read -r unit before_e before_a; do
    name=''
    read -r name now_e now_a < <(grep "^$unit " "$phase_dir/state/units.txt") || true
    [ "$name" = "$unit" ] || fail "no state recorded for $unit"
    if [ "$before_e" = absent ]; then
      case "$now_e" in
        absent | disabled) ;;
        *) fail "$unit is $now_e after the restore; it did not exist before" ;;
      esac
      [ "$now_a" != active ] || fail "$unit runs after the restore; it did not exist before"
    elif [ "$now_e" != "$before_e" ]; then
      fail "$unit is $now_e after the restore, $before_e before"
    elif [ "$mode" != boot ] && [ "$now_a" != "$before_a" ]; then
      fail "$unit is $now_a after the restore, $before_a before"
    fi
  done <"$BASELINE/units.txt"
  log "units as before ($mode)"
}

check_packages_kept() {
  local pkg
  for pkg in $(state_value packages_added); do
    pkg_ok "$pkg" || fail "$pkg was removed by the restore"
  done
  log "packages installed by apply kept: $(state_value packages_added)"
}

# VT-20: the restore ran when the confirmation time was up, not earlier.
check_restore_time() {
  local applied rolled timeout elapsed
  applied="$(date -d "$(state_value applied_at)" +%s)"
  rolled="$(date -d "$(state_value rolled_back_at)" +%s)"
  timeout=$(($(state_value confirm_timeout) * 60))
  elapsed=$((rolled - applied))
  printf 'applied_at to rolled_back_at: %ss, confirmation time %ss\n' "$elapsed" "$timeout" |
    tee "$phase_dir/restore-time.txt"
  if [ "$elapsed" -lt $((timeout - 5)) ] || [ "$elapsed" -gt $((timeout + 120)) ]; then
    fail "restored after ${elapsed}s with a confirmation time of ${timeout}s"
  fi
}

# VT-22: the restore ran at boot and finished before sshd and UFW started.
check_boot_restore() {
  local done_at unit started
  [ "$(cat "$phase_dir/state/boot_id")" != "$(cat "$BASELINE/boot_id")" ] || fail 'the boot ID did not change'
  journalctl -b -u "$BOOT_UNIT" --no-pager -o cat >"$phase_dir/boot-unit.log"
  cat "$phase_dir/boot-unit.log"
  grep -qF '已恢复到应用前的配置' "$phase_dir/boot-unit.log" || fail "$BOOT_UNIT did not restore"
  done_at="$(systemctl show -p ExecMainExitTimestampMonotonic --value "$BOOT_UNIT")"
  [ "${done_at:-0}" -gt 0 ] || fail "$BOOT_UNIT did not run in this boot"
  for unit in ssh.socket ssh.service ufw.service; do
    started="$(systemctl show -p ActiveEnterTimestampMonotonic --value "$unit")"
    [ "${started:-0}" -eq 0 ] || [ "$started" -ge "$done_at" ] || fail "$unit started before the restore finished"
  done
  log "restored at boot before sshd and UFW started"
}

phase_m2_prepare() {
  local user
  user="$(default_user)"
  [ -s "$PRIVATE/password" ] || fail 'the test password file is missing'
  # RSA keys are what the administrator actually uses (verification plan 3.4).
  cat "$KEYS/rsa.pub" >>/root/.ssh/authorized_keys
  cat "$KEYS/ed25519.pub" >>"/home/$user/.ssh/authorized_keys"
  printf '#!/bin/sh\ncat %s/password\n' "$PRIVATE" >"$PRIVATE/askpass"
  chmod 0700 "$PRIVATE/askpass"
  install -d -m 0755 /root/vh-www
  printf 'ok\n' >/root/vh-www/index.html
  log "guest keys added: RSA for root, Ed25519 for $user"
}

phase_m2_baseline() {
  settle
  quiet_apt_upgrades
  record_state "$phase_dir/state"
  date +%s >"$phase_dir/start"
  log 'baseline recorded'
}

# m2-listen PORT...: HTTP servers on every IPv4 and IPv6 address.
phase_m2_listen() {
  local port
  for port in "$@"; do
    systemd-run --quiet --collect --unit "vh-http-$port" \
      python3 -m http.server --bind :: --directory /root/vh-www "$port"
  done
  wait_listen "$@"
  log "listening on $*"
}

# VT-15: the panel stand-in listens on loopback only, as 3X-UI will.
phase_m2_panel_loopback() {
  systemctl stop vh-http-2053
  systemd-run --quiet --collect --unit vh-http-2053-lo \
    python3 -m http.server --bind 127.0.0.1 --directory /root/vh-www 2053
  wait_listen 2053
  ss -H -ltn 'sport = :2053' | tee "$phase_dir/listen.txt"
  [ "$(awk '{print $4}' "$phase_dir/listen.txt")" = 127.0.0.1:2053 ] || fail 'port 2053 is not on loopback only'
}

phase_m2_before() {
  local user port
  user="$(default_user)"
  netns_up
  # Controls (verification plan VR-8): what must fail after apply works now.
  expect_login ctl-root-key ok "$OK4" "root@$DST4" key rsa
  expect_login ctl-root-key-v6 ok "$OK6" "root@$DST6" key rsa
  expect_login ctl-user-key ok "$BAD_USER_KEY" "$user@$DST4" key ed25519
  expect_login ctl-user-password ok "$BAD_USER_PW" "$user@$DST4" password
  for port in 443 2096 2053 8080 80; do
    expect_port "ctl-v4-$port" open "$OK4" "$DST4" "$port"
    expect_port "ctl-v6-$port" open "$OK6" "$DST6" "$port"
  done
}

# VT-24: refused confirmations leave the change pending.
phase_m2_pending() {
  [ "$(state_value status)" = pending ] || fail "status is $(state_value status), expected pending"
  restore_armed
  log 'still pending: marker, boot unit and one restore timer in place'
}

phase_m2_applied() {
  local user account port
  user="$(default_user)"
  netns_up
  record_state "$phase_dir/state"
  cp "$STATE_DIR/state" "$phase_dir/tool-state.txt"
  cp "$STATE_DIR/log" "$phase_dir/tool-log.txt"

  # VT-10: confirmed, nothing left armed, verify passes.
  [ "$(state_value status)" = applied ] || fail "status is $(state_value status), expected applied"
  no_restore_armed
  capture vt10-verify "$VH" verify
  expect_rc vt10-verify 0
  expect_clean vt10-verify

  # VT-11: sudo rules, root's keys and sudoers unchanged.
  same_as_baseline access.txt

  # VT-13: effective values per account; the cloud-init fragment stays.
  for account in root "$user"; do
    sshd_is "$account" passwordauthentication no
    sshd_is "$account" kbdinteractiveauthentication no
  done
  sshd_is root permitrootlogin without-password
  sshd_is root pubkeyauthentication yes
  awk '$1 == "denyusers" { for (i = 2; i <= NF; i++) print $i }' "$phase_dir/state/sshd-$user.txt" |
    grep -qx -- "$user" || fail "$user is not in DenyUsers"
  grep -qx 'PasswordAuthentication yes' /etc/ssh/sshd_config.d/50-cloud-init.conf ||
    fail '50-cloud-init.conf was changed'
  same_as_baseline listen22.txt

  # VT-14: policies and rules as declared, checked over IPv4 and IPv6.
  ufw status verbose >"$phase_dir/ufw-status.txt"
  grep -qxE 'Default: deny \(incoming\), allow \(outgoing\), (deny|disabled) \(routed\)' "$phase_dir/ufw-status.txt" ||
    fail 'UFW default policies'
  awk 'seen && NF { gsub(/ +/, " "); print } /^--/ { seen = 1 }' "$phase_dir/ufw-status.txt" | sort >"$phase_dir/ufw-rules.txt"
  printf '%s\n' "$LIFECYCLE_RULES" | sort >"$phase_dir/ufw-rules.expected"
  diff -u "$phase_dir/ufw-rules.expected" "$phase_dir/ufw-rules.txt" || fail 'UFW rules differ from the declaration'
  expect_login root-key ok "$OK4" "root@$DST4" key rsa
  expect_login root-key-v6 ok "$OK6" "root@$DST6" key rsa
  expect_port v4-443 open "$OK4" "$DST4" 443
  expect_port v6-443 open "$OK6" "$DST6" 443
  expect_port v4-2096 closed "$OK4" "$DST4" 2096
  expect_port v6-2096 open "$OK6" "$DST6" 2096
  for port in 2053 8080 80; do
    expect_port "v4-$port" closed "$OK4" "$DST4" "$port"
    expect_port "v6-$port" closed "$OK6" "$DST6" "$port"
  done

  state_dir_checks
  same_as_baseline apt.txt
  same_as_baseline sysctl.txt qdisc.txt
  ufw_sysctl_unchanged
  leak_checks "$(cat "$EVIDENCE/m2-baseline/start")"

  # VT-11 and VT-13: the failing logins come last.
  expect_login root-password denied "$BAD_ROOT_PW" "root@$DST4" password
  expect_login user-password denied "$BAD_USER_PW" "$user@$DST4" password
  expect_login user-key denied "$BAD_USER_KEY" "$user@$DST4" key ed25519
}

phase_m2_rebooted() {
  cloud-init status --wait >/dev/null 2>&1 || true
  quiet_apt_upgrades
  record_state "$phase_dir/state"
  [ "$(cat "$phase_dir/state/boot_id")" != "$(cat "$EVIDENCE/m2-applied/state/boot_id")" ] ||
    fail 'the boot ID did not change'
  [ "$(state_value status)" = applied ] || fail "status is $(state_value status), expected applied"
  no_restore_armed
  wait_fail2ban
  capture vt10-reboot-verify "$VH" verify
  expect_rc vt10-reboot-verify 0
  expect_clean vt10-reboot-verify
  same_as_baseline sysctl.txt qdisc.txt listen22.txt
}

# m2-rolled-back MODE: VT-20 (timeout), VT-22 (boot) and VT-23 (failure).
phase_m2_rolled_back() {
  local mode="${1-}" reason user
  user="$(default_user)"
  case "$mode" in
    timeout) reason='确认超时' ;;
    boot) reason='待确认期间重启' ;;
    failure) reason='应用失败' ;;
    *) fail "unknown restore mode: $mode" ;;
  esac
  cloud-init status --wait >/dev/null 2>&1 || true
  record_state "$phase_dir/state"
  cp "$STATE_DIR/state" "$phase_dir/tool-state.txt"
  cp "$STATE_DIR/log" "$phase_dir/tool-log.txt"
  [ "$(state_value status)" = rolled-back ] || fail "status is $(state_value status), expected rolled-back"
  state_value rollback_reason | grep -qF -- "$reason" || fail "rollback reason: $(state_value rollback_reason)"
  no_restore_armed
  same_as_baseline sshd-root.txt "sshd-$user.txt" sysctl.txt qdisc.txt apt.txt access.txt listen22.txt
  check_ufw_restored
  check_files_restored
  check_units_restored "$mode"
  check_packages_kept
  case "$mode" in
    timeout) check_restore_time ;;
    boot) check_boot_restore ;;
  esac
  leak_checks "$(cat "$EVIDENCE/m2-baseline/start")"
}

# VT-23: Fail2ban installed as the distribution ships it and its service
# masked, so that apply fails after the restore is armed.
phase_vt23_setup() {
  settle
  install_packages fail2ban
  systemctl mask --now fail2ban.service
  log "fail2ban.service is $(systemctl is-enabled fail2ban.service 2>/dev/null || true)"
}

m2_main() {
  local phase="${1-}"
  [ "$#" -eq 0 ] || shift
  [ "$(id -u)" -eq 0 ] || fail 'run as root'
  phase_dir="$EVIDENCE/$phase"
  install -d -m 0700 "$EVIDENCE" "$PRIVATE"
  rm -rf "$phase_dir"
  install -d -m 0700 "$phase_dir"
  case "$phase" in
    m2-prepare) phase_m2_prepare ;;
    m2-baseline) phase_m2_baseline ;;
    m2-listen) phase_m2_listen "$@" ;;
    m2-panel-loopback) phase_m2_panel_loopback ;;
    m2-before) phase_m2_before ;;
    m2-pending) phase_m2_pending ;;
    m2-applied) phase_m2_applied ;;
    m2-rebooted) phase_m2_rebooted ;;
    m2-rolled-back) phase_m2_rolled_back "$@" ;;
    vt23-setup) phase_vt23_setup ;;
    *) fail "unknown phase: $phase" ;;
  esac
  log "phase $phase passed"
}

m2_main "$@"
