#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Guest side of the M4 VM tests (docs/verification-plan.md 4.8: VT-61, VT-63,
# VT-64 and the local part of VT-72; VT-60 runs in the lifecycle flow with the
# M2 phases). tests/vm.py runs rollback, ports, apply and confirm over SSH as
# an administrator would, and one phase of this script per SSH session in
# between. The hardened suite also runs the two port-flow phases of VT-55
# from here, for the UFW helpers.

# shellcheck source=m2.sh
. "${BASH_SOURCE[0]%/*}/m2.sh"

readonly INSTALLED_BIN=/usr/local/bin/vps-hardening
readonly INSTALLED_LIB=/usr/local/lib/vps-hardening

# The tool's record and everything it manages, for the "no change" checks.
tool_record() {
  local path unit
  find "$STATE_DIR" -type f -print0 | sort -z | xargs -0 -r sha256sum
  for path in "${MANAGED_FILES[@]}"; do
    printf '%s %s\n' "$(file_sha "$path")" "$path"
  done
  ufw status verbose
  for unit in "${MANAGED_UNITS[@]}" "$BOOT_UNIT"; do
    unit_state "$unit"
  done
  systemctl list-units --no-legend --all 'vps-hardening-timeout-*'
}

# rules_for PORT/PROTO...: the `ufw status verbose` rules, spaces squeezed, for
# 22/tcp and the given ports, each for IPv4 and IPv6.
rules_for() {
  local spec
  for spec in 22/tcp "$@"; do
    printf '%s ALLOW IN Anywhere # vps-hardening\n' "$spec"
    printf '%s (v6) ALLOW IN Anywhere (v6) # vps-hardening\n' "$spec"
  done
}

ufw_rules_are() {
  ufw status verbose | awk 'seen && NF { gsub(/ +/, " "); print } /^--/ { seen = 1 }' | sort >"$phase_dir/ufw-rules.txt"
  rules_for "$@" | sort >"$phase_dir/ufw-rules.expected"
  diff -u "$phase_dir/ufw-rules.expected" "$phase_dir/ufw-rules.txt" || fail 'UFW rules differ from the declaration'
  log "UFW allows 22/tcp $* on IPv4 and IPv6, nothing else"
}

# ports_reachable OPEN CLOSED: "PORT..." lists, checked from the second source over IPv4 and IPv6.
ports_reachable() {
  local port
  for port in $1; do
    expect_port "v4-$port" open "$OK4" "$DST4" "$port"
    expect_port "v6-$port" open "$OK6" "$DST6" "$port"
  done
  for port in $2; do
    expect_port "v4-$port" closed "$OK4" "$DST4" "$port"
    expect_port "v6-$port" closed "$OK6" "$DST6" "$port"
  done
}

# Each overlay boots with the APT timers running; keep upgrades from
# restarting sshd during the probe (VT-25).
phase_m4_setup() {
  local deadline=$((SECONDS + 1200))
  cloud-init status --wait >/dev/null 2>&1 || true
  quiet_apt_upgrades
  while apt_busy; do
    [ "$SECONDS" -lt "$deadline" ] || fail 'package manager still busy after 20 minutes'
    sleep 5
  done
  [ "$(state_value status)" != applied ] || wait_fail2ban
  log 'ready'
}

# VT-61: 3X-UI's files and service before the rollback. The database, the
# metrics file and the Xray configuration the panel writes while it runs are
# left out.
xui_files() {
  find /usr/local/x-ui /usr/bin/x-ui /etc/x-ui /etc/systemd/system/x-ui.service /etc/systemd/system/x-ui.service.d \
    -xdev -type f -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum |
    grep -vE '  (/etc/x-ui/(x-ui\.db(-wal|-shm)?|system_metrics\.gob)|/usr/local/x-ui/bin/config\.json)$' || true
}

phase_m4_xui_record() {
  xui_files >"$phase_dir/xui-files.txt"
  grep -q '  /usr/local/x-ui/x-ui$' "$phase_dir/xui-files.txt" || fail '3X-UI is not installed'
  unit_state x-ui.service | tee "$phase_dir/xui-unit.txt"
  grep -qx 'x-ui.service enabled active' "$phase_dir/xui-unit.txt" || fail 'x-ui.service is not enabled and running'
}

phase_m4_xui_kept() {
  xui_files >"$phase_dir/xui-files.txt"
  diff -u "$EVIDENCE/m4-xui-record/xui-files.txt" "$phase_dir/xui-files.txt" || fail 'the rollback changed 3X-UI files'
  unit_state x-ui.service >"$phase_dir/xui-unit.txt"
  diff -u "$EVIDENCE/m4-xui-record/xui-unit.txt" "$phase_dir/xui-unit.txt" || fail 'the rollback changed x-ui.service'
  wait_listen 2053
  ss -H -ltn 'sport = :2053' | tee "$phase_dir/xui-listen.txt"
  [ "$(awk '{print $4}' "$phase_dir/xui-listen.txt")" = 127.0.0.1:2053 ] || fail 'the panel is not on 127.0.0.1:2053 only'
  log "3X-UI files ($(wc -l <"$phase_dir/xui-files.txt")) and service unchanged; panel on loopback"
}

# VT-55, requirement D41: hardened without public ports, UFW allows 22/tcp only.
phase_m4_flow_ssh_only() {
  [ "$(state_value status)" = applied ] || fail "status is $(state_value status), expected applied"
  [ -z "$(state_value open)" ] || fail "declared ports: $(state_value open)"
  ufw_rules_are
}

# VT-55, requirement D41: the 3X-UI ports added with ports and confirmed.
phase_m4_flow_ports_added() {
  [ "$(state_value status)" = applied ] || fail "status is $(state_value status), expected applied"
  [ "$(state_value open)" = '443/tcp/both 2096/tcp/both' ] || fail "declared ports: $(state_value open)"
  [ -n "$(state_value ports_confirmed_at)" ] || fail 'the confirmation of the port change is not recorded'
  no_restore_armed
  ufw_rules_are 443/tcp 2096/tcp
  verify_passes flow-verify
}

# VT-63: the hardened guest with HTTP servers on 443, 2096, 8443 and 9443.
phase_m4_ports_before() {
  netns_up
  ufw_rules_are 443/tcp 2096/tcp
  ports_reachable '443 2096' '8443 9443 2053'
}

# VT-63: conflicting ports, an undeclared removal and a cancelled change are
# refused before anything changes.
phase_m4_ports_refused() {
  local name
  tool_record >"$phase_dir/record-before.txt"
  capture no-tty "$VH" ports --add 8443/tcp
  expect_rc no-tty 2
  expect_text no-tty '必须在交互终端中运行'
  capture add-ssh on_tty "$VH" ports --add 22/tcp
  expect_rc add-ssh 2
  expect_text add-ssh '公开端口不能是 22'
  capture add-panel on_tty "$VH" ports --add 2053/tcp
  expect_rc add-panel 2
  expect_text add-panel '与面板端口相同'
  capture add-http on_tty "$VH" ports --add 80/tcp
  expect_rc add-http 2
  expect_text add-http '公开端口不能是 80/tcp'
  capture add-declared on_tty "$VH" ports --add 443/tcp/ipv4
  expect_rc add-declared 2
  expect_text add-declared '已经是公开端口'
  capture remove-undeclared on_tty "$VH" ports --remove 8080/tcp
  expect_rc remove-undeclared 2
  expect_text remove-undeclared '不是已声明的公开端口'
  # A line written straight into a rules file: the change would rewrite the
  # file without it while the line stays loaded.
  cp -p /etc/ufw/user6.rules "$PRIVATE/user6.rules"
  sed -i '/^COMMIT$/i -A ufw6-user-input -p tcp --dport 8081 -j ACCEPT' /etc/ufw/user6.rules
  capture userrules on_tty "$VH" ports --add 8443/tcp
  cp -p "$PRIVATE/user6.rules" /etc/ufw/user6.rules
  expect_rc userrules 1
  expect_report userrules FAIL ports.userrules
  expect_report userrules PASS ports.rules
  capture cancelled on_tty "$VH" ports --add 8443/tcp
  expect_rc cancelled 1
  expect_text cancelled '已取消，未做任何变更'
  for name in no-tty add-ssh add-panel add-http add-declared remove-undeclared userrules cancelled; do
    expect_clean "$name"
  done
  tool_record >"$phase_dir/record-after.txt"
  diff -u "$phase_dir/record-before.txt" "$phase_dir/record-after.txt" || fail 'a refused or cancelled change left changes'
  log 'refused and cancelled port changes changed nothing'
}

phase_m4_ports_changed() {
  netns_up
  [ "$(state_value status)" = applied ] || fail "status is $(state_value status), expected applied"
  [ "$(state_value open)" = '443/tcp/both 8443/tcp/both' ] || fail "declared ports: $(state_value open)"
  [ -n "$(state_value ports_confirmed_at)" ] || fail 'the confirmation of the port change is not recorded'
  no_restore_armed
  [ ! -e "$STATE_DIR/snapshot-ports" ] || fail 'the port snapshot is still there'
  ufw_rules_are 443/tcp 8443/tcp
  ports_reachable '443 8443' '2096 2053 9443'
  sha256sum /etc/ufw/user.rules /etc/ufw/user6.rules >"$phase_dir/ufw-files.txt"
  verify_passes vt63-verify
}

phase_m4_ports_pending() {
  netns_up
  [ "$(state_value status)" = ports-pending ] || fail "status is $(state_value status), expected ports-pending"
  restore_armed
  grep -qx 'kind=ports' "$STATE_DIR/pending" || fail 'the pending marker is not for a port change'
  ufw_rules_are 443/tcp 8443/tcp 9443/tcp
  ports_reachable '443 8443 9443' '2096'
  capture status "$VH" status
  expect_rc status 0
  expect_text status '状态：端口变更待确认'
  expect_text status '变更前的公开端口：22/tcp、443/tcp、8443/tcp'
  capture verify "$VH" verify
  expect_rc verify 0
  expect_report verify WARN state
  expect_report verify PASS ufw.rules
}

phase_m4_ports_restored() {
  netns_up
  [ "$(state_value status)" = applied ] || fail "status is $(state_value status), expected applied"
  state_value ports_rollback_reason | grep -qxF '确认超时' || fail "restore reason: $(state_value ports_rollback_reason)"
  [ "$(state_value open)" = '443/tcp/both 8443/tcp/both' ] || fail "declared ports: $(state_value open)"
  no_restore_armed
  [ ! -e "$STATE_DIR/snapshot-ports" ] || fail 'the port snapshot is still there'
  sha256sum -c "$EVIDENCE/m4-ports-changed/ufw-files.txt" || fail 'the UFW rule files are not as before the change'
  ufw_rules_are 443/tcp 8443/tcp
  ports_reachable '443 8443' '9443'
  verify_passes vt63-restored-verify
}

# VT-64
phase_m4_record() {
  tool_record >"$phase_dir/record.txt"
  log "recorded $(wc -l <"$phase_dir/record.txt") lines"
}

# m4-unchanged LABEL REF: the record equals the one phase REF made.
phase_m4_unchanged() {
  tool_record >"$phase_dir/record.txt"
  diff -u "$EVIDENCE/$2/record.txt" "$phase_dir/record.txt" || fail "changed since $2"
  log "unchanged since $2"
}

phase_m4_ufw_drift() {
  ufw allow 8080/tcp
  tool_record >"$phase_dir/record.txt"
}

phase_m4_unmask() {
  systemctl unmask fail2ban.service
  log "fail2ban.service is $(systemctl is-enabled fail2ban.service 2>/dev/null || true)"
}

phase_m4_reapplied() {
  [ "$(state_value status)" = applied ] || fail "status is $(state_value status), expected applied"
  ! grep -qE '^(rollback_reason|rolled_back_at)=' "$STATE_DIR/state" || fail 'records of the earlier apply are left'
  no_restore_armed
  verify_passes vt64-verify
}

# VT-72, local part: a release directory as the release workflow will make it.
release_dir() {
  install -d -m 0755 "$1"
  install -m 0755 "$BUNDLE/bin/vps-hardening" "$1/vps-hardening"
  install -m 0644 -t "$1" "$BUNDLE"/lib/vps-hardening/*.sh
  (cd "$1" && sha256sum vps-hardening ./*.sh | sed 's|  \./|  |' >SHA256SUMS)
}

installed_record() {
  stat -c '%a %U:%G %n' "$INSTALLED_BIN" "$INSTALLED_LIB" "$INSTALLED_LIB"/*
  sha256sum "$INSTALLED_BIN" "$INSTALLED_LIB"/*
  find /usr/local/bin /usr/local/lib -maxdepth 1 -name '.vps-hardening*'
}

# fake_mv: a test double for mv, first on the installer's PATH. With
# VH_TEST_FAULT set, the rename of the staged modules ("lib-") or of the new
# command ("bin-") fails ("-fail") or is followed by SIGTERM to the installer
# ("-term"). Every other call goes to mv.
fake_mv() {
  [ ! -e /usr/local/sbin/mv ] || fail '/usr/local/sbin/mv exists'
  install -d -m 0755 /usr/local/sbin
  cat >/usr/local/sbin/mv <<'EOF'
#!/bin/sh
case "${VH_TEST_FAULT-}" in
  lib-*) pattern='/.vps-hardening.stage.' ;;
  bin-*) pattern='/.vps-hardening.new.' ;;
  *) exec /bin/mv "$@" ;;
esac
case "$*" in
  *"$pattern"*) ;;
  *) exec /bin/mv "$@" ;;
esac
case "$VH_TEST_FAULT" in
  *-fail) exit 1 ;;
esac
/bin/mv "$@" || exit
kill -TERM "$PPID"
EOF
  chmod 0755 /usr/local/sbin/mv
}

# expect_install NAME RC TEXT ARGS...: the installer copy exits with RC and says TEXT.
expect_install() {
  local name="$1" rc="$2" text="$3"
  shift 3
  capture "$name" bash "$@"
  expect_rc "$name" "$rc"
  expect_text "$name" "$text"
}

phase_m4_installer() {
  local rel=/root/vh-release inst=/root/vh-install.sh digest version name lock_pid
  if [ -e "$STATE_DIR" ] || [ -e "$INSTALLED_BIN" ]; then
    fail 'the guest is not clean for the installer test'
  fi
  # Both preflight runs below must see an idle package manager.
  settle
  version="$(sed -n "s/^readonly VH_VERSION='\(.*\)'$/\1/p" "$VH")"
  rm -rf "$rel"*
  release_dir "$rel"
  cat "$rel/SHA256SUMS"
  [ "$(wc -l <"$rel/SHA256SUMS")" -eq 13 ] || fail 'the release lists not 13 assets'
  digest="$(sha256sum <"$rel/SHA256SUMS" | awk '{print $1}')"
  sed "s/^EXPECTED_MANIFEST_SHA256=''\$/EXPECTED_MANIFEST_SHA256='$digest'/" "$BUNDLE/install.sh" >"$inst"
  grep -qx "EXPECTED_MANIFEST_SHA256='$digest'" "$inst" || fail 'could not bind the installer copy'

  # The installer as committed is bound to no release and installs nothing.
  expect_install unbound 1 '没有绑定发行版' "$BUNDLE/install.sh" --source-dir "$rel"
  expect_install relative 2 '必须是绝对路径' "$inst" --source-dir vh-release
  [ ! -e "$INSTALLED_BIN" ] || fail 'a refused install left files'
  # An install that does not complete puts back what was there: here nothing.
  fake_mv
  VH_TEST_FAULT=bin-fail expect_install fault-fresh 1 '已恢复为安装前的状态' "$inst" --source-dir "$rel"
  rm /usr/local/sbin/mv
  [ ! -e "$INSTALLED_BIN" ] && [ ! -e "$INSTALLED_LIB" ] || fail 'an incomplete install left files'
  [ -z "$(find /usr/local/bin /usr/local/lib -maxdepth 1 -name '.vps-hardening*')" ] ||
    fail 'an incomplete install left staging files'

  expect_install install 0 '安装完成' "$inst" --source-dir "$rel"
  # The recommended flow declares no public port at hardening (requirements D41).
  expect_match install '下一步：vps-hardening preflight$'
  installed_record | tee "$phase_dir/installed.txt"
  [ "$(grep -c '^755 root:root ' "$phase_dir/installed.txt")" -eq 2 ] || fail 'the command or module directory is not 0755 root'
  [ "$(grep -c '^644 root:root ' "$phase_dir/installed.txt")" -eq 12 ] || fail 'not 12 modules 0644 root'
  ! grep -q '/\.vps-hardening' "$phase_dir/installed.txt" || fail 'staging files are left'
  for name in vps-hardening "$BUNDLE"/lib/vps-hardening/*.sh; do
    name="${name##*/}"
    if [ "$name" = vps-hardening ]; then
      cmp "$rel/$name" "$INSTALLED_BIN" || fail 'the installed command differs from the release'
    else
      cmp "$rel/$name" "$INSTALLED_LIB/$name" || fail "the installed $name differs from the release"
    fi
  done
  [ "$("$INSTALLED_BIN" --version)" = "vps-hardening $version" ] || fail 'the installed version is wrong'
  capture installed-preflight "$INSTALLED_BIN" preflight "${GOOD_ARGS[@]}"
  capture bundle-preflight "$VH" preflight "${GOOD_ARGS[@]}"
  diff -u "$phase_dir/bundle-preflight.out" "$phase_dir/installed-preflight.out" || fail 'the installed preflight differs'
  [ "$(cat "$phase_dir/installed-preflight.rc")" = "$(cat "$phase_dir/bundle-preflight.rc")" ] || fail 'preflight exit status differs'
  expect_clean installed-preflight

  expect_install again 0 '未做变更' "$inst" --source-dir "$rel"
  # The same contents with another mode or owner are installed again.
  for name in mode-module mode-dir owner-command; do
    case "$name" in
      mode-module) chmod 0600 "$INSTALLED_LIB/common.sh" ;;
      mode-dir) chmod 0700 "$INSTALLED_LIB" ;;
      owner-command) chown 65534:65534 "$INSTALLED_BIN" ;;
    esac
    expect_install "$name" 0 '安装完成' "$inst" --source-dir "$rel"
    installed_record >"$phase_dir/installed-$name.txt"
    diff -u "$phase_dir/installed.txt" "$phase_dir/installed-$name.txt" || fail "$name: the release was not installed again"
  done

  # Tampered asset, tampered manifest, missing asset: refused, nothing changed.
  cp -a "$rel" "$rel-asset"
  printf '# tampered\n' >>"$rel-asset/common.sh"
  expect_install tampered-asset 1 'common.sh 未通过 SHA-256 校验' "$inst" --source-dir "$rel-asset"
  cp -a "$rel-asset" "$rel-manifest"
  (cd "$rel-manifest" && sha256sum vps-hardening ./*.sh | sed 's|  \./|  |' >SHA256SUMS)
  expect_install tampered-manifest 1 '与安装脚本内置的不一致' "$inst" --source-dir "$rel-manifest"
  cp -a "$rel" "$rel-missing"
  rm "$rel-missing/ports.sh"
  expect_install missing-asset 1 '资产目录中没有 ports.sh' "$inst" --source-dir "$rel-missing"
  # Not while a change awaits confirmation, nor while the tool holds its lock.
  install -d -m 0700 "$STATE_DIR"
  : >"$STATE_DIR/pending"
  expect_install pending 1 '有待确认的变更' "$inst" --source-dir "$rel"
  rm -rf "$STATE_DIR"
  # The lock holder becomes sleep itself, so killing it releases the lock.
  (exec 9>/run/vps-hardening.lock && flock 9 && exec sleep 120) &
  lock_pid=$!
  sleep 2
  expect_install locked 1 '另一个 vps-hardening 操作正在进行' "$inst" --source-dir "$rel"
  kill "$lock_pid"
  wait "$lock_pid" || true
  installed_record >"$phase_dir/installed-after.txt"
  diff -u "$phase_dir/installed.txt" "$phase_dir/installed-after.txt" || fail 'a refused install changed the installed files'

  # A replacement that fails or is interrupted at either rename, or after the
  # command is replaced, puts the previous copy back as it was.
  printf '# local change\n' >>"$INSTALLED_LIB/status.sh"
  installed_record >"$phase_dir/installed-changed.txt"
  fake_mv
  for name in lib-fail lib-term bin-fail bin-term; do
    VH_TEST_FAULT="$name" expect_install "fault-$name" 1 '已恢复为安装前的状态' "$inst" --source-dir "$rel"
    installed_record >"$phase_dir/installed-fault-$name.txt"
    diff -u "$phase_dir/installed-changed.txt" "$phase_dir/installed-fault-$name.txt" ||
      fail "fault-$name: the previous copy was not put back"
  done
  rm /usr/local/sbin/mv

  # Replacing a different installed copy puts the release back. On an applied
  # host the closing hint points to verify, not preflight.
  install -d -m 0700 "$STATE_DIR"
  printf 'status=applied\n' >"$STATE_DIR/state"
  expect_install replace 0 '安装完成' "$inst" --source-dir "$rel"
  expect_text replace '下一步：vps-hardening verify'
  rm -rf "$STATE_DIR"
  installed_record >"$phase_dir/installed-replaced.txt"
  diff -u "$phase_dir/installed.txt" "$phase_dir/installed-replaced.txt" || fail 'the replaced install differs'
  for name in unbound relative fault-fresh install again mode-module mode-dir owner-command tampered-asset \
    tampered-manifest missing-asset pending locked fault-lib-fail fault-lib-term fault-bin-fail fault-bin-term replace; do
    expect_clean "$name"
  done
  log 'installer: verified install, no-op reinstall, reinstall for modes and owners, replacement; tampered, missing, pending and locked refused; incomplete installs put back'
}

m4_main() {
  local phase="${1-}"
  [ "$(id -u)" -eq 0 ] || fail 'run as root'
  # Every word names the evidence directory, so repeated phases keep theirs.
  phase_dir="$EVIDENCE/$(IFS=-; printf '%s' "$*")"
  [ "$#" -eq 0 ] || shift
  install -d -m 0700 "$EVIDENCE" "$PRIVATE"
  rm -rf "$phase_dir"
  install -d -m 0700 "$phase_dir"
  case "$phase" in
    m4-setup) phase_m4_setup ;;
    m4-xui-record) phase_m4_xui_record ;;
    m4-xui-kept) phase_m4_xui_kept ;;
    m4-flow-ssh-only) phase_m4_flow_ssh_only ;;
    m4-flow-ports-added) phase_m4_flow_ports_added ;;
    m4-ports-before) phase_m4_ports_before ;;
    m4-ports-refused) phase_m4_ports_refused ;;
    m4-ports-changed) phase_m4_ports_changed ;;
    m4-ports-pending) phase_m4_ports_pending ;;
    m4-ports-restored) phase_m4_ports_restored ;;
    m4-record) phase_m4_record ;;
    m4-unchanged) phase_m4_unchanged "$@" ;;
    m4-ufw-drift) phase_m4_ufw_drift ;;
    m4-unmask) phase_m4_unmask ;;
    m4-reapplied) phase_m4_reapplied ;;
    m4-installer) phase_m4_installer ;;
    *) fail "unknown phase: $phase" ;;
  esac
  log "phase $phase passed"
}

m4_main "$@"
