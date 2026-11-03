#!/usr/bin/env bash
# D64 guest assertions. The runner performs apply/confirm in real SSH sessions.
# shellcheck source-path=SCRIPTDIR
# shellcheck source=m4.sh
. "${BASH_SOURCE[0]%/*}/m4.sh"

provider_file=/etc/ssh/sshd_config.d/01-vh-provider.conf

endpoint_evidence() {
  /usr/sbin/sshd -T >"$phase_dir/sshd-T.txt"
  ss -H -ltnp >"$phase_dir/listeners.txt"
  systemctl show ssh.service -p ExecStart -p MainPID -p FragmentPath -p DropInPaths >"$phase_dir/service.txt"
  systemctl show ssh.socket -p Listen -p ActiveState -p FragmentPath -p DropInPaths >"$phase_dir/socket.txt"
  systemctl cat ssh.service ssh.socket >"$phase_dir/units.txt" 2>&1 || true
}

phase_endpoint_cases() {
  local candidate=$((GUEST_SSH_PORT + 1)) spec
  settle
  assert_ssh_mode
  endpoint_evidence
  cp -p "$provider_file" "$PRIVATE/provider.saved"
  for spec in panel public; do
    snapshot "$spec-before"
    if [ "$spec" = panel ]; then
      capture "$spec" "$VH" preflight --panel-port "$GUEST_SSH_PORT"
    else
      capture "$spec" "$VH" preflight --open "$GUEST_SSH_PORT/udp"
    fi
    expect_rc "$spec" 2
    snapshot "$spec-after"
    same_snapshot "$spec-before" "$spec-after"
  done
  # No environment variable is required for a console preflight.
  snapshot console-before
  capture console systemd-run --quiet --unit="vh-console-preflight-$$" --wait --pipe --collect \
    /usr/bin/env -u SSH_CONNECTION -u SSH_CLIENT "$VH" preflight
  expect_rc console 0
  expect_report console PASS sshd.endpoint
  snapshot console-after
  same_snapshot console-before console-after
  for spec in multi mixed mismatch; do
    case "$spec" in
      multi) printf 'Port %s\nPort %s\n' "$GUEST_SSH_PORT" "$candidate" >"$provider_file" ;;
      mixed) printf 'Port %s\nListenAddress 0.0.0.0\nListenAddress 127.0.0.1:%s\n' \
        "$GUEST_SSH_PORT" "$candidate" >"$provider_file" ;;
      mismatch) printf 'Port %s\n' "$candidate" >"$provider_file" ;;
    esac
    snapshot "$spec-before"
    capture "$spec" "$VH" preflight
    expect_rc "$spec" 1
    expect_report "$spec" FAIL sshd.endpoint
    capture "$spec-apply" on_tty "$VH" apply
    expect_rc "$spec-apply" 1
    expect_report "$spec-apply" FAIL sshd.endpoint
    snapshot "$spec-after"
    same_snapshot "$spec-before" "$spec-after"
    cp -p "$PRIVATE/provider.saved" "$provider_file"
  done
  capture restored "$VH" preflight
  expect_rc restored 0
}

phase_endpoint_explicit() {
  # Service activation is selected by the runner for this overlay. sshd -T
  # reports its default Port=22; the explicit ListenAddress still listens on P.
  [ ! "$(systemctl is-active ssh.socket || true)" = active ] || fail 'explicit-address fixture needs service activation'
  printf 'ListenAddress 0.0.0.0:%s\n' "$GUEST_SSH_PORT" >"$provider_file"
  /usr/sbin/sshd -t
  systemctl restart ssh.service
  wait_listen "$GUEST_SSH_PORT"
}

phase_endpoint_positive() {
  local variant="${1-}"
  endpoint_evidence
  snapshot before
  capture preflight "$VH" preflight
  expect_rc preflight 0
  expect_report preflight PASS sshd.endpoint
  snapshot after
  same_snapshot before after
  grep -qx 'port 22' "$phase_dir/sshd-T.txt" || fail 'raw port must remain 22 in explicit-address fixture'
  case "$variant" in
    explicit-address|explicit|environment-listen)
      [ -z "$(ss -H -ltn -6 "sport = :$GUEST_SSH_PORT")" ] || fail 'IPv4-only fixture gained an IPv6 SSH listener'
      expect_report preflight WARN sshd.listen
      ;;
  esac
}

# An actual native-unit/owner fault in an isolated overlay. Keep the existing
# driver session, restore the fixture before it ends, and never count loss of
# driver access as a product rejection.
phase_native_negative() {
  local kind="$1" server='' wrapper=/etc/systemd/system/ssh.service.d/vh-test-wrapper.conf
  local socket_dropin=/etc/systemd/system/ssh.socket.d/vh-test-listen.conf
  cp -p "$provider_file" "$PRIVATE/native-provider.saved"
  native_cleanup() {
    if [ -n "$server" ]; then kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true; fi
    cp -p "$PRIVATE/native-provider.saved" "$provider_file"
    rm -f "$wrapper" "$socket_dropin"
    systemctl daemon-reload
    [ "$kind" = socket ] || systemctl restart ssh.service
  }
  [ ! -e "$wrapper" ] && [ ! -e "$socket_dropin" ] || fail 'native fault fixture already exists'
  trap native_cleanup EXIT
  case "$kind" in
    socket)
      assert_ssh_mode socket
      install -d -m 0755 "${socket_dropin%/*}"
      printf '[Socket]\nListenStream=\nListenStream=%s\n' "$((GUEST_SSH_PORT + 1))" >"$socket_dropin"
      # Deliberately no daemon-reload: persistent and loaded states disagree.
      ;;
    wrapper)
      phase_service_mode
      install -d -m 0755 "${wrapper%/*}"
      printf '[Service]\nExecStart=\nExecStart=/bin/sh -c "exec /usr/sbin/sshd -D"\n' >"$wrapper"
      systemctl daemon-reload
      ;;
    owner)
      phase_service_mode
      printf 'Port %s\n' "$((GUEST_SSH_PORT + 1))" >"$provider_file"
      systemctl restart ssh.service
      wait_listen "$((GUEST_SSH_PORT + 1))"
      # The native daemon remains active on the other port. Disk now expects P,
      # while an unrelated Python process really owns P in the host namespace.
      cp -p "$PRIVATE/native-provider.saved" "$provider_file"
      python3 -m http.server "$GUEST_SSH_PORT" --bind 0.0.0.0 >"$PRIVATE/foreign-listener.log" 2>&1 &
      server=$!
      wait_listen "$GUEST_SSH_PORT"
      ;;
    *) fail "unknown native fault $kind" ;;
  esac
  endpoint_evidence
  snapshot before
  capture preflight "$VH" preflight
  expect_rc preflight 1
  expect_report preflight FAIL sshd.endpoint
  case "$kind" in
    owner) expect_text preflight '管理端点的监听不属于对应 SSH 服务/socket' ;;
    wrapper) expect_text preflight 'SSH 未由已知 sshd 原生入口启动' ;;
    socket) expect_text preflight 'ssh.socket 需要重新加载' ;;
  esac
  capture apply on_tty "$VH" apply
  expect_rc apply 1
  expect_report apply FAIL sshd.endpoint
  snapshot after
  same_snapshot before after
  native_cleanup
  trap - EXIT
}

phase_endpoint_argument() {
  local option_port="$GUEST_SSH_PORT"
  install -d -m 0755 /etc/systemd/system/ssh.service.d
  case "$1" in
    port) printf 'Port 22\n' >"$provider_file" ;;
    explicit)
      printf 'ListenAddress 0.0.0.0:%s\n' "$GUEST_SSH_PORT" >"$provider_file"
      option_port=$((GUEST_SSH_PORT + 1))
      ;;
    unit-port|environment-port|environment-listen) printf 'Port 22\n' >"$provider_file" ;;
    *) fail "unknown startup fixture $1" ;;
  esac
  case "$1" in
    unit-port)
      printf '[Service]\nExecStart=\nExecStart=/usr/sbin/sshd -D -o "Port %s"\n' "$GUEST_SSH_PORT" \
        >/etc/systemd/system/ssh.service.d/vh-test-native.conf
      ;;
    environment-port|environment-listen)
      if [ "$1" = environment-port ]; then
        printf "SSHD_OPTS='-p %s'\n" "$GUEST_SSH_PORT" >/etc/default/vh-test-ssh
      else
        printf "SSHD_OPTS='-o \"ListenAddress 0.0.0.0:%s\"'\n" "$GUEST_SSH_PORT" >/etc/default/vh-test-ssh
      fi
      # shellcheck disable=SC2016 # systemd expands this variable at service start.
      printf '[Service]\nEnvironmentFile=\nEnvironmentFile=/etc/default/vh-test-ssh\nExecStart=\nExecStart=/usr/sbin/sshd -D $SSHD_OPTS\n' \
        >/etc/systemd/system/ssh.service.d/vh-test-native.conf
      ;;
    *)
      printf '[Service]\nExecStart=\nExecStart=/usr/sbin/sshd -D -p %s\n' "$option_port" \
        >/etc/systemd/system/ssh.service.d/vh-test-native.conf
      ;;
  esac
  systemctl daemon-reload
  systemctl restart ssh.service
  wait_listen "$GUEST_SSH_PORT"
}

pending_material() {
  local unit
  sha256sum "$STATE_DIR/state" "$STATE_DIR/pending"
  find "$STATE_DIR/snapshot" "$STATE_DIR/snapshot-ports" -type f -exec sha256sum '{}' + 2>/dev/null | sort || true
  unit="$(awk -F= '$1 == "timer" {print $2}' "$STATE_DIR/pending")"
  systemctl is-active "$unit.timer"
  systemctl is-enabled "$BOOT_UNIT"
  # Active alone cannot detect a silently restarted/extended timer.
  systemctl show "$unit.timer" -p NextElapseUSecMonotonic -p NextElapseUSecRealtime -p TimersMonotonic
}

phase_pending_before() {
  restore_armed
  pending_material >"$PRIVATE/pending-material"
}

phase_pending_same() {
  pending_material >"$phase_dir/pending-material"
  diff -u "$PRIVATE/pending-material" "$phase_dir/pending-material" || fail 'refused confirmation changed recovery material'
  restore_armed
}

phase_drift() {
  local kind="${1:-port}"
  cp -p "$provider_file" "$PRIVATE/provider.saved"
  case "$kind" in
    port) printf 'Port %s\n' "$((GUEST_SSH_PORT + 1))" >"$provider_file" ;;
    address) printf 'Port %s\nListenAddress 127.0.0.1\n' "$GUEST_SSH_PORT" >"$provider_file" ;;
    activation|startup)
      state_value ssh_activation >"$PRIVATE/activation.saved"
      if [ "$kind" = activation ]; then
        [ "$(cat "$PRIVATE/activation.saved")" = socket ] || fail 'activation drift requires a socket baseline'
        phase_service_mode
      else
        [ "$(cat "$PRIVATE/activation.saved")" = service ] || fail 'startup drift requires a service baseline'
        install -d -m 0755 /etc/systemd/system/ssh.service.d
        printf '[Service]\nExecStart=\nExecStart=/usr/sbin/sshd -D -p %s\n' "$((GUEST_SSH_PORT + 1))" \
          >/etc/systemd/system/ssh.service.d/vh-test-activation.conf
        systemctl daemon-reload
      fi
      ;;
    *) fail "unknown drift $kind" ;;
  esac
}

phase_undrift() {
  cp -p "$PRIVATE/provider.saved" "$provider_file"
  if [ -f "$PRIVATE/activation.saved" ]; then
    if [ "$(cat "$PRIVATE/activation.saved")" = socket ]; then
      phase_socket_mode
    else
      rm -f /etc/systemd/system/ssh.service.d/vh-test-activation.conf
      systemctl daemon-reload
    fi
    rm "$PRIVATE/activation.saved"
  fi
}

phase_connection_wrong() {
  local alternate=$((GUEST_SSH_PORT + 1)) master rc=0
  # The additional listener is removed inside the new session. Its established
  # connection survives, so endpoint checking passes while this session's port
  # is wrong. It must reach confirm.connection, not an earlier guard.
  /usr/sbin/sshd -D -f /etc/ssh/sshd_config -p "$alternate" \
    -o "ListenAddress=127.0.0.1:$alternate" -o "PidFile=$PRIVATE/alternate.pid" \
    >"$PRIVATE/alternate.log" 2>&1 &
  master=$!
  wait_listen "$alternate"
  ssh -p "$alternate" -i "$PRIVATE/rsa" -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 root@127.0.0.1 \
    "kill $master; for n in \$(seq 10); do [ -z \"\$(ss -H -ltn 'sport = :$alternate')\" ] && exec $VH confirm; sleep 1; done; exit 90" \
    >"$phase_dir/confirm.out" 2>&1 || rc=$?
  kill "$master" 2>/dev/null || true
  wait "$master" 2>/dev/null || true
  printf '%s\n' "$rc" >"$phase_dir/confirm.rc"
  expect_rc confirm 1
  expect_report confirm FAIL confirm.connection
}

phase_connection_fault() {
  case "$1" in
    on)
      [ ! -e /usr/local/sbin/python3 ] || fail 'connection probe wrapper already exists'
      cat >/usr/local/sbin/python3 <<'EOF'
#!/bin/sh
if [ "${1-}" = - ] && [ "${2-}" = connection ]; then
  printf '无法核实：测试注入的连接归属读取失败\n' >&2
  exit 1
fi
exec /usr/bin/python3 "$@"
EOF
      chmod 0755 /usr/local/sbin/python3
      ;;
    off) rm /usr/local/sbin/python3 ;;
    *) fail "unknown connection fault $1" ;;
  esac
}

phase_restore_fault() {
  local fault="$1" timer rc=0 kind index
  [ ! -e /usr/local/sbin/ss ] || fail 'ss wrapper already exists'
  timer="$(awk -F= '$1 == "timer" {print $2}' "$STATE_DIR/pending")"
  kind="$(awk -F= '$1 == "kind" {print $2}' "$STATE_DIR/pending")"
  index="$STATE_DIR/snapshot/index"
  [ "$kind" != ports ] || index="$STATE_DIR/snapshot-ports/index"
  cp -p "$index" "$PRIVATE/restore-index"
  find "${index%/*}" -type f -exec sha256sum '{}' + | sort >"$PRIVATE/restore-material"
  cp -p "$STATE_DIR/units" "$PRIVATE/restore-units"
  if [ "$kind" = ports ]; then
    cp "$STATE_DIR/snapshot-ports/open" "$PRIVATE/restore-open"
    [ ! -s "$PRIVATE/restore-open" ] || fail 'this fault fixture starts with SSH-only rules'
  fi
  case "$fault" in
    unknown) printf '#!/bin/sh\nexit 1\n' >/usr/local/sbin/ss ;;
    mismatch)
      printf '#!/bin/sh\n/usr/bin/ss "$@" | sed '\''s/:%s /:%s /g'\''\n' \
        "$GUEST_SSH_PORT" "$((GUEST_SSH_PORT + 1))" >/usr/local/sbin/ss ;;
    *) fail "unknown restore fault $fault" ;;
  esac
  chmod 0755 /usr/local/sbin/ss
  "$VH" _restore timeout "$timer" >"$phase_dir/restore.out" 2>&1 || rc=$?
  rm /usr/local/sbin/ss
  printf '%s\n' "$rc" >"$phase_dir/restore.rc"
  expect_rc restore 1
  expect_report restore FAIL restore.endpoint
  assert_restore_effects "$kind" "$index"
  [ "$(state_value status)" = restore-failed ] || fail 'endpoint failure was marked successful'
  [ -e "$STATE_DIR/pending" ] && [ -s "$STATE_DIR/snapshot/index" ] || fail 'recovery materials lost'
  [ "$(systemctl is-enabled "$BOOT_UNIT" 2>/dev/null)" = enabled ] || fail 'boot recovery was disarmed'
  [ -z "$(systemctl list-units --no-legend --state=active 'vps-hardening-timeout-*.timer')" ] || fail 'recovery timer was restarted'
}

assert_restore_effects() {
  local kind="$1" index="$2" unit existed enabled active now_e now_a
  assert_restored_index "$PRIVATE/restore-index"
  find "${index%/*}" -type f -exec sha256sum '{}' + | sort >"$phase_dir/restore-material"
  diff -u "$PRIVATE/restore-material" "$phase_dir/restore-material" || fail 'restore replaced its recovery snapshot'
  if [ "$kind" = ports ]; then
    [ "$(state_value open)" = "$(cat "$PRIVATE/restore-open")" ] || fail 'port declaration not restored before endpoint failure'
    ufw_rules_are
  else
    grep -qx 'Status: inactive' <<<"$(ufw status)" || fail 'UFW was not disabled before endpoint failure'
    [ -s "$STATE_DIR/units" ] || fail 'original unit record is missing'
    while read -r unit existed enabled active; do
      read -r _ now_e now_a < <(unit_state "$unit")
      printf '%s %s %s\n' "$unit" "$now_e" "$now_a" >>"$phase_dir/restored-units.txt"
      if [ "$existed" = no ]; then
        case "$now_e" in absent|disabled) ;; *) fail "$unit was introduced but remains enabled" ;; esac
        [ "$now_a" != active ] || fail "$unit was introduced but still runs"
      else
        [ "$now_e" = "$enabled" ] && [ "$now_a" = "$active" ] || fail "$unit was not restored before endpoint failure"
      fi
    done <"$PRIVATE/restore-units"
  fi
  assert_ssh_mode
}

recovery_inventory() {
  local directory directories=(/etc/systemd/system)
  for directory in /run/systemd/system /run/systemd/transient; do
    [ ! -d "$directory" ] || directories+=("$directory")
  done
  find "${directories[@]}" -path '*vps-hardening*' -printf '%y %p -> %l\n' | sort
}

phase_manual_restore_fault() {
  case "$1" in
    on)
      [ "$(state_value status)" = applied ] || fail 'manual fault needs a confirmed applied state'
      no_restore_armed
      ! systemctl is-active --quiet "$BOOT_UNIT" || fail 'manual fixture already has running boot recovery'
      [ ! -e /usr/local/sbin/ss ] || fail 'ss wrapper already exists'
      [ "$(awk '$NF == "/etc/ssh/sshd_config.d/00-vps-hardening.conf" {print $2}' "$STATE_DIR/snapshot/index")" = absent ] ||
        fail 'manual fixture expects restore to remove the managed sshd drop-in'
      cp -p "$STATE_DIR/snapshot/index" "$PRIVATE/restore-index"
      cp -p "$STATE_DIR/units" "$PRIVATE/restore-units"
      find "$STATE_DIR/snapshot" -type f -exec sha256sum '{}' + | sort >"$PRIVATE/restore-material"
      recovery_inventory >"$PRIVATE/recovery-before"
      file_sha "/etc/systemd/system/$BOOT_UNIT" >"$PRIVATE/boot-before"
      cat >/usr/local/sbin/ss <<'EOF'
#!/bin/sh
# Pre-rollback endpoint checks see the real sockets. Once snapshot restoration
# removes the managed auth fragment, only the final runtime read fails.
if [ ! -e /etc/ssh/sshd_config.d/00-vps-hardening.conf ]; then
  printf '无法核实：恢复后的读取故障\n' >&2
  exit 1
fi
exec /usr/bin/ss "$@"
EOF
      chmod 0755 /usr/local/sbin/ss
      ;;
    check)
      rm /usr/local/sbin/ss
      assert_restore_effects apply "$STATE_DIR/snapshot/index"
      [ "$(state_value status)" = restore-failed ] || fail 'manual endpoint failure was marked successful'
      [ ! -e "$STATE_DIR/pending" ] || fail 'manual failure invented pending state'
      no_restore_armed
      ! systemctl is-active --quiet "$BOOT_UNIT" || fail 'manual failure started the boot recovery unit'
      recovery_inventory >"$phase_dir/recovery-after"
      [ -z "$(comm -13 "$PRIVATE/recovery-before" "$phase_dir/recovery-after")" ] || fail 'manual failure created a recovery unit, even if inactive'
      file_sha "/etc/systemd/system/$BOOT_UNIT" >"$phase_dir/boot-after"
      diff -u "$PRIVATE/boot-before" "$phase_dir/boot-after" || fail 'manual failure created or rewrote boot recovery'
      ;;
    *) fail "unknown manual recovery fault $1" ;;
  esac
}

assert_restored_index() {
  local _i kind digest meta path
  [ -s "$1" ] || fail 'empty expected recovery index'
  while read -r _i kind digest meta path; do
    if [ "$kind" = absent ]; then
      [ ! -e "$path" ] || fail "$path was not removed during recovery"
    else
      [ "$(file_sha "$path")" = "$digest" ] || fail "$path was not restored before reporting endpoint failure"
      [ "$(stat -c '%a:%u:%g' "$path")" = "$meta" ] || fail "$path recovery metadata differs"
    fi
  done <"$1"
}

phase_record() {
  local field
  [ "$(state_value ssh_port)" = "$GUEST_SSH_PORT" ] || fail 'recorded P differs from guest listener'
  for field in ssh_activation ssh_listeners; do
    [ -n "$(state_value "$field")" ] || fail "$field is missing"
  done
  [ "$(state_value ssh_activation)" = "$GUEST_SSH_MODE" ] || fail 'recorded activation differs from the required fixture'
  assert_ssh_mode
  endpoint_evidence
  capture verify "$VH" verify
  expect_rc verify 0
  capture status "$VH" status
  expect_rc status 0
  expect_text status '<公网SSH端口>'
  ufw_rules_are
}

phase_record_corrupt() {
  cp -p "$STATE_DIR/state" "$PRIVATE/state.saved"
  case "$1" in
    partial) sed '/^ssh_listeners=/d' "$PRIVATE/state.saved" >"$STATE_DIR/state" ;;
    invalid) sed 's/^ssh_port=.*/ssh_port=65536/' "$PRIVATE/state.saved" >"$STATE_DIR/state" ;;
    unknown) sed 's/^version=.*/version=unknown/' "$PRIVATE/state.saved" >"$STATE_DIR/state" ;;
    missing) sed '/^ssh_port=/d; /^ssh_activation=/d; /^ssh_listeners=/d' "$PRIVATE/state.saved" >"$STATE_DIR/state" ;;
    *) fail "unknown record fault $1" ;;
  esac
  sha256sum "$STATE_DIR/state" >"$PRIVATE/corrupt-state"
  tool_record >"$PRIVATE/corrupt-material"
}

phase_record_unchanged() {
  sha256sum "$STATE_DIR/state" >"$phase_dir/corrupt-state"
  diff -u "$PRIVATE/corrupt-state" "$phase_dir/corrupt-state" || fail 'rejected malformed record was rewritten before fixture repair'
  tool_record >"$phase_dir/corrupt-material"
  diff -u "$PRIVATE/corrupt-material" "$phase_dir/corrupt-material" || fail 'rejected malformed record changed managed material'
}

phase_readonly_before() {
  snapshot before
  cp "$phase_dir/snap-before.txt" "$PRIVATE/readonly-before"
  tool_record >"$PRIVATE/readonly-material"
}
phase_readonly_same() {
  snapshot after
  diff -u "$PRIVATE/readonly-before" "$phase_dir/snap-after.txt" || fail 'read-only rejection changed the host'
  tool_record >"$phase_dir/readonly-material"
  diff -u "$PRIVATE/readonly-material" "$phase_dir/readonly-material" || fail 'read-only rejection changed tool records'
}

phase_legacy_fields() {
  ! grep -qE '^ssh_(port|activation|listeners)=' "$STATE_DIR/state" || fail 'old state acquired new fields before rollback and reapply'
}

phase_protected_remove() {
  tool_record >"$phase_dir/before"
  capture remove-ssh on_tty "$VH" ports --remove "$GUEST_SSH_PORT/tcp"
  expect_rc remove-ssh 2
  expect_text remove-ssh "$GUEST_SSH_PORT 端口总是放行，不能撤销"
  tool_record >"$phase_dir/after"
  diff -u "$phase_dir/before" "$phase_dir/after" || fail 'refusing SSH removal changed the host'
}

phase_record_restore() { cp -p "$PRIVATE/state.saved" "$STATE_DIR/state"; }

phase_service_mode() {
  if systemctl cat ssh.socket >/dev/null 2>&1; then
    systemctl stop ssh.socket
    systemctl disable ssh.socket
  fi
  systemctl enable ssh.service
  systemctl daemon-reload
  systemctl restart ssh.service
  wait_listen "$GUEST_SSH_PORT"
  printf 'service\n' >"$PRIVATE/ssh-mode"
  assert_ssh_mode service
}

phase_socket_mode() {
  systemctl stop ssh.service
  systemctl stop ssh.socket
  systemctl enable ssh.socket
  systemctl daemon-reload
  systemctl start ssh.socket
  systemctl start ssh.service
  wait_listen "$GUEST_SSH_PORT"
  printf 'socket\n' >"$PRIVATE/ssh-mode"
  assert_ssh_mode socket
}

phase_role_port() {
  local target="$1" rc=0
  phase_service_mode
  cp -p "$provider_file" "$PRIVATE/role-provider.saved"
  # The runner's already established control session survives the listener
  # change. Product operations use fresh root sessions to the new local P.
  # This is a local fixture, not evidence of provider-side NAT.
  role_cleanup() {
    cp -p "$PRIVATE/role-provider.saved" "$provider_file"
    systemctl restart ssh.service
    if command -v ufw >/dev/null; then ufw --force disable >/dev/null; fi
  }
  trap role_cleanup EXIT
  printf 'Port %s\n' "$target" >"$provider_file"
  systemctl restart ssh.service
  wait_listen "$target"
  # SSH options must precede destination, so remote command is supplied here.
  role_command() {
    local command="$1" tty="${2-}" options=()
    [ -z "$tty" ] || options=(-tt)
    ssh -p "$target" -i "$PRIVATE/rsa" -o IdentitiesOnly=yes -o BatchMode=yes \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
      "${options[@]}" root@127.0.0.1 "$command"
  }
  if [ "$target" = 80 ]; then
    snapshot port80-before
    capture port80 role_command "$VH preflight"
    expect_rc port80 1
    expect_report port80 FAIL sshd.endpoint
    capture port80-apply role_command "$VH apply" tty
    expect_rc port80-apply 1
    expect_report port80-apply FAIL sshd.endpoint
    snapshot port80-after
    same_snapshot port80-before port80-after
  else
    snapshot conflict-before
    capture panel-conflict role_command "$VH preflight --panel-port $target"
    expect_rc panel-conflict 2
    capture business-conflict role_command "$VH preflight --open $target/udp"
    expect_rc business-conflict 2
    snapshot conflict-after
    same_snapshot conflict-before conflict-after
    printf 'yes\n' | role_command "$VH apply" tty >"$phase_dir/apply.out" 2>&1 || rc=$?
    printf '%s\n' "$rc" >"$phase_dir/apply.rc"
    expect_rc apply 0
    expect_text apply '加固已应用，等待确认'
    [ "$(state_value ssh_port)" = "$target" ] || fail 'role port was not recorded'
    capture confirm role_command "$VH confirm"
    expect_rc confirm 0
    capture protected role_command "$VH ports --add $target/tcp" tty
    expect_rc protected 2
    rc=0
    printf 'yes\n' | role_command "$VH rollback" tty >"$phase_dir/rollback.out" 2>&1 || rc=$?
    printf '%s\n' "$rc" >"$phase_dir/rollback.rc"
    expect_rc rollback 0
  fi
  role_cleanup
  trap - EXIT
}

fixture_installer() {
  local source="$1" rel="$2" installer="$3" digest
  install -d -m 0755 "$rel"
  install -m 0755 "$source/bin/vps-hardening" "$rel/vps-hardening"
  install -m 0644 -t "$rel" "$source"/lib/vps-hardening/*.sh
  (cd "$rel" && sha256sum vps-hardening ./*.sh | sed 's|  \./|  |' >SHA256SUMS)
  digest="$(sha256sum <"$rel/SHA256SUMS" | awk '{print $1}')"
  sed "s/^EXPECTED_MANIFEST_SHA256=''\$/EXPECTED_MANIFEST_SHA256='$digest'/" "$source/install.sh" >"$installer"
}

phase_legacy_install() {
  [ "$GUEST_SSH_PORT" = 22 ] || fail 'real old tool only supports guest port 22'
  fixture_installer "$BUNDLE/fixtures/legacy" /root/vh-release-old /root/vh-install-old.sh
  expect_install old-install 0 '安装完成' /root/vh-install-old.sh --source-dir /root/vh-release-old
  fixture_installer "$BUNDLE" /root/vh-release-new /root/vh-install-new.sh
  capture old-version "$INSTALLED_BIN" --version
  expect_text old-version 'vps-hardening 0.1.2'
}

phase_legacy_blocked() {
  installed_record >"$phase_dir/installed-before"
  pending_material >"$phase_dir/pending-before"
  expect_install new-install 1 '有待确认的变更' /root/vh-install-new.sh --source-dir /root/vh-release-new
  installed_record >"$phase_dir/installed-after"
  pending_material >"$phase_dir/pending-after"
  diff -u "$phase_dir/installed-before" "$phase_dir/installed-after" || fail 'refused upgrade replaced old tool'
  diff -u "$phase_dir/pending-before" "$phase_dir/pending-after" || fail 'refused upgrade altered recovery'
}

phase_legacy_upgrade() {
  [ ! -e "$STATE_DIR/pending" ] || fail 'pending before supported upgrade'
  sha256sum "$STATE_DIR/state" >"$phase_dir/state-before"
  expect_install new-install 0 '安装完成' /root/vh-install-new.sh --source-dir /root/vh-release-new
  capture verify "$INSTALLED_BIN" verify
  expect_rc verify 0
  capture status "$INSTALLED_BIN" status
  expect_rc status 0
  sha256sum "$STATE_DIR/state" >"$phase_dir/state-after"
  diff -u "$phase_dir/state-before" "$phase_dir/state-after" || fail 'read-only legacy compatibility rewrote state'
  ! grep -q '^ssh_port=' "$STATE_DIR/state" || fail 'old state acquired new fields without rollback'
}

non22_main() {
  local phase="${1-}" label word
  shift
  [ "$(id -u)" -eq 0 ] || fail 'run as root'
  label="$phase"
  for word in "$@"; do label="$label-$word"; done
  phase_dir="$EVIDENCE/non22-$label"
  install -d -m 0700 "$phase_dir"
  case "$phase" in
    endpoint-cases) phase_endpoint_cases ;;
    endpoint-explicit) phase_endpoint_explicit ;;
    endpoint-positive) phase_endpoint_positive "$@" ;;
    endpoint-argument) phase_endpoint_argument "$@" ;;
    native-negative) phase_native_negative "$@" ;;
    pending-before) phase_pending_before ;;
    pending-same) phase_pending_same ;;
    drift) phase_drift "$@" ;;
    undrift) phase_undrift ;;
    connection-wrong) phase_connection_wrong ;;
    connection-fault) phase_connection_fault "$@" ;;
    restore-fault) phase_restore_fault "$@" ;;
    manual-restore-fault) phase_manual_restore_fault "$@" ;;
    record) phase_record ;;
    record-corrupt) phase_record_corrupt "$@" ;;
    record-unchanged) phase_record_unchanged ;;
    record-restore) phase_record_restore ;;
    service-mode) phase_service_mode ;;
    protected-remove) phase_protected_remove ;;
    readonly-before) phase_readonly_before ;;
    readonly-same) phase_readonly_same ;;
    role-port) phase_role_port "$@" ;;
    legacy-install) phase_legacy_install ;;
    legacy-blocked) phase_legacy_blocked ;;
    legacy-upgrade) phase_legacy_upgrade ;;
    legacy-fields) phase_legacy_fields ;;
    *) fail "unknown phase $phase" ;;
  esac
  log "non22 $phase passed"
}

non22_main "$@"
