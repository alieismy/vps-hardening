#!/usr/bin/env bash
# D64: execute the real confirm/restore control flow with filesystem/service
# adapters confined to a private fixture. This is not a Linux/SSH runtime test.
# shellcheck source-path=SCRIPTDIR/../lib/vps-hardening
set -Eeuo pipefail
cd "${BASH_SOURCE[0]%/*}/.."
# shellcheck source=common.sh
. lib/vps-hardening/common.sh
# shellcheck source=pending.sh
. lib/vps-hardening/pending.sh
# shellcheck source=rollback.sh
. lib/vps-hardening/rollback.sh
# shellcheck source=apply.sh
. lib/vps-hardening/apply.sh
# shellcheck source=ports.sh
. lib/vps-hardening/ports.sh

test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
export VH_TEST_TRACE VH_TEST_STATE VH_TEST_PENDING VH_TEST_TEMP
VH_SELF="$test_root/verify"
cat >"$VH_SELF" <<'EOF'
#!/usr/bin/env bash
[ "$1" = verify ] || exit 10
grep -qx 'status=applied' "$VH_TEST_STATE" || exit 11
[ ! -e "$VH_TEST_PENDING" ] || exit 12
[ ! -e "$VH_TEST_TEMP" ] || exit 13
printf 'verify\n' >>"$VH_TEST_TRACE"
EOF
chmod 0755 "$VH_SELF"

fixture() {
  local name="$1"
  case_root="$test_root/$name"
  mkdir -p "$case_root/snapshot" "$case_root/snapshot-ports"
  VH_STATE_FILE="$case_root/state"
  VH_PENDING_FILE="$case_root/pending"
  VH_SNAPSHOT_DIR="$case_root/snapshot"
  VH_PORTS_SNAPSHOT_DIR="$case_root/snapshot-ports"
  VH_LOG_FILE="$case_root/log"
  VH_TMP="$case_root/tmp"
  VH_TEST_TRACE="$case_root/trace"
  VH_TEST_STATE="$VH_STATE_FILE" VH_TEST_PENDING="$VH_PENDING_FILE" VH_TEST_TEMP="$VH_TMP"
  printf 'status=pending\nopen=\nufw_was_active=no\n' >"$VH_STATE_FILE"
  printf 'kind=apply\nsession=1\n' >"$VH_PENDING_FILE"
  printf '\n' >"$VH_PORTS_SNAPSHOT_DIR/open"
  touch "$VH_TEST_TRACE" "$case_root/timer" "$case_root/boot"
  VH_SSHD_ARGS=()
  VH_SSH_PORT=2222 VH_SSH_ACTIVATION=service VH_SSH_LISTENERS='ipv4,0.0.0.0,2222'
  SSH_TEST_ENDPOINT=pass SSH_TEST_CONNECTION=pass
  SSH_TEST_UNITS_FAIL=no
  SSH_TEST_LEGACY=no
}

event() { printf '%s\n' "$*" >>"$VH_TEST_TRACE"; }
assert() { "$@" || { printf '[x] assertion failed: %s\n' "$*" >&2; exit 1; }; }
id() { printf '0\n'; }
vh_tmp_init() { mkdir -p "$VH_TMP"; }
vh_lock() { event lock; }
own_loginuid() { printf '0\n'; }
own_sessionid() { printf '2\n'; }
session_from_sshd() { event ssh-session; }
utc_now() { printf '2026-11-03T00:00:00Z\n'; }
vh_log() { event "log $*"; }
state_get() {
  awk -F= -v key="$1" '$1 == key {print substr($0,index($0,"=")+1)}' "${2:-$VH_STATE_FILE}"
}
state_set() {
  event "state $1 $2"
  awk -F= -v key="$1" '$1 != key' "$VH_STATE_FILE" >"$case_root/new-state"
  printf '%s=%s\n' "$1" "$2" >>"$case_root/new-state"
  mv "$case_root/new-state" "$VH_STATE_FILE"
}
ssh_endpoint_check_record() {
  event endpoint-check
  VH_SSH_LEGACY="$SSH_TEST_LEGACY"
  # Restoring the legacy managed jail removes the runtime evidence that was
  # available before restoration. The proven baseline must survive in memory.
  if [ "$SSH_TEST_LEGACY" = yes ] && grep -qx files "$VH_TEST_TRACE"; then
    VH_SSH_ERROR='无法核实：旧 jail 已恢复为不存在'
    return 1
  fi
  case "$SSH_TEST_ENDPOINT" in
    pass) return 0 ;;
    mismatch) VH_SSH_ERROR='不一致：端点与记录不同' ;;
    unknown) VH_SSH_ERROR='无法核实：读取超时' ;;
  esac
  return 1
}
ssh_endpoint_discover() { event discover; [ "$SSH_TEST_ENDPOINT" = pass ]; }
ssh_endpoint_report() {
  event endpoint
  if ssh_endpoint_check_record; then report PASS "$1" 'fixture endpoint'; else report FAIL "$1" "$VH_SSH_ERROR"; return 1; fi
}
ssh_confirm_connection() { event connection; [ "$SSH_TEST_CONNECTION" = pass ]; }
disarm_triggers() { event disarm; rm -f "$case_root/timer" "$case_root/boot"; }
disarm_restore() { disarm_triggers; rm -f "$VH_PENDING_FILE"; }
print_tunnel_hint() { event tunnel; }
sync() { :; }
have() { return 1; }
stop_timers() { event stop-timers; rm -f "$case_root/timer"; }
snapshot_restore() { event files; }
bounded() { event sshd-syntax; }
bounded_change() { event "change $*"; }
ssh_startup_probe() { event startup-options; }
sshd_cache_clear() { :; }
restore_units() { event units; [ "$SSH_TEST_UNITS_FAIL" = no ]; }
record_digest() { event "digest $1"; }

# A separate shell keeps the real main-shell ERR guard intact. Both the known
# failure entry and the owning command's ERR handler must preserve exit 1/3
# even when the real restore control flow reports an endpoint failure.
if [ "${1-}" = --failure-case ]; then
  operation="$2" failure="$3" SSH_TEST_ENDPOINT="$4"
  fixture "failure-$operation-$failure-$SSH_TEST_ENDPOINT"
  SSH_TEST_ENDPOINT="$4"
  if [ "$operation" = ports ]; then
    sed -i 's/status=pending/status=ports-pending/' "$VH_STATE_FILE"
    sed -i 's/kind=apply/kind=ports/' "$VH_PENDING_FILE"
  fi
  VH_APPLY_STAGE=changing VH_PORTS_STAGE=changing
  # Read by the owning ERR handler loaded below from bin/vps-hardening.
  # shellcheck disable=SC2034
  VH_ABORT_HOOK="${operation}_abort"
  expected_exit=1
  [ "$failure" != internal ] || expected_exit=3
  # Invoked by this worker's EXIT trap, including an exit from the ERR handler.
  # shellcheck disable=SC2329
  check_failed_restore_exit() {
    local actual=$?
    trap - EXIT
    if [ "$actual" = "$expected_exit" ] && [ "$(state_get status)" = restore-failed ] &&
        [ -e "$VH_PENDING_FILE" ] && [ -e "$case_root/boot" ] && [ ! -e "$case_root/timer" ] &&
        grep -qx files "$VH_TEST_TRACE" && ! grep -qx disarm "$VH_TEST_TRACE"; then
      rm -rf -- "$test_root"
      exit 0
    fi
    printf '[x] failure/restore exit contract failed: got %s expected %s; evidence %s\n' \
      "$actual" "$expected_exit" "$test_root" >&2
    exit 1
  }
  trap check_failed_restore_exit EXIT
  # Read the owning function only, without dispatching the product CLI.
  # shellcheck source=/dev/null
  . <(sed -n '/^vh_on_error() {$/,/^}$/p' bin/vps-hardening)
  trap 'vh_on_error "$?" fixture "$BASH_COMMAND"' ERR
  if [ "$failure" = internal ]; then
    false
  else
    "${operation}_fail" fixture
  fi
  exit 99
fi

for state in pending ports-pending; do
  for failure in endpoint connection; do
    fixture "confirm-$state-$failure"
    [ "$state" != ports-pending ] || { sed -i 's/pending/ports-pending/' "$VH_STATE_FILE"; sed -i 's/kind=apply/kind=ports/' "$VH_PENDING_FILE"; }
    cp "$VH_STATE_FILE" "$case_root/state-before"
    cp "$VH_PENDING_FILE" "$case_root/pending-before"
    [ "$failure" != endpoint ] || SSH_TEST_ENDPOINT=unknown
    [ "$failure" != connection ] || SSH_TEST_CONNECTION=unknown
    rc=0
    # shellcheck disable=SC2119 # confirm deliberately receives no CLI arguments.
    (cmd_confirm) >"$case_root/output" 2>&1 || rc=$?
    assert test "$rc" = 1
    assert cmp "$case_root/state-before" "$VH_STATE_FILE"
    assert cmp "$case_root/pending-before" "$VH_PENDING_FILE"
    assert test -e "$case_root/timer"
    assert test -e "$case_root/boot"
    assert test -d "$VH_PORTS_SNAPSHOT_DIR"
    assert grep -q "\[FAIL\] confirm\.$failure" "$case_root/output"
    assert test "$(grep -c '^disarm$' "$VH_TEST_TRACE" || true)" = 0
  done
  fixture "confirm-$state-pass"
  [ "$state" != ports-pending ] || { sed -i 's/pending/ports-pending/' "$VH_STATE_FILE"; sed -i 's/kind=apply/kind=ports/' "$VH_PENDING_FILE"; }
  # shellcheck disable=SC2119 # confirm deliberately receives no CLI arguments.
  (cmd_confirm) >"$case_root/output" 2>&1
  assert grep -qx applied <(state_get status)
  assert test ! -e "$VH_PENDING_FILE"
  assert test "$(grep -E '^(endpoint|connection|disarm|verify)$' "$VH_TEST_TRACE" | paste -sd ',')" = endpoint,connection,disarm,verify
done

for kind in all ports; do
  for mode in runtime boot; do
    for endpoint in pass mismatch unknown; do
      fixture "restore-$kind-$mode-$endpoint"
      SSH_TEST_ENDPOINT="$endpoint"
      rc=0
      "restore_$kind" "$mode" test >"$case_root/output" 2>&1 || rc=$?
      if [ "$mode" = boot ] || [ "$endpoint" = pass ]; then
        assert test "$rc" = 0
        assert test ! -e "$VH_PENDING_FILE"
        want=rolled-back
        [ "$kind" != ports ] || want=applied
        assert test "$(state_get status)" = "$want"
        order="$(grep -E '^(files|units|endpoint-check|disarm)$' "$VH_TEST_TRACE" | paste -sd ',')"
        if [ "$mode" = runtime ]; then
          expected='endpoint-check,files,units,endpoint-check,disarm'
          [ "$kind" != ports ] || expected='endpoint-check,files,endpoint-check,disarm'
        else
          expected='files,units,disarm'
          [ "$kind" != ports ] || expected='files,disarm'
        fi
        assert test "$order" = "$expected"
        if [ "$mode" = boot ]; then assert grep -q '\[SKIP\] restore.endpoint' "$case_root/output"; fi
      else
        assert test "$rc" = 1
        assert test "$(state_get status)" = restore-failed
        assert test -e "$VH_PENDING_FILE"
        assert test -e "$case_root/boot"
        assert test ! -e "$case_root/timer"
        assert test -d "$VH_PORTS_SNAPSHOT_DIR"
        assert grep -qx files "$VH_TEST_TRACE"
        assert grep -q '\[FAIL\] restore.endpoint' "$case_root/output"
        assert test "$(grep -c '^disarm$' "$VH_TEST_TRACE" || true)" = 0
      fi
    done
  done
done

# A manual rollback without pending never invents a boot fallback after an
# endpoint failure; it still performs file and service restoration.
fixture manual-no-pending
rm "$VH_PENDING_FILE" "$case_root/timer" "$case_root/boot"
SSH_TEST_ENDPOINT=unknown
rc=0
restore_all runtime test >"$case_root/output" 2>&1 || rc=$?
assert test "$rc" = 1
assert test ! -e "$VH_PENDING_FILE"
assert test ! -e "$case_root/boot"
assert grep -qx files "$VH_TEST_TRACE"
assert grep -qx units "$VH_TEST_TRACE"

for failure in no yes; do
  fixture "prepare-$failure"
  rm "$VH_PENDING_FILE" "$case_root/timer" "$case_root/boot"
  printf 'status=applying\n' >"$VH_STATE_FILE"
  touch "$VH_SNAPSHOT_DIR/index"
  SSH_TEST_UNITS_FAIL="$failure"
  rc=0
  (rollback_prepare <<<yes) >"$case_root/output" 2>&1 || rc=$?
  if [ "$failure" = no ]; then
    assert test "$rc" = 0
    assert test "$(state_get status)" = rolled-back
  else
    assert test "$rc" = 1
    assert test "$(state_get status)" = applying
    assert test -e "$VH_SNAPSHOT_DIR/index"
    SSH_TEST_UNITS_FAIL=no
    (rollback_prepare <<<yes) >"$case_root/retry-output" 2>&1
    assert test "$(state_get status)" = rolled-back
  fi
  assert test ! -e "$VH_PENDING_FILE"
  assert test ! -e "$case_root/boot"
  assert test "$(grep -Ec '^(files|endpoint-check|startup-options|sshd-syntax|change |disarm)' "$VH_TEST_TRACE" || true)" = 0
done

fixture legacy-baseline
SSH_TEST_LEGACY=yes
VH_SSH_PORT=22 VH_SSH_LISTENERS='ipv4,0.0.0.0,22'
restore_all runtime test >"$case_root/output" 2>&1
assert test "$(state_get status)" = rolled-back
assert test "$(grep -c '^endpoint-check$' "$VH_TEST_TRACE")" = 1
assert grep -qx discover "$VH_TEST_TRACE"
assert test ! -e "$VH_PENDING_FILE"
for operation in apply ports; do
  for failure in known internal; do
    for endpoint in mismatch unknown; do
      bash tests/test_lifecycle.sh --failure-case "$operation" "$failure" "$endpoint" \
        >"$test_root/$operation-$failure-$endpoint.out" 2>&1 || {
          cat "$test_root/$operation-$failure-$endpoint.out" >&2
          exit 1
        }
    done
  done
done
# Run the real rule check against private files; only its fixed directory is
# substituted. IPv6 uses a different UFW chain even on an IPv4-only host.
(
  case_root="$test_root/ufw-rules"
  mkdir -p "$case_root"
  rule_check="$(declare -f ufw_ssh_rules_ready)"
  eval "${rule_check//\/etc\/ufw/$case_root}"
  for VH_SSH_PORT in 22 2222; do
    printf '%s\n' "-A ufw-user-input -p tcp --dport $VH_SSH_PORT -j ACCEPT" >"$case_root/user.rules"
    printf '%s\n' "-A ufw6-user-input -p tcp --dport $VH_SSH_PORT -j ACCEPT" >"$case_root/user6.rules"
    assert ufw_ssh_rules_ready
    printf '%s\n' "-A ufw-user-input -p tcp --dport $VH_SSH_PORT -j ACCEPT" >"$case_root/user6.rules"
    if ufw_ssh_rules_ready; then exit 1; fi
    printf '%s\n' "-A ufw6-user-input -p tcp --dport $VH_SSH_PORT -s ::1 -j ACCEPT" >"$case_root/user6.rules"
    if ufw_ssh_rules_ready; then exit 1; fi
    printf '%s\n' "-A ufw6-user-input -p tcp --dport 2223 -j ACCEPT" >"$case_root/user6.rules"
    if ufw_ssh_rules_ready; then exit 1; fi
  done
)
printf '[+] lifecycle decisions: 6 confirm + 12 restore + no-pending + 3 preparation + legacy recovery + 8 failure exits passed; UFW dual-family rules passed at P=22/2222\n'
