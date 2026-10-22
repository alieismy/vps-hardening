# shellcheck shell=bash
# The confirmation window (FR-05, design 7.5): arming the automatic restore,
# confirm, and the restores shared by timeout, reboot, failures and rollback.
# A pending change is of one of two kinds, recorded in the marker: apply (undo
# all of it) or ports (undo the port change only, FR-14).

readonly VH_BOOT_UNIT=vps-hardening-rollback.service
readonly VH_BOOT_UNIT_FILE="/etc/systemd/system/$VH_BOOT_UNIT"
readonly VH_TIMER_PREFIX=vps-hardening-timeout
# The kernel's value for "no audit session" in /proc/<pid>/sessionid and loginuid.
readonly VH_AUDIT_UNSET=4294967295

# What restore_all could not undo, empty when it fully succeeded.
RESTORE_FAILED=''

# Audit login UID and session ID of this process, set by pam_loginuid at login
# and kept across sudo and su.
own_loginuid() {
  cat "/proc/$$/loginuid"
}

own_sessionid() {
  cat "/proc/$$/sessionid"
}

# True when an ancestor of this shell is an sshd process: sshd on OpenSSH 9.6
# and earlier, sshd-session from 9.8 (Debian 13).
session_from_sshd() {
  local pid="$$" name ppid
  while [ "$pid" -gt 1 ]; do
    name="$(awk '$1 == "Name:" { print $2 }' "/proc/$pid/status" 2>/dev/null)" || return 1
    case "$name" in
      sshd | sshd-session) return 0 ;;
    esac
    ppid="$(awk '$1 == "PPid:" { print $2 }' "/proc/$pid/status" 2>/dev/null)" || return 1
    [[ "$ppid" =~ ^[0-9]+$ ]] || return 1
    pid="$ppid"
  done
  return 1
}

boot_unit_content() {
  cat <<EOF
# Managed by vps-hardening. Enabled only while a change awaits confirmation.
[Unit]
Description=vps-hardening: restore the previous configuration after a reboot before confirmation
DefaultDependencies=no
ConditionPathExists=$VH_PENDING_FILE
RequiresMountsFor=$VH_STATE_DIR ${VH_SELF%/*} $VH_LIB_DIR
After=local-fs.target
Before=sysinit.target ssh.service ssh.socket ufw.service fail2ban.service network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
ExecStart=$VH_SELF _restore boot

[Install]
WantedBy=sysinit.target
EOF
}

# Systemd units call the tool by this path while a change is pending.
check_self_path() {
  [[ "$VH_SELF" =~ ^/[A-Za-z0-9._/-]+$ ]] || refuse "本工具的路径含特殊字符，无法写入 systemd 单元：$VH_SELF"
}

# start_timer SECONDS: a transient timer that restores unless confirmed.
# Prints the unit name; each arming gets a new name, so a restore started by
# an earlier timer can tell that it has been replaced.
start_timer() {
  local unit
  unit="$VH_TIMER_PREFIX-$(date +%s%N)-$$"
  bounded_change systemd-run --quiet --unit="$unit" --collect \
    --description='vps-hardening: restore the previous configuration unless confirmed' \
    --on-active="$1s" --timer-property=AccuracySec=1s \
    -- "$VH_SELF" _restore timeout "$unit" >/dev/null
  printf '%s\n' "$unit"
}

stop_timers() {
  bounded_change systemctl stop "$VH_TIMER_PREFIX-*.timer" >/dev/null 2>&1
}

# arm_restore SECONDS KIND: step 6 of apply, and the same for ports: marker,
# boot unit, then timer. Each must work before the first change. Called in a
# condition, so each result is checked explicitly; a timer whose name the
# marker does not hold would skip the restore. VH_APPLY_SESSION is the session
# that makes the change, which confirm must not be.
arm_restore() {
  local timeout_s="$1" unit deadline
  deadline=$(($(date +%s) + timeout_s))
  : >"$VH_PENDING_FILE"
  state_set kind "$2" "$VH_PENDING_FILE"
  state_set session "$VH_APPLY_SESSION" "$VH_PENDING_FILE"
  state_set deadline "$deadline" "$VH_PENDING_FILE"
  if [ ! -f "$VH_BOOT_UNIT_FILE" ] || [ "$(boot_unit_content)" != "$(cat "$VH_BOOT_UNIT_FILE")" ]; then
    boot_unit_content >"$VH_BOOT_UNIT_FILE.new"
    chmod 0644 "$VH_BOOT_UNIT_FILE.new"
    mv -f -- "$VH_BOOT_UNIT_FILE.new" "$VH_BOOT_UNIT_FILE"
    bounded_change systemctl daemon-reload
  fi
  bounded_change systemctl enable --quiet "$VH_BOOT_UNIT"
  unit_enabled "$VH_BOOT_UNIT" || return 1
  unit="$(start_timer "$timeout_s")"
  systemctl is-active --quiet "$unit.timer" || return 1
  state_set timer "$unit" "$VH_PENDING_FILE"
  [ "$(state_get timer "$VH_PENDING_FILE")" = "$unit" ]
}

# Step 10 of apply: give the administrator the full confirmation time. The
# new timer starts before the old one stops, so one is always running.
rearm_timer() {
  local timeout_s="$1" old unit
  old="$(state_get timer "$VH_PENDING_FILE")"
  unit="$(start_timer "$timeout_s")"
  systemctl is-active --quiet "$unit.timer" || return 1
  state_set timer "$unit" "$VH_PENDING_FILE"
  [ "$(state_get timer "$VH_PENDING_FILE")" = "$unit" ] || return 1
  state_set deadline "$(($(date +%s) + timeout_s))" "$VH_PENDING_FILE"
  bounded_change systemctl stop "$old.timer" >/dev/null 2>&1 || true
}

# disarm_restore [boot]: stop the timers, disable the boot unit, remove the
# marker. At boot no timer exists and the manager is not reloaded: only the
# symlink changes, which matters from the next boot on. An apply interrupted
# before step 6 never wrote the unit, and disabling a missing unit fails.
disarm_restore() {
  local errors=0 nr=()
  if [ "${1-}" = boot ]; then
    nr=(--no-reload)
  else
    stop_timers || true
  fi
  if [ -e "$VH_BOOT_UNIT_FILE" ]; then
    bounded_change systemctl "${nr[@]}" disable --quiet "$VH_BOOT_UNIT" >/dev/null 2>&1 || errors=$((errors + 1))
  fi
  rm -f -- "$VH_PENDING_FILE" || errors=$((errors + 1))
  sync
  [ "$errors" -eq 0 ]
}

# Put unit enablement and activity back as recorded before package
# installation. A unit that did not exist then ends disabled and stopped.
# At boot the manager is not reloaded, and activity before the reboot does
# not carry over: enabled units start as on any boot, and the start that
# apply's enabling queued for the others is cancelled without waiting.
restore_units() {
  local mode="$1" unit exists enabled active nr=() errors=0
  [ -f "$VH_UNITS_FILE" ] || return 0
  [ "$mode" != boot ] || nr=(--no-reload)
  while read -r unit exists enabled active; do
    if [ "$exists" = no ]; then
      unit_exists "$unit" || continue
      enabled=disabled active=inactive
    fi
    case "$enabled" in
      enabled) bounded_change systemctl "${nr[@]}" enable --quiet "$unit" >/dev/null 2>&1 || errors=$((errors + 1)) ;;
      disabled) bounded_change systemctl "${nr[@]}" disable --quiet "$unit" >/dev/null 2>&1 || errors=$((errors + 1)) ;;
    esac
    if [ "$mode" = boot ]; then
      case "$enabled" in
        enabled | static | alias | indirect | generated) ;;
        *) bounded_change systemctl --no-block stop "$unit" >/dev/null 2>&1 || errors=$((errors + 1)) ;;
      esac
      continue
    fi
    case "$active" in
      active) bounded_change systemctl restart "$unit" >/dev/null 2>&1 || errors=$((errors + 1)) ;;
      inactive | failed) bounded_change systemctl stop "$unit" >/dev/null 2>&1 || errors=$((errors + 1)) ;;
    esac
  done <"$VH_UNITS_FILE"
  [ "$errors" -eq 0 ]
}

# restore_all MODE REASON: undo apply. MODE is runtime or boot; at boot the
# services have not started yet, so nothing is reloaded or disabled at runtime.
# Every step runs even if an earlier one failed; the result says what failed.
restore_all() {
  local mode="$1" reason="$2" failed=()
  trap '' INT TERM HUP
  state_set status restoring
  state_set restore_started_at "$(utc_now)"
  # One log line per step, so that the log shows where a slow restore spent its time.
  vh_log "restore ($mode): $reason"
  if [ "$mode" = runtime ]; then
    stop_timers || true
    # New hosts start with UFW inactive (FR-02), so restoring means disabling it.
    if have ufw && [ "$(state_get ufw_was_active)" != yes ] && ufw_active; then
      bounded_change ufw --force disable >>"$VH_LOG_FILE" 2>&1 || failed+=('UFW 停用')
    fi
  fi
  vh_log 'restore: files'
  snapshot_restore "$VH_SNAPSHOT_DIR" >>"$VH_LOG_FILE" 2>&1 || failed+=('文件恢复')
  if [ "$mode" = runtime ]; then
    vh_log 'restore: sshd'
    sshd_cache_clear
    if bounded /usr/sbin/sshd -t >>"$VH_LOG_FILE" 2>&1; then
      bounded_change systemctl try-reload-or-restart ssh.service >>"$VH_LOG_FILE" 2>&1 || failed+=('sshd 重新加载')
    else
      failed+=('sshd 配置检查')
    fi
  fi
  vh_log 'restore: units'
  restore_units "$mode" || failed+=('服务状态')
  if [ "${#failed[@]}" -eq 0 ]; then
    disarm_restore "$mode" || failed+=('撤除自动恢复')
  fi
  if [ "${#failed[@]}" -eq 0 ]; then
    # A port change pending at the time is undone with everything else.
    rm -rf -- "$VH_PORTS_SNAPSHOT_DIR"
    state_set status rolled-back
    state_set rolled_back_at "$(utc_now)"
    state_set rollback_reason "$reason"
    vh_log "restore ($mode) done"
    return 0
  fi
  restore_failed "$mode" "$reason" "${failed[@]}"
}

# restore_failed MODE REASON FAILED...: keep the marker and boot unit so that
# a reboot tries again.
restore_failed() {
  local mode="$1" reason="$2"
  shift 2
  state_set status restore-failed
  state_set rollback_reason "$reason; 失败：$(join_by '、' "$@")"
  vh_log "restore ($mode) failed: $*"
  RESTORE_FAILED="$(join_by '、' "$@")"
  return 1
}

# restore_ports MODE REASON: undo a pending port change (FR-14): the UFW rule
# files, the declared ports and the rule record as before it; the state is
# applied again. At boot UFW has not started yet and loads the restored files.
restore_ports() {
  local mode="$1" reason="$2" failed=()
  trap '' INT TERM HUP
  state_set status restoring
  state_set restore_started_at "$(utc_now)"
  vh_log "port restore ($mode): $reason"
  [ "$mode" != runtime ] || stop_timers || true
  snapshot_restore "$VH_PORTS_SNAPSHOT_DIR" >>"$VH_LOG_FILE" 2>&1 || failed+=('文件恢复')
  if [ "$mode" = runtime ]; then
    bounded_change ufw reload >>"$VH_LOG_FILE" 2>&1 || failed+=('UFW 重新加载')
  fi
  if ! [ -f "$VH_PORTS_SNAPSHOT_DIR/open" ] || ! [ -f "$VH_PORTS_SNAPSHOT_DIR/ufw-rules" ] ||
    ! state_set open "$(cat "$VH_PORTS_SNAPSHOT_DIR/open")" ||
    ! install -m 0600 -- "$VH_PORTS_SNAPSHOT_DIR/ufw-rules" "$VH_UFW_RULES_FILE" ||
    ! record_digest /etc/ufw/user.rules || ! record_digest /etc/ufw/user6.rules; then
    failed+=('记录恢复')
  fi
  if [ "${#failed[@]}" -eq 0 ]; then
    disarm_restore "$mode" || failed+=('撤除自动恢复')
  fi
  if [ "${#failed[@]}" -eq 0 ]; then
    rm -rf -- "$VH_PORTS_SNAPSHOT_DIR"
    state_set status applied
    state_set ports_rolled_back_at "$(utc_now)"
    state_set ports_rollback_reason "$reason"
    vh_log "port restore ($mode) done"
    return 0
  fi
  restore_failed "$mode" "端口变更：$reason" "${failed[@]}"
}

# restore_report [ports]
restore_report() {
  if [ -n "${RESTORE_FAILED-}" ]; then
    printf '[x] 恢复未全部完成（%s），详见 %s。请从服务商控制台检查 SSH 和 UFW。\n' "$RESTORE_FAILED" "$VH_LOG_FILE" >&2
  elif [ "${1-}" = ports ]; then
    printf '已恢复到端口变更前的规则：公开端口 %s\n' "$(open_ports_text "$(state_get open)")"
  else
    printf '已恢复到应用前的配置。本工具安装的软件包保留：%s\n' "$(state_get packages_added | sed 's/^$/（无）/')"
  fi
}

# specs_text SPEC...: port specifications for people, "/both" left out.
specs_text() {
  local spec items=()
  for spec in "$@"; do
    items+=("${spec%/both}")
  done
  join_by '、' "${items[@]}"
}

# open_ports_text "SPEC...": the declared public ports, 22/tcp first.
open_ports_text() {
  # shellcheck disable=SC2086 # split into specifications on purpose
  specs_text 22/tcp $1
}

# vps-hardening _restore timeout UNIT | _restore boot (run by systemd only).
cmd_restore() {
  local mode="${1-}" unit="${2-}" kind
  [ "$(id -u)" -eq 0 ] || usage_error '需要 root 权限'
  case "$mode" in
    timeout) [ -n "$unit" ] || usage_error '缺少定时器名称' ;;
    boot) ;;
    *) usage_error "未知的恢复方式：$mode" ;;
  esac
  vh_tmp_init
  # Apply or confirm may hold the lock; their outcome decides what is left to do.
  vh_lock 900 || internal_error '等待操作锁超时'
  if [ ! -e "$VH_PENDING_FILE" ]; then
    printf '没有待确认的变更，无需恢复。\n'
    exit "$VH_EXIT_OK"
  fi
  if [ "$mode" = timeout ] && [ "$(state_get timer "$VH_PENDING_FILE")" != "$unit" ]; then
    printf '定时器 %s 已被替换，由新的定时器处理。\n' "$unit"
    exit "$VH_EXIT_OK"
  fi
  kind="$(state_get kind "$VH_PENDING_FILE")"
  if [ "$kind" = ports ]; then
    if [ "$mode" = timeout ]; then
      restore_ports runtime '确认超时' || true
    else
      restore_ports boot '待确认期间重启' || true
    fi
  elif [ "$mode" = timeout ]; then
    restore_all runtime '确认超时' || true
  else
    restore_all boot '待确认期间重启' || true
  fi
  restore_report "$kind"
  [ -z "${RESTORE_FAILED-}" ] || exit "$VH_EXIT_FAIL"
}

cmd_confirm() {
  local status loginuid sessionid kind command=apply
  [ "$#" -eq 0 ] || usage_error "confirm 不接受参数：$1"
  [ "$(id -u)" -eq 0 ] || refuse '需要 root 权限：请用 root 的密钥登录后执行'
  # No temporary directory here: the final exec would skip its EXIT trap.
  vh_lock 0 || refuse '另一个 vps-hardening 操作正在进行，请稍后再试'
  status="$(state_get status)"
  case "$status" in
    pending | ports-pending) ;;
    *) status='' ;;
  esac
  if [ -z "$status" ] || [ ! -e "$VH_PENDING_FILE" ]; then
    refuse "当前没有待确认的变更（状态：$(state_get status | sed 's/^$/未应用/')）"
  fi
  kind="$(state_get kind "$VH_PENDING_FILE")"
  [ "$kind" != ports ] || command=ports
  loginuid="$(own_loginuid)"
  sessionid="$(own_sessionid)"
  if [ "$loginuid" != 0 ]; then
    refuse '确认必须在以 root 登录的会话中执行；经 sudo 或 su 切换到 root 不算。请用 root 的密钥开一个新的 SSH 会话'
  fi
  if [ "$sessionid" = "$VH_AUDIT_UNSET" ] || ! [[ "$sessionid" =~ ^[0-9]+$ ]]; then
    refuse '当前会话没有登录会话编号，无法确认它是新的 SSH 会话'
  fi
  if [ "$sessionid" = "$(state_get session "$VH_PENDING_FILE")" ]; then
    refuse "这是执行 $command 的会话。请保持它，另开一个终端，用 root 的密钥登录后再执行 confirm"
  fi
  session_from_sshd || refuse '当前会话不是经 SSH 登录的；确认要证明 root 的密钥登录可用'

  disarm_restore || internal_error '撤除自动恢复失败；状态未改变，请重试'
  state_set status applied
  if [ "$kind" = ports ]; then
    rm -rf -- "$VH_PORTS_SNAPSHOT_DIR"
    state_set ports_confirmed_at "$(utc_now)"
    vh_log "port change confirmed from session $sessionid"
    printf '已确认，端口变更生效：公开端口 %s。自动恢复已撤除。\n\n' "$(open_ports_text "$(state_get open)")"
  else
    state_set confirmed_at "$(utc_now)"
    vh_log "confirmed from session $sessionid"
    printf '已确认，加固生效。自动恢复已撤除。\n\n'
  fi
  print_tunnel_hint
  printf '\n== 验证\n'
  exec 9>&-
  exec "$VH_SELF" verify
}

print_tunnel_hint() {
  printf '访问面板（安装 3X-UI 之后）：在本机执行\n'
  printf '  ssh -N -L 127.0.0.1:8443:127.0.0.1:%s -i <私钥> -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes root@<VPS 地址>\n' \
    "$(state_get panel_port)"
  printf '然后在本机浏览器打开 http://127.0.0.1:8443/ 加面板的访问路径（面板配置了证书时用 https）。\n'
}
