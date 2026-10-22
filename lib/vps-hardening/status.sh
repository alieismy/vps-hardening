# shellcheck shell=bash
# status (FR-13, design 7.1): what the tool has done on this host. Read-only
# and without the lock, so it also answers while another command runs, and
# then shows that command's state at that moment.

cmd_status() {
  local status
  [ "$#" -eq 0 ] || usage_error "status 不接受参数：$1"
  [ "$(id -u)" -eq 0 ] || refuse '需要 root 权限：状态目录只有 root 可读'
  printf 'vps-hardening %s\n' "$VH_VERSION"
  if [ ! -f "$VH_STATE_FILE" ]; then
    printf '状态：未应用（本工具没有在这台主机上执行过）\n'
    return 0
  fi
  status="$(state_get status)"
  printf '状态：%s\n' "$(status_text "$status")"
  status_line '应用的版本' "$(state_get version)"
  status_line '应用开始' "$(state_get started_at)"
  status_line '应用完成' "$(state_get applied_at)"
  status_line '确认' "$(state_get confirmed_at)"
  status_line '面板端口' "$(state_get panel_port | sed 's/$/（不开放，只经 SSH 隧道访问）/')"
  status_line '公开端口' "$(open_ports_text "$(state_get open)")"
  status_line '确认时限' "$(state_get confirm_timeout | sed 's/$/ 分钟/')"
  status_line '禁止经 SSH 登录的账户' "$(state_get denied_users)"
  status_line 'root 公钥指纹' "$(state_get root_keys)"
  status_line '本工具安装的软件包' "$(state_get packages_added | sed 's/^$/（无）/')"
  status_files
  status_ports
  status_line '回滚' "$(state_get rolled_back_at)"
  status_line '回滚原因' "$(state_get rollback_reason)"
  status_line '日志' "$VH_LOG_FILE"

  case "$status" in
    pending | ports-pending) status_pending "$status" ;;
    applying | restoring | restore-failed)
      printf '\n处理：确认没有其他 vps-hardening 操作在运行后，执行 vps-hardening rollback；详见日志。\n'
      ;;
  esac
  if have_record; then
    printf '\n'
    print_tunnel_hint
  fi
}

status_text() {
  case "$1" in
    applying) printf '应用中（未完成）\n' ;;
    pending) printf '待确认\n' ;;
    applied) printf '已应用\n' ;;
    ports-pending) printf '端口变更待确认\n' ;;
    restoring) printf '恢复中（未完成）\n' ;;
    restore-failed) printf '恢复失败\n' ;;
    rolled-back) printf '已回滚\n' ;;
    *) printf '%s\n' "${1:-未知}" ;;
  esac
}

# status_line LABEL VALUE: one line, left out when VALUE is empty.
status_line() {
  [ -z "$2" ] || printf '%s：%s\n' "$1" "$2"
}

# FR-13: each managed file before apply and after the last change, by digest.
status_files() {
  local _i kind digest _meta path
  [ -f "$VH_SNAPSHOT_DIR/index" ] || return 0
  printf '受管文件（SHA-256 前 12 位，应用前 → 最近一次变更后）：\n'
  while read -r _i kind digest _meta path; do
    [ "$kind" = present ] || digest=absent
    printf '  %s：%s → %s\n' "$path" "$(short_digest "$digest")" "$(short_digest "$(recorded_digest "$path")")"
  done <"$VH_SNAPSHOT_DIR/index"
}

short_digest() {
  case "$1" in
    '') printf '（未记录）\n' ;;
    absent) printf '不存在\n' ;;
    *) printf '%s\n' "${1:0:12}" ;;
  esac
}

# The latest port change (FR-14) and how it ended.
status_ports() {
  local started
  started="$(state_get ports_started_at)"
  [ -n "$started" ] || return 0
  printf '最近一次端口变更：开始 %s' "$started"
  if [ -n "$(state_get ports_confirmed_at)" ]; then
    printf '，确认 %s' "$(state_get ports_confirmed_at)"
  elif [ -n "$(state_get ports_rolled_back_at)" ]; then
    printf '，%s 恢复原端口（%s）' "$(state_get ports_rolled_back_at)" "$(state_get ports_rollback_reason)"
  fi
  printf '\n'
}

status_pending() {
  local deadline
  deadline="$(state_get deadline "$VH_PENDING_FILE")"
  printf '\n'
  if [ "$1" = ports-pending ] && [ -f "$VH_PORTS_SNAPSHOT_DIR/open" ]; then
    printf '变更前的公开端口：%s\n' "$(open_ports_text "$(cat "$VH_PORTS_SNAPSHOT_DIR/open")")"
  fi
  if [ -n "$deadline" ]; then
    printf '确认截止：%s（约 %s 分钟后）\n' "$(date -u -d "@$deadline" '+%Y-%m-%d %H:%M:%S UTC')" "$(minutes_left)"
  fi
  printf '请保持发起变更的会话，另开一个终端，用 root 的密钥登录后执行：\n'
  printf '  %s confirm\n' "$VH_SELF"
  if [ "$1" = ports-pending ]; then
    printf '到期未确认，或在此之前重启，都会恢复变更前的公开端口。\n'
  else
    printf '到期未确认，或在此之前重启，都会自动恢复到应用前的配置。\n'
  fi
}
