# shellcheck shell=bash
# ports (FR-14, design 7.3): add or remove declared public ports on an applied
# host, inside the same confirmation window as apply: the timer, the boot
# unit and confirm keep or undo the change. Only the two UFW rule files
# change; their snapshot is kept in snapshot-ports, apart from apply's.

# prepare: nothing changed yet; changing: failure restores the old ports.
VH_PORTS_STAGE=''
VH_PORTS_OLD=()
VH_PORTS_NEW=()
VH_PORTS_ADDED=()
VH_PORTS_REMOVED=()

cmd_ports() {
  parse_ports_options "$@"
  [ "$(id -u)" -eq 0 ] || refuse '需要 root 权限：请在 root shell 中运行'
  vh_tmp_init
  vh_lock 0 || refuse '另一个 vps-hardening 操作正在进行，请稍后再试'
  case "$(state_get status)" in
    applied) ;;
    pending) refuse '加固还在待确认：请先从新的 SSH 会话以 root 执行 confirm' ;;
    ports-pending) refuse '上一次端口变更还在待确认：请先确认，或等它到期恢复' ;;
    '') refuse '本工具没有在这台主机上应用过：请先执行 apply' ;;
    *) refuse "本工具的状态为 $(state_get status)，不能变更端口，详见 $VH_LOG_FILE" ;;
  esac
  ports_compute
  printf '== 变更前检查\n'
  ports_checks
  report_summary
  if [ "$VH_COUNT_FAIL" -gt 0 ]; then
    printf '\n变更前检查有不符合项，未做任何变更。\n'
    exit "$VH_EXIT_FAIL"
  fi
  ports_plan
  if ! safeguards_prompt 确认完成; then
    printf '已取消，未做任何变更。\n'
    exit "$VH_EXIT_FAIL"
  fi
  ports_run
}

# The declared ports after the removals, then the additions. A port is told
# apart by PORT/PROTO; the record decides what may be removed or added.
ports_compute() {
  local panel spec declared i found
  panel="$(state_get panel_port)"
  read -r -a VH_PORTS_OLD <<<"$(state_get open)"
  VH_PORTS_NEW=("${VH_PORTS_OLD[@]}")
  for spec in "${VH_IN_REMOVE[@]}"; do
    split_port_spec "$spec"
    [ "$VH_SPEC_PORT" -ne 22 ] || usage_error '22 端口总是放行，不能撤销'
    found=''
    for i in "${!VH_PORTS_NEW[@]}"; do
      declared="${VH_PORTS_NEW[$i]}"
      [ "${declared%/*}" = "$VH_SPEC_PORT/$VH_SPEC_PROTO" ] || continue
      # A family given with --remove must be the declared one.
      if [[ "$spec" == */*/* ]] && [ "${declared##*/}" != "$VH_SPEC_FAMILY" ]; then
        usage_error "$VH_SPEC_PORT/$VH_SPEC_PROTO 声明的地址族是 ${declared##*/}，不是 $VH_SPEC_FAMILY"
      fi
      found="$declared"
      unset 'VH_PORTS_NEW[i]'
    done
    [ -n "$found" ] ||
      usage_error "$VH_SPEC_PORT/$VH_SPEC_PROTO 不是已声明的公开端口；当前为 $(open_ports_text "${VH_PORTS_OLD[*]}")"
    VH_PORTS_REMOVED+=("$found")
  done
  VH_PORTS_NEW=("${VH_PORTS_NEW[@]}")
  for spec in "${VH_IN_ADD[@]}"; do
    split_port_spec "$spec"
    check_public_port "$panel"
    for declared in "${VH_PORTS_NEW[@]}"; do
      [ "${declared%/*}" != "$VH_SPEC_PORT/$VH_SPEC_PROTO" ] ||
        usage_error "$VH_SPEC_PORT/$VH_SPEC_PROTO 已经是公开端口"
    done
    VH_PORTS_ADDED+=("$VH_SPEC_PORT/$VH_SPEC_PROTO/$VH_SPEC_FAMILY")
    VH_PORTS_NEW+=("$VH_SPEC_PORT/$VH_SPEC_PROTO/$VH_SPEC_FAMILY")
  done
  [ "${#VH_PORTS_NEW[@]}" -le "$VH_MAX_OPEN" ] || usage_error "公开端口最多 $VH_MAX_OPEN 个"
}

# The change starts from the declared rules, with 22/tcp allowed.
ports_checks() {
  if ufw_active; then
    report PASS ports.ufw 'UFW 已启用'
  else
    report FAIL ports.ufw 'UFW 未启用'
  fi
  if diff <(ufw_status_rules | ufw_rule_tokens) <(expected_rule_tokens 22/tcp/both "${VH_PORTS_OLD[@]}") >/dev/null; then
    report PASS ports.rules 'UFW 规则与声明一致'
  else
    report FAIL ports.rules 'UFW 规则与声明不一致：请先用 verify 查看并处理差异'
  fi
  if ufw_added_rules | ufw_rules_allow_port 22; then
    report PASS ports.ssh 'UFW 放行 22/tcp'
  else
    report FAIL ports.ssh 'UFW 中没有放行 22/tcp 的规则'
  fi
  check_root_keys
}

ports_plan() {
  printf '\n== 将要执行的变更\n'
  if [ "${#VH_PORTS_REMOVED[@]}" -gt 0 ]; then
    printf -- '- 撤销公开端口：%s\n' "$(specs_text "${VH_PORTS_REMOVED[@]}")"
  fi
  if [ "${#VH_PORTS_ADDED[@]}" -gt 0 ]; then
    printf -- '- 增加公开端口：%s\n' "$(specs_text "${VH_PORTS_ADDED[@]}")"
  fi
  printf -- '- 变更后 UFW 放行：%s；面板端口 %s 不放行\n' "$(open_ports_text "${VH_PORTS_NEW[*]}")" "$(state_get panel_port)"
  printf -- '- 确认时限 %s 分钟：期间须从新的 SSH 会话以 root 执行 confirm，否则恢复原端口\n' "$VH_IN_TIMEOUT"
}

# Undo whatever ports has changed so far.
ports_undo() {
  local reason="$1"
  trap '' INT TERM HUP
  VH_ABORT_HOOK=''
  case "$VH_PORTS_STAGE" in
    changing)
      vh_log "ports failed: $reason"
      printf '正在恢复原端口……\n' >&2
      restore_ports runtime "$reason" || true
      restore_report ports >&2
      ;;
    prepare)
      vh_log "ports failed before any rule change: $reason"
      rm -rf -- "$VH_PORTS_SNAPSHOT_DIR"
      state_set ports_rolled_back_at "$(utc_now)"
      state_set ports_rollback_reason "$reason（尚未修改规则）"
      ;;
  esac
}

ports_fail() {
  printf '[x] %s\n' "$*" >&2
  ports_undo "端口变更失败：$*"
  exit "$VH_EXIT_FAIL"
}

# ERR trap hook (bin/vps-hardening).
ports_abort() {
  ports_undo '端口变更中出现内部错误'
}

ports_signal() {
  trap '' INT TERM HUP
  [ "$1" != HUP ] || output_to_log
  ports_fail "收到信号 $1"
}

ports_run() {
  local timeout_s=$((VH_IN_TIMEOUT * 60)) path
  check_self_path
  trap 'ports_signal INT' INT
  trap 'ports_signal TERM' TERM
  trap 'ports_signal HUP' HUP
  VH_APPLY_SESSION="$(own_sessionid)"
  VH_PORTS_STAGE=prepare
  VH_ABORT_HOOK=ports_abort
  vh_log "ports started by session $VH_APPLY_SESSION: remove ${VH_PORTS_REMOVED[*]:-none}; add ${VH_PORTS_ADDED[*]:-none}"
  state_set ports_started_at "$(utc_now)"
  state_set ports_confirmed_at ''
  state_set ports_rolled_back_at ''
  state_set ports_rollback_reason ''

  printf '\n== 1/3 记录变更前的规则\n'
  snapshot_take "$VH_PORTS_SNAPSHOT_DIR" "${VH_PORT_FILES[@]}" || ports_fail '无法记录 UFW 规则文件的快照'
  state_get open >"$VH_PORTS_SNAPSHOT_DIR/open"

  printf '== 2/3 布置自动恢复（%s 分钟）\n' "$VH_IN_TIMEOUT"
  VH_PORTS_STAGE=changing
  arm_restore "$timeout_s" ports || ports_fail '无法布置自动恢复；不会修改 UFW 规则'
  state_set status ports-pending

  printf '== 3/3 UFW\n'
  ports_ufw >>"$VH_LOG_FILE" 2>&1 || ports_fail "UFW 规则变更失败，详见 $VH_LOG_FILE"
  ports_rules_match || ports_fail "变更后的 UFW 规则与声明的公开端口不一致，详见 $VH_LOG_FILE"
  state_set open "${VH_PORTS_NEW[*]}"
  for path in "${VH_PORT_FILES[@]}"; do
    record_digest "$path"
  done
  rearm_timer "$timeout_s" || ports_fail '无法重新计时'
  # shellcheck disable=SC2034 # read by the ERR trap in bin/vps-hardening
  VH_ABORT_HOOK=''
  VH_PORTS_STAGE=finished
  vh_log 'ports done, pending confirmation'
  ports_done_message
}

# Called in a condition, where errexit is off: every step is checked. Removals
# come first, so that a port can move to another address family in one change.
ports_ufw() {
  local spec
  for spec in "${VH_PORTS_REMOVED[@]}"; do
    ufw_port_rule delete "$spec" || return 1
  done
  for spec in "${VH_PORTS_ADDED[@]}"; do
    ufw_port_rule "$spec" || return 1
  done
}

# `ufw delete` of a rule that does not exist still exits 0, so the result is
# checked: the active rules are exactly 22/tcp and the new declared ports, for
# the declared address families, from anywhere, with the tool's comment.
ports_rules_match() {
  diff <(ufw_status_rules | ufw_rule_tokens) <(expected_rule_tokens 22/tcp/both "${VH_PORTS_NEW[@]}") >>"$VH_LOG_FILE"
}

# Rule lines of `ufw status` on stdin, as "FAMILY RULE" with the "(v6)" marks
# taken out and runs of spaces squeezed, sorted. Only `ufw status verbose`
# shows the direction of inbound rules; it is dropped here too.
ufw_rule_tokens() {
  awk '{ family = /\(v6\)/ ? "v6" : "v4"; gsub(/ \(v6\)/, ""); $1 = $1; sub(/ ALLOW IN /, " ALLOW "); print family, $0 }' | sort
}

expected_rule_tokens() {
  local spec port proto family
  for spec in "$@"; do
    IFS=/ read -r port proto family <<<"$spec"
    if [ "$family" != ipv6 ]; then
      printf 'v4 %s/%s ALLOW Anywhere # %s\n' "$port" "$proto" "$VH_UFW_COMMENT"
    fi
    if [ "$family" != ipv4 ]; then
      printf 'v6 %s/%s ALLOW Anywhere # %s\n' "$port" "$proto" "$VH_UFW_COMMENT"
    fi
  done | sort
}

ports_done_message() {
  local deadline
  deadline="$(state_get deadline "$VH_PENDING_FILE")"
  printf '\n端口变更已生效，等待确认。公开端口：%s\n' "$(open_ports_text "${VH_PORTS_NEW[*]}")"
  printf '确认截止：%s（%s 分钟后）\n' "$(date -u -d "@$deadline" '+%Y-%m-%d %H:%M:%S UTC')" "$VH_IN_TIMEOUT"
  printf '请保持当前会话，另开一个终端，用 root 的密钥登录后执行：\n'
  printf '  %s confirm\n' "$VH_SELF"
  printf '到期未确认，或在此之前重启，都会恢复原端口：%s\n' "$(open_ports_text "${VH_PORTS_OLD[*]}")"
}
