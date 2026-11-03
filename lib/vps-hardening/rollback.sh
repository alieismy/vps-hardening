# shellcheck shell=bash
# rollback (FR-12, design 7.3): restore the configuration from before apply.
# The lockout checks run first, on the configuration the restore will leave:
# root's keys and the sshd values, both from the sshd configuration evaluated
# with the drop-in as it was before apply, and UFW. Nothing changes unless all
# of them pass.

cmd_rollback() {
  local status
  [ "$#" -eq 0 ] || usage_error "rollback 不接受参数：$1"
  [ "$(id -u)" -eq 0 ] || refuse '需要 root 权限：请在 root shell 中运行'
  vh_tmp_init
  vh_lock 0 || refuse '另一个 vps-hardening 操作正在进行，请稍后再试'
  status="$(state_get status)"
  case "$status" in
    # An interrupted apply or restore is finished by rolling back as well.
    applied | pending | ports-pending | applying | restoring | restore-failed) ;;
    rolled-back) refuse "已经回滚（$(state_get rollback_reason)），没有需要回滚的变更" ;;
    '') refuse '本工具没有在这台主机上应用过，没有需要回滚的变更' ;;
    *) refuse "本工具的状态为 $status，详见 $VH_LOG_FILE" ;;
  esac
  # arm_restore creates pending before any managed configuration change.
  # An interrupted preparation can have a partial record; do not require the
  # endpoint fields that it had not finished writing merely to restore units.
  if [ "$status" = applying ] && [ ! -e "$VH_PENDING_FILE" ]; then
    rollback_prepare
    return
  fi
  printf '== 回滚前检查\n'
  ssh_endpoint_report rollback.endpoint || true
  rollback_checks "$status"
  report_summary
  if [ "$VH_COUNT_FAIL" -gt 0 ]; then
    printf '\n回滚前检查有不符合项，未做任何变更。\n'
    exit "$VH_EXIT_FAIL"
  fi
  rollback_plan
  if ! safeguards_prompt 回滚完成; then
    printf '已取消，未做任何变更。\n'
    exit "$VH_EXIT_FAIL"
  fi
  ssh_endpoint_report rollback.endpoint || refuse "交互期间 SSH 入口变化：$VH_SSH_ERROR；未做变更"
  printf '\n正在回滚……\n'
  restore_all runtime '手工回滚' || true
  restore_report
  [ -z "$RESTORE_FAILED" ] || exit "$VH_EXIT_FAIL"
  printf '请另开一个终端，用 root 的密钥登录，确认仍可登录。\n'
}

rollback_checks() {
  # Arming writes the marker before the first configuration change, so an
  # apply without it changed packages and their services only.
  if [ "$1" = applying ] && [ ! -e "$VH_PENDING_FILE" ]; then
    report INFO rollback.snapshot '应用在修改配置之前中断：回滚只恢复服务状态'
  elif snapshot_complete "$VH_SNAPSHOT_DIR" "${#VH_MANAGED_FILES[@]}"; then
    report PASS rollback.snapshot "应用前的快照完整（${#VH_MANAGED_FILES[@]} 个文件）"
  else
    report FAIL rollback.snapshot "应用前的快照不完整或被修改（$VH_SNAPSHOT_DIR），无法完整回滚"
  fi
  # The key files and algorithms can differ from the current ones when this
  # tool's drop-in was changed after apply (requirements D60).
  if rollback_sshd_eval; then
    check_root_keys "$VH_TMP/sshd-T.rollback" '回滚后的配置下，'
    rollback_check_sshd
  else
    report FAIL rollback.sshd "无法评估回滚后的 sshd 配置：$(head -n 1 "$VH_TMP/sshd-T.rollback.err" 2>/dev/null)"
  fi
  # New hosts start with UFW inactive (FR-02), so the restore disables it.
  if [ "$(state_get ufw_was_active)" = yes ]; then
    report FAIL rollback.ufw "记录显示应用前 UFW 已启用，与新机条件不符（FR-02）：无法预先确认回滚后放行 ${VH_SSH_PORT:-未知}/tcp"
  else
    report PASS rollback.ufw "回滚后 UFW 停用（应用前未启用），SSH 管理端口不受 UFW 限制"
  fi
}

# The sshd configuration the restore will leave, evaluated for root before
# anything changes. In a private mount namespace sshd sees a copy of the
# drop-in directory with this tool's drop-in as it was before apply; the real
# directory is not touched.
rollback_sshd_eval() {
  local dir="$VH_TMP/sshd_config.d" dropin="$VH_SSHD_DROPIN_DIR/$VH_SSHD_DROPIN_NAME" i kind _digest _meta path
  [ -n "${VH_SSH_PORT-}" ] || return 1
  rm -rf -- "$dir"
  cp -a -- "$VH_SSHD_DROPIN_DIR" "$dir" || return 1
  if [ -f "$VH_SNAPSHOT_DIR/index" ]; then
    while read -r i kind _digest _meta path; do
      [ "$path" = "$dropin" ] || continue
      if [ "$kind" = present ]; then
        cp -- "$VH_SNAPSHOT_DIR/$i" "$dir/$VH_SSHD_DROPIN_NAME" || return 1
      else
        rm -f -- "$dir/$VH_SSHD_DROPIN_NAME" || return 1
      fi
    done <"$VH_SNAPSHOT_DIR/index"
  fi
  # shellcheck disable=SC2016 # expanded by the inner shell
  bounded unshare --mount --propagation private -- /bin/sh -c \
    'mount --bind "$1" "$2" || exit; conn=$3; shift 3; /usr/sbin/sshd "$@" -t && /usr/sbin/sshd "$@" -T -C "$conn"' \
    sh "$dir" "$VH_SSHD_DROPIN_DIR" "user=root,$VH_SSHD_PROBE_CONN,lport=$VH_SSH_PORT" "${VH_SSHD_ARGS[@]}" \
    >"$VH_TMP/sshd-T.rollback" 2>"$VH_TMP/sshd-T.rollback.err"
}

# FR-12: restored authentication and effective endpoints preserve root access. Reads the
# output of rollback_sshd_eval.
rollback_check_sshd() {
  local file="$VH_TMP/sshd-T.rollback" prl pubkey password endpoints
  endpoints="$(ssh_endpoint_from_config "$file")" || endpoints=''
  prl="$(sshd_value permitrootlogin <"$file")"
  pubkey="$(sshd_value pubkeyauthentication <"$file")"
  password="$(sshd_value passwordauthentication <"$file")"
  case "$prl" in
    yes | without-password | prohibit-password) ;;
    *) prl='' ;;
  esac
  if [ -z "$prl" ] || [ "$pubkey" != yes ] || [ -z "${VH_SSH_PORT-}" ] || [ "$endpoints" != "${VH_SSH_LISTENERS-}" ]; then
    report FAIL rollback.sshd "回滚后的认证或有效监听端点不符合 SSH 基线：permitrootlogin $(sshd_value permitrootlogin <"$file")，pubkeyauthentication ${pubkey:-（空）}，端点 ${endpoints:-无法求值}"
    return 0
  fi
  report PASS rollback.sshd "回滚后的认证配置允许 root 公钥登录，端点符合 $VH_SSH_PORT 基线（permitrootlogin $prl）；实际登录须外部验收"
  if [ "$password" = yes ]; then
    report WARN rollback.password "回滚后恢复应用前的密码认证（passwordauthentication yes，root 的 permitrootlogin $prl）：公网主机上的密码猜测会随即开始"
  else
    report INFO rollback.password "回滚后密码认证仍关闭（passwordauthentication ${password:-（空）}）"
  fi
}

rollback_plan() {
  local _i kind _digest _meta path restore=() remove=()
  if [ -f "$VH_SNAPSHOT_DIR/index" ]; then
    while read -r _i kind _digest _meta path; do
      if [ "$kind" = present ]; then
        restore+=("$path")
      else
        remove+=("$path")
      fi
    done <"$VH_SNAPSHOT_DIR/index"
  fi
  printf '\n== 将要执行的回滚\n'
  if [ "${#restore[@]}" -gt 0 ]; then
    printf -- '- 恢复到应用前的内容：%s\n' "$(join_by '、' "${restore[@]}")"
  fi
  if [ "${#remove[@]}" -gt 0 ]; then
    printf -- '- 删除应用时新建的文件：%s\n' "$(join_by '、' "${remove[@]}")"
  fi
  printf -- '- UFW：停用（应用前未启用）\n'
  printf -- '- 服务：%s 恢复到应用前的启用和运行状态\n' "$(join_by '、' "${VH_MANAGED_UNITS[@]}")"
  if [ -e "$VH_PENDING_FILE" ]; then
    printf -- '- 撤除待确认的自动恢复，待确认的变更一并撤销\n'
  fi
  printf -- '- 保留：本工具安装的软件包（%s）、root 的 authorized_keys、3X-UI 和 vps-tuning 的文件、本工具的状态记录和日志\n' \
    "$(state_get packages_added | sed 's/^$/无/')"
}

# Complete preparation interrupted before arming: only package/service effects
# exist. Never reload SSH, restore a configuration snapshot or claim login works.
rollback_prepare() {
  report INFO rollback.snapshot '应用在修改配置之前中断：只恢复服务状态，SSH 入口未验证'
  printf '将恢复安装软件包前的服务状态；软件包保留，不修改 SSH/UFW 配置。\n'
  safeguards_prompt 回滚完成 || refuse '已取消，未做任何变更'
  if ! restore_units runtime; then
    vh_log 'prepare rollback failed: unit restoration incomplete'
    refuse '服务状态未能全部恢复；保留应用中状态及恢复材料，请排除原因后重试 rollback'
  fi
  if ! state_set rolled_back_at "$(utc_now)" ||
    ! state_set rollback_reason '手工回滚（准备阶段，尚未修改配置）' ||
    ! state_set status rolled-back; then
    refuse '恢复未全部完成（状态记录），请排除写入问题后重试 rollback'
  fi
  vh_log 'prepare rollback done; SSH endpoint unverified'
  printf '已恢复准备阶段的服务状态；SSH 入口及公网登录未验证。\n'
}
