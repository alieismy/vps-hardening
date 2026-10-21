# shellcheck shell=bash
# apply (design 7.3): preflight, confirmation, then the changes, inside the
# automatic-restore window armed before the first change to the login path.

readonly VH_F2B_JAIL=/etc/fail2ban/jail.d/99-vps-hardening.local
readonly VH_F2B_LOCAL=/etc/fail2ban/fail2ban.local
readonly VH_APT_CONF=/etc/apt/apt.conf.d/52vps-hardening
readonly VH_UFW_COMMENT=vps-hardening
# Bound for package installation, which runs before the restore is armed.
readonly VH_APT_TIMEOUT=1800

# prepare: only packages may change; changing: failure restores the snapshot.
VH_APPLY_STAGE=''
VH_APPLY_SESSION=''
VH_DENIED_USERS=()

cmd_apply() {
  parse_host_options "$@"
  if [ "$(id -u)" -ne 0 ]; then
    report FAIL root '需要 root 权限：请在 root shell 中运行'
    finish_checks
  fi
  vh_tmp_init
  vh_lock 0 || {
    printf '[x] 另一个 vps-hardening 操作正在进行，请稍后再试\n' >&2
    exit "$VH_EXIT_FAIL"
  }
  if [ "$(state_get status)" = applied ]; then
    apply_again
  fi
  printf '== 预检\n'
  run_preflight_checks
  report_summary
  if [ "$VH_COUNT_FAIL" -gt 0 ]; then
    printf '\n预检有不符合项，未做任何变更。\n'
    exit "$VH_EXIT_FAIL"
  fi
  read -r -a VH_DENIED_USERS <<<"$(nopasswd_key_accounts | paste -sd ' ')"
  apply_plan
  if ! safeguards_prompt 确认完成; then
    printf '已取消，未做任何变更。\n'
    exit "$VH_EXIT_FAIL"
  fi
  apply_run
}

# NFR-03 and design 7.3: apply on an applied host changes nothing. It passes
# when the inputs match the record and verify passes. Drift is refused, not
# repaired; public ports change through ports. The confirmation time is not
# compared: it only matters while a change is pending.
apply_again() {
  local want got
  printf '== 已应用：核对参数和当前状态\n'
  want="$(state_get panel_port) $(sorted_words "$(state_get open)")"
  got="$VH_IN_PANEL_PORT $(sorted_words "${VH_IN_OPEN[*]}")"
  if [ "$want" = "$got" ]; then
    report PASS apply.inputs '参数与应用记录一致'
  else
    report FAIL apply.inputs "参数与应用记录不同：记录为面板端口 $(state_get panel_port)、公开端口 $(open_ports_text "$(state_get open)")，本次为面板端口 $VH_IN_PANEL_PORT、公开端口 $(open_ports_text "${VH_IN_OPEN[*]}")。公开端口请用 ports 变更"
  fi
  run_verify_checks
  report_summary
  if [ "$VH_COUNT_FAIL" -eq 0 ]; then
    printf '\n已应用，全部通过，未做任何变更。\n'
    exit "$VH_EXIT_OK"
  fi
  printf '\n已应用，但有不符合项，未做任何变更。请按上面的不符合项处理，或执行 vps-hardening rollback 后重新应用。\n'
  exit "$VH_EXIT_FAIL"
}

# sorted_words "WORDS": the words sorted, on one line.
sorted_words() {
  # shellcheck disable=SC2086 # split into words on purpose
  printf '%s\n' $1 | sort | paste -sd ' '
}

apply_plan() {
  local spec opens=()
  for spec in "${VH_IN_OPEN[@]}"; do
    opens+=("${spec%/both}")
  done
  printf '\n== 将要执行的变更\n'
  printf -- '- 安装软件包（已安装的跳过）：%s\n' "${VH_PACKAGES[*]}"
  printf -- '- SSH：root 只能用密钥登录，关闭密码和键盘交互认证'
  if [ "${#VH_DENIED_USERS[@]}" -gt 0 ]; then
    printf '；禁止 %s 经 SSH 登录（有免密 sudo）' "$(join_by '、' "${VH_DENIED_USERS[@]}")"
  fi
  printf '\n- UFW：拒绝入站、允许出站、拒绝转发；放行 22/tcp%s；面板端口 %s 不放行\n' \
    "$([ "${#opens[@]}" -eq 0 ] || printf '、%s' "$(join_by '、' "${opens[@]}")")" "$VH_IN_PANEL_PORT"
  printf -- '- Fail2ban：只保护 SSH（normal 模式，5 次失败封禁 1 天）\n'
  printf -- '- 自动安全更新：每天更新并安装安全更新，不自动重启\n'
  printf -- '- 确认时限 %s 分钟：期间须从新的 SSH 会话以 root 执行 confirm，否则自动恢复\n' "$VH_IN_TIMEOUT"
}

# Undo whatever apply has changed so far (FR-05).
apply_undo() {
  local reason="$1"
  trap '' INT TERM HUP
  VH_ABORT_HOOK=''
  case "$VH_APPLY_STAGE" in
    changing)
      vh_log "apply failed: $reason"
      printf '正在恢复应用前的配置……\n' >&2
      restore_all runtime "$reason" || true
      restore_report >&2
      ;;
    prepare)
      # Only packages may have been installed: they stay, their services go back.
      vh_log "apply failed before any configuration change: $reason"
      if ! restore_units runtime; then
        reason="$reason；服务状态未能全部恢复"
        printf '[x] 服务状态未能全部恢复，详见 %s\n' "$VH_UNITS_FILE" >&2
      fi
      state_set status rolled-back
      state_set rolled_back_at "$(utc_now)"
      state_set rollback_reason "$reason（尚未修改配置）"
      ;;
  esac
}

# Undo, report, and exit non-zero.
apply_fail() {
  printf '[x] %s\n' "$*" >&2
  apply_undo "应用失败：$*"
  exit "$VH_EXIT_FAIL"
}

# ERR trap hook (bin/vps-hardening): an unexpected failure undoes too.
apply_abort() {
  apply_undo '应用中出现内部错误'
}

# A lost session or Ctrl-C mid-apply restores at once instead of waiting for the timer.
apply_signal() {
  trap '' INT TERM HUP
  [ "$1" != HUP ] || output_to_log
  apply_fail "收到信号 $1"
}

apply_run() {
  local timeout_s=$((VH_IN_TIMEOUT * 60))
  check_self_path
  trap 'apply_signal INT' INT
  trap 'apply_signal TERM' TERM
  trap 'apply_signal HUP' HUP
  VH_APPLY_SESSION="$(own_sessionid)"

  # Records of an earlier, rolled-back apply (FR-02) must not be reused.
  state_dir_init
  rm -rf -- "$VH_STATE_FILE" "$VH_UFW_RULES_FILE" "$VH_UNITS_FILE" "$VH_SNAPSHOT_DIR" "$VH_PORTS_SNAPSHOT_DIR"
  state_set status applying
  VH_APPLY_STAGE=prepare
  VH_ABORT_HOOK=apply_abort
  state_set version "$VH_VERSION"
  state_set started_at "$(utc_now)"
  state_set panel_port "$VH_IN_PANEL_PORT"
  state_set open "${VH_IN_OPEN[*]}"
  state_set confirm_timeout "$VH_IN_TIMEOUT"
  state_set apply_session "$VH_APPLY_SESSION"
  state_set denied_users "${VH_DENIED_USERS[*]}"
  state_set root_keys "$(printf '%s\n' "${VH_ROOT_KEYS[@]}" | awk '{print $2}' | paste -sd ' ')"
  state_set ufw_was_active "$(ufw_active && echo yes || echo no)"
  vh_log "apply started by session $VH_APPLY_SESSION, version $VH_VERSION"

  printf '\n== 1/6 记录初始状态并安装软件包\n'
  units_record
  install_missing_packages
  snapshot_take "$VH_SNAPSHOT_DIR" "${VH_MANAGED_FILES[@]}" || apply_fail '无法记录受管文件的快照'

  printf '== 2/6 布置自动恢复（%s 分钟）\n' "$VH_IN_TIMEOUT"
  VH_APPLY_STAGE=changing
  arm_restore "$timeout_s" apply || apply_fail '无法布置自动恢复；不会继续修改 SSH'

  printf '== 3/6 SSH\n'
  apply_ssh
  printf '== 4/6 UFW\n'
  apply_ufw
  printf '== 5/6 Fail2ban\n'
  apply_fail2ban
  printf '== 6/6 自动安全更新\n'
  apply_auto_updates

  record_digests
  rearm_timer "$timeout_s" || apply_fail '无法重新计时'
  state_set status pending
  state_set applied_at "$(utc_now)"
  # shellcheck disable=SC2034 # read by the ERR trap in bin/vps-hardening
  VH_ABORT_HOOK=''
  VH_APPLY_STAGE=finished
  vh_log 'apply done, pending confirmation'
  apply_done_message
}

install_missing_packages() {
  local pkg missing=()
  for pkg in "${VH_PACKAGES[@]}"; do
    pkg_installed "$pkg" || missing+=("$pkg")
  done
  state_set packages_added "${missing[*]}"
  if [ "${#missing[@]}" -eq 0 ]; then
    printf '软件包都已安装\n'
    return 0
  fi
  printf '安装：%s（输出写入 %s）\n' "${missing[*]}" "$VH_LOG_FILE"
  if ! DEBIAN_FRONTEND=noninteractive timeout --kill-after=30 "$VH_APT_TIMEOUT" \
    apt-get -q -y --no-install-recommends \
    -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
    install "${missing[@]}" </dev/null >>"$VH_LOG_FILE" 2>&1; then
    apply_fail "安装软件包失败，详见 $VH_LOG_FILE"
  fi
}

# write_managed PATH: content on stdin, mode 0644, replaced atomically.
write_managed() {
  cat >"$1.vh-new"
  chmod 0644 "$1.vh-new"
  mv -f -- "$1.vh-new" "$1"
}

sshd_dropin_content() {
  printf '# Managed by vps-hardening (requirements FR-04). verify reports any change.\n'
  printf 'PermitRootLogin prohibit-password\n'
  printf 'PasswordAuthentication no\n'
  printf 'KbdInteractiveAuthentication no\n'
  printf 'PubkeyAuthentication yes\n'
  if [ "${#VH_DENIED_USERS[@]}" -gt 0 ]; then
    printf 'DenyUsers %s\n' "${VH_DENIED_USERS[*]}"
  fi
}

# sshd_expect USER KEYWORD ALLOWED...: the on-disk configuration evaluated for USER.
sshd_expect() {
  local user="$1" key="$2" value
  shift 2
  value="$(sshd_effective "$user" | sshd_value "$key")"
  case " $* " in
    *" $value "*) return 0 ;;
  esac
  apply_fail "sshd 对 $user 的 $key 为 ${value:-（空）}，应为 $(join_by ' 或 ' "$@")；已撤销 SSH 片段"
}

apply_ssh() {
  local user
  sshd_dropin_content | write_managed "$VH_SSHD_DROPIN_DIR/$VH_SSHD_DROPIN_NAME"
  bounded /usr/sbin/sshd -t >"$VH_TMP/sshd-t.err" 2>&1 ||
    apply_fail "sshd 配置检查失败：$(head -n 1 "$VH_TMP/sshd-t.err")"
  sshd_cache_clear
  sshd_effective root >/dev/null || apply_fail "无法读取 sshd 生效配置：$(head -n 1 "$VH_TMP/sshd-T.err")"
  sshd_expect root permitrootlogin without-password prohibit-password
  sshd_expect root passwordauthentication no
  sshd_expect root kbdinteractiveauthentication no
  sshd_expect root pubkeyauthentication yes
  sshd_expect root port 22
  sshd_expect root allowtcpforwarding yes local
  for user in "${VH_DENIED_USERS[@]}"; do
    sshd_effective "$user" | sshd_values denyusers | grep -qxF -- "$user" ||
      apply_fail "DenyUsers 对 $user 没有生效"
    sshd_expect "$user" passwordauthentication no
    sshd_expect "$user" kbdinteractiveauthentication no
  done
  bounded_change systemctl try-reload-or-restart ssh.service || apply_fail 'sshd 重新加载失败'
  printf 'sshd 已按新配置重新加载\n'
}

# ufw_port_rule [delete] PORT/PROTO/FAMILY: allow a declared public port, or
# delete that rule (FR-14). The deletion names the comment too, so that it
# matches the rule exactly.
ufw_port_rule() {
  local verb=(allow) port proto family
  if [ "$1" = delete ]; then
    verb=(delete allow)
    shift
  fi
  IFS=/ read -r port proto family <<<"$1"
  case "$family" in
    both) bounded_change ufw "${verb[@]}" "$port/$proto" comment "$VH_UFW_COMMENT" ;;
    ipv4) bounded_change ufw "${verb[@]}" proto "$proto" to 0.0.0.0/0 port "$port" comment "$VH_UFW_COMMENT" ;;
    ipv6) bounded_change ufw "${verb[@]}" proto "$proto" to ::/0 port "$port" comment "$VH_UFW_COMMENT" ;;
  esac
}

# Called in a condition, where errexit is off: every step is checked.
ufw_configure() {
  local spec
  if ! grep -qx 'IPV6=yes' /etc/default/ufw; then
    if grep -q '^IPV6=' /etc/default/ufw; then
      sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw || return 1
    else
      printf 'IPV6=yes\n' >>/etc/default/ufw || return 1
    fi
  fi
  bounded_change ufw default deny incoming || return 1
  bounded_change ufw default allow outgoing || return 1
  bounded_change ufw default deny routed || return 1
  bounded_change ufw allow 22/tcp comment "$VH_UFW_COMMENT" || return 1
  for spec in "${VH_IN_OPEN[@]}"; do
    ufw_port_rule "$spec" || return 1
  done
}

apply_ufw() {
  ufw_configure >>"$VH_LOG_FILE" 2>&1 || apply_fail "UFW 规则写入失败，详见 $VH_LOG_FILE"
  # FR-05: 22/tcp must be allowed before the firewall is enabled.
  ufw_added_rules | ufw_rules_allow_port 22 || apply_fail 'UFW 中没有放行 22/tcp 的规则，不会启用防火墙'
  if ! unit_enabled ufw.service; then
    bounded_change systemctl enable --quiet ufw.service || apply_fail '无法设置 ufw.service 开机启动'
  fi
  bounded_change ufw --force enable >>"$VH_LOG_FILE" 2>&1 || apply_fail "UFW 启用失败，详见 $VH_LOG_FILE"
  ufw_active || apply_fail 'UFW 启用后状态不是 active'
  ufw_status_rules >"$VH_UFW_RULES_FILE"
  printf 'UFW 已启用：%s 条规则\n' "$(wc -l <"$VH_UFW_RULES_FILE")"
}

f2b_jail_content() {
  cat <<'EOF'
# Managed by vps-hardening (requirements FR-08). verify reports any change.
[sshd]
enabled = true
port = 22
protocol = tcp
backend = systemd
journalmatch = _SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session
mode = normal
banaction = nftables
banaction_allports = nftables[type=allports]
bantime = 1d
findtime = 10m
maxretry = 5
bantime.increment = true
bantime.maxtime = 4w
bantime.rndtime = 10m
ignoreself = true
ignoreip = 127.0.0.1/8 ::1
usedns = no
EOF
}

# f2b_wait: the server answers and the sshd jail runs (start takes a while under emulation).
f2b_wait() {
  local i
  for i in $(seq 60); do
    if bounded fail2ban-client ping >/dev/null 2>&1 && bounded fail2ban-client status sshd >/dev/null 2>&1; then
      return 0
    fi
    [ "$i" -eq 60 ] || sleep 2
  done
  return 1
}

f2b_expect() {
  local value
  value="$(bounded fail2ban-client get sshd "$1" 2>/dev/null)" || value=''
  [ "$value" = "$2" ] || apply_fail "Fail2ban 的 $1 为 ${value:-（空）}，应为 $2"
}

apply_fail2ban() {
  local jails
  f2b_jail_content | write_managed "$VH_F2B_JAIL"
  printf '# Managed by vps-hardening (requirements FR-08).\n[Definition]\ndbpurgeage = 30d\n' |
    write_managed "$VH_F2B_LOCAL"
  bounded fail2ban-client -t >>"$VH_LOG_FILE" 2>&1 || apply_fail "Fail2ban 配置检查失败，详见 $VH_LOG_FILE"
  bounded_change systemctl enable --quiet fail2ban.service || apply_fail '无法设置 fail2ban.service 开机启动'
  bounded_change systemctl restart fail2ban.service || apply_fail 'fail2ban.service 启动失败'
  f2b_wait || apply_fail 'fail2ban 启动后 sshd jail 没有运行'
  jails="$(bounded fail2ban-client status 2>/dev/null | sed -n 's/^.*Jail list:[[:space:]]*//p')"
  [ "$jails" = sshd ] || apply_fail "Fail2ban 的 jail 应只有 sshd，实际为：${jails:-（空）}"
  f2b_expect maxretry 5
  f2b_expect findtime 600
  f2b_expect bantime 86400
  printf 'Fail2ban 已启用：sshd jail\n'
}

# The ${distro_*} placeholders are literal: unattended-upgrades expands them.
# shellcheck disable=SC2016
apt_conf_content() {
  printf '// Managed by vps-hardening (requirements FR-09). verify reports any change.\n'
  printf 'APT::Periodic::Update-Package-Lists "1";\n'
  printf 'APT::Periodic::Unattended-Upgrade "1";\n'
  printf 'Unattended-Upgrade::Automatic-Reboot "false";\n'
  printf '#clear Unattended-Upgrade::Origins-Pattern;\n'
  printf '#clear Unattended-Upgrade::Allowed-Origins;\n'
  case "$VH_OS_ID" in
    debian)
      printf 'Unattended-Upgrade::Origins-Pattern {\n'
      printf '  "origin=Debian,codename=${distro_codename},label=Debian";\n'
      printf '  "origin=Debian,codename=${distro_codename},label=Debian-Security";\n'
      printf '  "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";\n'
      printf '};\n'
      ;;
    ubuntu)
      printf 'Unattended-Upgrade::Allowed-Origins {\n'
      printf '  "${distro_id}:${distro_codename}-security";\n'
      printf '  "${distro_id}ESMApps:${distro_codename}-apps-security";\n'
      printf '  "${distro_id}ESM:${distro_codename}-infra-security";\n'
      printf '};\n'
      ;;
  esac
}

apply_auto_updates() {
  apt_conf_content | write_managed "$VH_APT_CONF"
  rm -f -- "$VH_TMP/apt-config"
  [ "$(apt_config_scalar APT::Periodic::Update-Package-Lists)" = 1 ] &&
    [ "$(apt_config_scalar APT::Periodic::Unattended-Upgrade)" = 1 ] ||
    apply_fail 'APT::Periodic 的生效值不是 1'
  [ "$(apt_config_scalar Unattended-Upgrade::Automatic-Reboot)" = false ] ||
    apply_fail 'Unattended-Upgrade::Automatic-Reboot 的生效值不是 false'
  diff <(expected_auto_update_origins | sort -u) <(actual_auto_update_origins | sort -u) >/dev/null ||
    apply_fail '自动更新来源的生效值与 FR-09 不一致'
  bounded_change systemctl enable --quiet --now apt-daily.timer apt-daily-upgrade.timer ||
    apply_fail '无法启用 APT 定时器'
  printf '自动安全更新已启用\n'
}

# FR-13: digests of the managed files after the change, for verify.
record_digests() {
  local path
  for path in "${VH_MANAGED_FILES[@]}"; do
    record_digest "$path"
  done
}

apply_done_message() {
  local deadline
  deadline="$(state_get deadline "$VH_PENDING_FILE")"
  printf '\n加固已应用，等待确认。\n'
  printf '确认截止：%s（%s 分钟后）\n' "$(date -u -d "@$deadline" '+%Y-%m-%d %H:%M:%S UTC')" "$VH_IN_TIMEOUT"
  printf '请保持当前会话，另开一个终端，用 root 的密钥登录后执行：\n'
  printf '  %s confirm\n' "$VH_SELF"
  printf '到期未确认，或在此之前重启，都会自动恢复到应用前的配置。\n\n'
  print_tunnel_hint
}
