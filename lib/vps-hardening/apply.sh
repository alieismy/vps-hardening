# shellcheck shell=bash
# apply (design 7.3): preflight, confirmation, then the changes, inside the
# automatic-restore window armed before the first change to the login path.

readonly VH_F2B_JAIL=/etc/fail2ban/jail.d/99-vps-hardening.local
readonly VH_F2B_LOCAL=/etc/fail2ban/fail2ban.local
# FR-08's journalmatch. The last two terms select sshd's records by the
# identifier it sends and the UID the kernel attests, for records journald
# could not give _COMM and _SYSTEMD_UNIT (requirements D84).
readonly VH_F2B_JOURNALMATCH='_SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session + SYSLOG_IDENTIFIER=sshd _UID=0 + SYSLOG_IDENTIFIER=sshd-session _UID=0'
# The value v0.1.0 to v0.2.0 wrote; update-fail2ban replaces it.
readonly VH_F2B_JOURNALMATCH_V1='_SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session'
readonly VH_APT_CONF=/etc/apt/apt.conf.d/52vps-hardening
readonly VH_UFW_COMMENT=vps-hardening
# Bound for package installation, which runs before the restore is armed.
readonly VH_APT_TIMEOUT=1800
# Wait for the dpkg lock, within that bound: unattended-upgrades may start
# between preflight's apt.idle check and the install.
readonly VH_APT_LOCK_WAIT=600

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
  apply_endpoint_recheck || refuse "交互期间 SSH 入口变化：$VH_SSH_ERROR；未做变更"
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
  printf '\n- UFW：拒绝入站、允许出站、拒绝转发；放行 %s/tcp%s；面板端口 %s 不放行\n' \
    "$VH_SSH_PORT" "$([ "${#opens[@]}" -eq 0 ] || printf '、%s' "$(join_by '、' "${opens[@]}")")" "$VH_IN_PANEL_PORT"
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
  rm -rf -- "$VH_STATE_FILE" "$VH_UNITS_FILE" "$VH_SNAPSHOT_DIR" "$VH_PORTS_SNAPSHOT_DIR"
  state_set status applying
  VH_APPLY_STAGE=prepare
  VH_ABORT_HOOK=apply_abort
  state_set version "$VH_VERSION"
  state_set record_format "$VH_RECORD_FORMAT"
  state_set ssh_port "$VH_SSH_PORT"
  state_set ssh_activation "$VH_SSH_ACTIVATION"
  state_set ssh_listeners "$VH_SSH_LISTENERS"
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
  ssh_endpoint_check_record || apply_fail "软件包安装后 SSH 入口不一致：$VH_SSH_ERROR"
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
  # fail2ban's postinst starts the service at once with the package's own
  # jail, whose 10-minute bans of sources in the journal backlog would outlast
  # the restart in step 5 (design 8.8). Held back for the install (f2b_hold),
  # it first starts in step 5 with FR-08's settings. The state records the
  # hold first, so that every restore path removes it (f2b_release).
  if [[ " ${missing[*]} " == *' fail2ban '* ]]; then
    state_set f2b_install_hold yes
    f2b_hold || apply_fail '无法在安装软件包期间阻止 fail2ban.service 启动'
  fi
  if ! DEBIAN_FRONTEND=noninteractive timeout --kill-after=30 "$VH_APT_TIMEOUT" \
    apt-get -q -y --no-install-recommends -o DPkg::Lock::Timeout="$VH_APT_LOCK_WAIT" \
    -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
    install "${missing[@]}" </dev/null >>"$VH_LOG_FILE" 2>&1; then
    apply_fail "安装软件包失败，详见 $VH_LOG_FILE"
  fi
  f2b_release runtime || apply_fail '无法撤除安装期间对 fail2ban.service 的阻止'
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
  ssh_endpoint_check_record || apply_fail "SSH 写入前入口不一致：$VH_SSH_ERROR"
  sshd_dropin_content | write_managed "$VH_SSHD_DROPIN_DIR/$VH_SSHD_DROPIN_NAME"
  bounded /usr/sbin/sshd "${VH_SSHD_ARGS[@]}" -t >"$VH_TMP/sshd-t.err" 2>&1 ||
    apply_fail "sshd 配置检查失败：$(head -n 1 "$VH_TMP/sshd-t.err")"
  sshd_cache_clear
  sshd_effective root >/dev/null || apply_fail "无法读取 sshd 生效配置：$(head -n 1 "$VH_TMP/sshd-T.err")"
  sshd_expect root permitrootlogin without-password prohibit-password
  sshd_expect root passwordauthentication no
  sshd_expect root kbdinteractiveauthentication no
  sshd_expect root pubkeyauthentication yes
  sshd_expect root allowtcpforwarding yes local
  for user in "${VH_DENIED_USERS[@]}"; do
    sshd_effective "$user" | sshd_values denyusers | grep -qxF -- "$user" ||
      apply_fail "DenyUsers 对 $user 没有生效"
    sshd_expect "$user" passwordauthentication no
    sshd_expect "$user" kbdinteractiveauthentication no
  done
  ssh_endpoint_check_record || apply_fail "SSH 配置写入后入口不一致：$VH_SSH_ERROR"
  bounded_change systemctl try-reload-or-restart ssh.service || apply_fail 'sshd 重新加载失败'
  ssh_endpoint_check_record discover-after-reload || apply_fail "SSH 重载后入口不一致：$VH_SSH_ERROR"
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
  bounded_change ufw allow "$VH_SSH_PORT/tcp" comment "$VH_UFW_COMMENT" || return 1
  for spec in "${VH_IN_OPEN[@]}"; do
    ufw_port_rule "$spec" || return 1
  done
}

apply_ufw() {
  ssh_endpoint_check_record || apply_fail "UFW 写入前 SSH 入口不一致：$VH_SSH_ERROR"
  ufw_configure >>"$VH_LOG_FILE" 2>&1 || apply_fail "UFW 规则写入失败，详见 $VH_LOG_FILE"
  # FR-05: both family rules must exist before enabling the firewall.
  ufw_ssh_rules_ready || apply_fail "UFW 未完整放行 $VH_SSH_PORT/tcp，不会启用防火墙"
  if ! unit_enabled ufw.service; then
    bounded_change systemctl enable --quiet ufw.service || apply_fail '无法设置 ufw.service 开机启动'
  fi
  bounded_change ufw --force enable >>"$VH_LOG_FILE" 2>&1 || apply_fail "UFW 启用失败，详见 $VH_LOG_FILE"
  ufw_active || apply_fail 'UFW 启用后状态不是 active'
  printf 'UFW 已启用：%s 条规则\n' "$(ufw_status_rules | wc -l)"
}

# f2b_jail_content [JOURNALMATCH]: the jail file for P, with FR-08's
# journalmatch unless another is given (update-fail2ban, the legacy proof).
f2b_jail_content() {
  local journalmatch="${1:-$VH_F2B_JOURNALMATCH}"
  cat <<EOF
# Managed by vps-hardening (requirements FR-08). verify reports any change.
[sshd]
enabled = true
port = $VH_SSH_PORT
protocol = tcp
backend = systemd
journalmatch = $journalmatch
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
  [ "$(f2b_get sshd action nftables port)" = "$VH_SSH_PORT" ] || apply_fail "Fail2ban 运行中的封禁动作端口不是 $VH_SSH_PORT"
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

# Compare the initial read-only result again after the interactive prompt.
apply_endpoint_recheck() {
  local port="$VH_SSH_PORT" activation="$VH_SSH_ACTIVATION" listeners="$VH_SSH_LISTENERS"
  ssh_endpoint_discover || return 1
  if [ "$VH_SSH_PORT" != "$port" ] || [ "$VH_SSH_ACTIVATION" != "$activation" ] ||
    [ "$VH_SSH_LISTENERS" != "$listeners" ]; then
    VH_SSH_ERROR='SSH 端口、监听或启动方式与预检不一致'
    return 1
  fi
}

# UFW stores v4/v6 rules separately even on IPv4-only hosts. Check the rule
# generated by `ufw allow P/tcp` in each file, not only `ufw show added` (which
# collapses the two address families before enable).
ufw_ssh_rules_ready() {
  local file chain
  for file in /etc/ufw/user.rules /etc/ufw/user6.rules; do
    [ -r "$file" ] || return 1
    chain=ufw-user-input
    [ "$file" != /etc/ufw/user6.rules ] || chain=ufw6-user-input
    awk -v p="$VH_SSH_PORT" -v chain="$chain" '
      $1 == "-A" && $2 == chain {
        proto=0; port=0; accept=0; restricted=0
        for (i=3;i<NF;i++) {
          if ($i=="-p" && $(i+1)=="tcp") proto=1
          if ($i=="--dport" && $(i+1)==p) port=1
          if ($i=="-j" && $(i+1)=="ACCEPT") accept=1
          if ($i=="-s" || $i=="-d" || $i=="-i") restricted=1
        }
        if (proto && port && accept && !restricted) found=1
      }
      END {exit found ? 0 : 1}
    ' "$file" || return 1
  done
}

# update-fail2ban (requirements D84, design 2.14): on an applied host whose
# jail file is the one v0.1.0 to v0.2.0 wrote, write the current one. Only
# that file, its recorded digest and the Fail2ban service change; SSH and UFW
# do not, so there is no confirmation window: a failure puts the old content
# back at once.

# '': nothing written; written: the new file is in place; restarted: the
# service was restarted with it.
VH_F2B_UPDATE_STAGE=''
VH_F2B_JAIL_KIND=''

cmd_update_fail2ban() {
  [ "$#" -eq 0 ] || usage_error "update-fail2ban 不接受参数：$1"
  [ "$(id -u)" -eq 0 ] || refuse '需要 root 权限：请在 root shell 中运行'
  vh_tmp_init
  vh_lock 0 || refuse '另一个 vps-hardening 操作正在进行，请稍后再试'
  case "$(state_get status)" in
    applied) ;;
    pending) refuse '加固还在待确认：请先从新的 SSH 会话以 root 执行 confirm' ;;
    ports-pending) refuse '端口变更还在待确认：请先确认，或等它到期恢复' ;;
    '') refuse '本工具没有在这台主机上应用过：请先执行 apply' ;;
    *) refuse "本工具的状态为 $(state_get status)，不能更新 Fail2ban，详见 $VH_LOG_FILE" ;;
  esac
  printf '== 更新前检查\n'
  f2b_update_checks
  report_summary
  if [ "$VH_COUNT_FAIL" -gt 0 ]; then
    printf '\n更新前检查有不符合项，未做任何变更。\n'
    exit "$VH_EXIT_FAIL"
  fi
  if [ "$VH_F2B_JAIL_KIND" = current ]; then
    printf '\njail 文件已是当前版本，无需更新，未做任何变更。\n'
    exit "$VH_EXIT_OK"
  fi
  f2b_update_plan
  if ! f2b_update_prompt; then
    printf '已取消，未做任何变更。\n'
    exit "$VH_EXIT_FAIL"
  fi
  f2b_update_run
}

# f2b_jail_kind: the jail file against the record and the contents this tool
# writes for P: changed (not as recorded), current, old or other.
f2b_jail_kind() {
  if ! same_as_applied "$VH_F2B_JAIL"; then
    printf 'changed\n'
  elif cmp -s -- "$VH_F2B_JAIL" <(f2b_jail_content); then
    printf 'current\n'
  elif cmp -s -- "$VH_F2B_JAIL" <(f2b_jail_content "$VH_F2B_JOURNALMATCH_V1"); then
    printf 'old\n'
  else
    printf 'other\n'
  fi
}

f2b_update_checks() {
  if ssh_endpoint_report update.endpoint; then
    VH_F2B_JAIL_KIND="$(f2b_jail_kind)"
    case "$VH_F2B_JAIL_KIND" in
      current) report PASS update.jail "$VH_F2B_JAIL 已是当前版本" ;;
      old) report PASS update.jail "$VH_F2B_JAIL 是 v0.2.0 及以前写入的版本，可以更新" ;;
      changed) report FAIL update.jail "$VH_F2B_JAIL 与应用记录不一致：请先用 verify 查看并处理差异" ;;
      *) report FAIL update.jail "$VH_F2B_JAIL 不是本工具为 $VH_SSH_PORT/tcp 写入的任何版本" ;;
    esac
  else
    report SKIP update.jail 'SSH 入口未通过核对，无法确定 jail 的端口'
  fi
  if unit_active fail2ban.service && bounded fail2ban-client status sshd >/dev/null 2>&1; then
    report PASS update.service 'fail2ban 服务在运行，sshd jail 已启动'
  else
    report FAIL update.service 'fail2ban 服务没有运行，或 sshd jail 没有启动'
  fi
}

f2b_update_plan() {
  printf '\n== 将要执行的变更\n'
  printf -- '- 改写 %s 中的 journalmatch，其他设置不变：\n' "$VH_F2B_JAIL"
  printf '    原值：%s\n' "$VH_F2B_JOURNALMATCH_V1"
  printf '    新值：%s\n' "$VH_F2B_JOURNALMATCH"
  printf -- '- 重启 fail2ban 服务：已有的封禁由 Fail2ban 从它的数据库恢复\n'
  printf -- '- 不修改 SSH、UFW 和其他文件，没有确认时限；失败时立即恢复原文件\n'
}

# SSH and UFW do not change, so apply's two safeguards are not asked for.
f2b_update_prompt() {
  local answer=''
  printf '\n确认更新请输入 yes：'
  read -r answer || return 1
  [ "$answer" = yes ]
}

f2b_update_run() {
  [ "$(f2b_jail_kind)" = old ] || refuse '交互期间 jail 文件发生变化，未做变更'
  trap 'f2b_update_signal INT' INT
  trap 'f2b_update_signal TERM' TERM
  trap 'f2b_update_signal HUP' HUP
  VH_ABORT_HOOK=f2b_update_abort
  vh_log 'update-fail2ban started: journalmatch to the current value'
  printf '\n正在更新……\n'
  VH_F2B_UPDATE_STAGE=written
  f2b_jail_content | write_managed "$VH_F2B_JAIL"
  bounded fail2ban-client -t >>"$VH_LOG_FILE" 2>&1 || f2b_update_fail "Fail2ban 配置检查失败，详见 $VH_LOG_FILE"
  VH_F2B_UPDATE_STAGE=restarted
  bounded_change systemctl restart fail2ban.service || f2b_update_fail 'fail2ban.service 重启失败'
  f2b_wait || f2b_update_fail 'fail2ban 重启后 sshd jail 没有运行'
  [ "$(f2b_get sshd journalmatch)" = "$VH_F2B_JOURNALMATCH" ] || f2b_update_fail 'Fail2ban 运行中的 journalmatch 不是新值'
  record_digest "$VH_F2B_JAIL" || f2b_update_fail '无法记录 jail 文件的摘要'
  # shellcheck disable=SC2034 # read by the ERR trap in bin/vps-hardening
  VH_ABORT_HOOK=''
  VH_F2B_UPDATE_STAGE=finished
  trap - INT TERM HUP
  vh_log 'update-fail2ban done'
  printf 'Fail2ban 已更新，运行中的 journalmatch 为新值。请执行 vps-hardening verify 核对。\n'
}

# Put the old content back, and restart the service again if it was restarted.
f2b_update_undo() {
  local reason="$1" stage="$VH_F2B_UPDATE_STAGE" restarted=''
  trap '' INT TERM HUP
  # shellcheck disable=SC2034 # read by the ERR trap in bin/vps-hardening
  VH_ABORT_HOOK=''
  VH_F2B_UPDATE_STAGE=''
  vh_log "update-fail2ban failed: $reason"
  [ -n "$stage" ] || return 0
  printf '正在恢复原来的 jail 文件……\n' >&2
  if ! f2b_jail_content "$VH_F2B_JOURNALMATCH_V1" | write_managed "$VH_F2B_JAIL"; then
    printf '[x] 无法恢复 %s：请执行 vps-hardening verify 查看\n' "$VH_F2B_JAIL" >&2
    return 0
  fi
  if [ "$stage" = restarted ]; then
    if ! { bounded_change systemctl restart fail2ban.service && f2b_wait; }; then
      printf '[x] 已恢复原来的 jail 文件，但 fail2ban 没有正常运行：请执行 systemctl status fail2ban 查看\n' >&2
      return 0
    fi
    restarted='，fail2ban 已按它重启'
  fi
  if same_as_applied "$VH_F2B_JAIL"; then
    printf '已恢复原来的 jail 文件%s。\n' "$restarted" >&2
  else
    printf '[x] 已恢复原来的 jail 文件%s，但它与应用记录的摘要不同：请执行 vps-hardening verify 查看\n' "$restarted" >&2
  fi
}

f2b_update_fail() {
  printf '[x] %s\n' "$*" >&2
  f2b_update_undo "$*"
  exit "$VH_EXIT_FAIL"
}

# ERR trap hook (bin/vps-hardening).
f2b_update_abort() {
  f2b_update_undo '更新中出现内部错误'
}

f2b_update_signal() {
  trap '' INT TERM HUP
  [ "$1" != HUP ] || output_to_log
  f2b_update_fail "收到信号 $1"
}
