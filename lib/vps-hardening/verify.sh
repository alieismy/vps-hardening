# shellcheck shell=bash
# Read-only verification (FR-10). Never changes files, services or rules.
#
# Checks that need the apply record (declared ports, file digests) report SKIP
# while there is no applied or pending record.

cmd_verify() {
  [ "$#" -eq 0 ] || usage_error "verify 不接受参数：$1"
  vh_tmp_init
  if verify_gate; then
    verify_state
    verify_accounts
    verify_ssh
    verify_ufw
    verify_fail2ban
    verify_nftables
    verify_auto_updates
    verify_boundary
    verify_reboot
  fi
  finish_checks
}

verify_gate() {
  if [ "$(id -u)" -ne 0 ]; then
    report FAIL root '需要 root 权限：请在 root shell 中运行，或使用 sudo'
    return 1
  fi
  detect_platform
  if [ -z "$VH_PLATFORM" ]; then
    report FAIL platform "不支持的平台：${VH_OS_PRETTY:-未知系统}（${VH_ARCH}）"
    return 1
  fi
  report PASS platform "$VH_OS_PRETTY（$VH_ARCH）"
}

skip_without_state() {
  report SKIP "$1" '没有应用记录，无法核对声明值'
}

# True when apply finished, confirmed or not: its declared values are on record.
have_record() {
  case "$(state_get status)" in
    applied | pending) return 0 ;;
  esac
  return 1
}

# Digest apply recorded for a managed file.
recorded_digest() {
  local key
  for key in $(seq 0 $((${#VH_MANAGED_FILES[@]} - 1))); do
    state_get "digest.$key" | awk -v path="$1" '$2 == path { print $1 }'
  done
}

# True when a managed file still has the digest apply recorded.
same_as_applied() {
  local digest
  digest="$(recorded_digest "$1")"
  [ -n "$digest" ] && [ "$(file_digest "$1")" = "$digest" ]
}

verify_state() {
  local deadline left
  if [ ! -e "$VH_STATE_DIR" ]; then
    report FAIL state '未应用：没有本工具的应用记录'
    return 0
  fi
  case "$(state_get status)" in
    applied) report PASS state "已应用，确认于 $(state_get confirmed_at)" ;;
    pending)
      deadline="$(state_get deadline "$VH_PENDING_FILE")"
      left=$(((${deadline:-0} - $(date +%s) + 59) / 60))
      report WARN state "待确认：约 $left 分钟后自动恢复，请从新的 SSH 会话以 root 执行 confirm"
      ;;
    rolled-back) report FAIL state "已回滚：$(state_get rollback_reason)" ;;
    *) report FAIL state "状态为 $(state_get status | sed 's/^$/未知/')，详见 $VH_LOG_FILE" ;;
  esac
}

verify_accounts() {
  local accounts user offenders=()
  accounts="$(nopasswd_key_accounts)"
  for user in $accounts; do
    account_denied_by_sshd "$user" || offenders+=("$user")
  done
  if [ "${#offenders[@]}" -gt 0 ]; then
    report FAIL accounts.nopasswd "$(join_by '、' "${offenders[@]}") 有免密 sudo，且仍可经 SSH 登录"
  else
    report PASS accounts.nopasswd '可经 SSH 登录的账户都没有免密 sudo'
  fi
}

# expect_sshd ID USER KEYWORD ALLOWED...
expect_sshd() {
  local id="$1" user="$2" key="$3" value
  shift 3
  value="$(sshd_effective "$user" | sshd_value "$key")"
  case " $* " in
    *" $value "*) report PASS "$id" "$key $value" ;;
    *) report FAIL "$id" "$key 为 ${value:-（空）}，应为 $(join_by ' 或 ' "$@")" ;;
  esac
}

verify_ssh() {
  local addrs v4=0 v6=0

  if ! sshd_effective root >/dev/null; then
    report FAIL ssh.config "无法读取 sshd 生效配置：$(head -n 1 "$VH_TMP/sshd-T.err")"
    return 0
  fi
  # sshd -T prints prohibit-password under its older name.
  expect_sshd ssh.permitrootlogin root permitrootlogin without-password prohibit-password
  expect_sshd ssh.passwordauthentication root passwordauthentication no
  expect_sshd ssh.kbdinteractive root kbdinteractiveauthentication no
  expect_sshd ssh.pubkey root pubkeyauthentication yes
  expect_sshd ssh.forwarding root allowtcpforwarding yes local
  expect_sshd ssh.port root port 22
  if have_record; then
    verify_ssh_record
  else
    skip_without_state ssh.dropin
  fi
  check_root_keys

  # A dual-stack socket (Ubuntu's ssh.socket) is listed as *.
  addrs=" $(tcp_listen_addresses 22 | paste -sd ' ') "
  case "$addrs" in
    *' 0.0.0.0 '* | *' * '*) v4=1 ;;
  esac
  case "$addrs" in
    *' [::] '* | *' * '*) v6=1 ;;
  esac
  if [ "$v4" -eq 0 ]; then
    report FAIL ssh.listen '22 端口没有在全部 IPv4 地址上监听'
  elif [ "$v6" -eq 0 ]; then
    report WARN ssh.listen '22 端口只在 IPv4 上监听'
  else
    report PASS ssh.listen '22 端口在 IPv4 和 IPv6 上监听'
  fi
}

verify_ssh_record() {
  local dropin="$VH_SSHD_DROPIN_DIR/$VH_SSHD_DROPIN_NAME" user value bad
  if same_as_applied "$dropin"; then
    report PASS ssh.dropin "$dropin 与应用时一致"
  else
    report FAIL ssh.dropin "$dropin 被修改或删除"
  fi
  # FR-04: the accounts denied by D13 are evaluated on their own too.
  for user in $(state_get denied_users); do
    bad=''
    sshd_effective "$user" | sshd_values denyusers | grep -qxF -- "$user" || bad='不在 DenyUsers 中'
    for value in passwordauthentication kbdinteractiveauthentication; do
      [ "$(sshd_effective "$user" | sshd_value "$value")" = no ] || bad="${bad:+$bad；}$value 不是 no"
    done
    if [ -z "$bad" ]; then
      report PASS ssh.denied "$user 被禁止经 SSH 登录"
    else
      report FAIL ssh.denied "$user：$bad"
    fi
  done
}

verify_ufw() {
  local status

  if ! have ufw; then
    report FAIL ufw.installed 'UFW 未安装'
    return 0
  fi
  report PASS ufw.installed 'UFW 已安装'
  status="$(bounded ufw status verbose 2>/dev/null)" || status=''
  if ! printf '%s\n' "$status" | grep -qx 'Status: active'; then
    report FAIL ufw.active 'UFW 未启用'
  else
    report PASS ufw.active 'UFW 已启用'
    # While the kernel does not forward, ufw shows the routed policy as
    # "disabled"; the configured policy is in /etc/default/ufw either way.
    if printf '%s\n' "$status" | grep -qxE 'Default: deny \(incoming\), allow \(outgoing\), (deny|disabled) \(routed\)' &&
      grep -qx 'DEFAULT_FORWARD_POLICY="DROP"' /etc/default/ufw 2>/dev/null; then
      report PASS ufw.defaults '默认拒绝入站、允许出站、拒绝转发'
    else
      report FAIL ufw.defaults "默认策略不符合：$(printf '%s\n' "$status" | grep '^Default:' || printf '未知')；$(grep '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw 2>/dev/null || printf 'DEFAULT_FORWARD_POLICY 未设置')"
    fi
  fi

  if grep -qx 'IPV6=yes' /etc/default/ufw 2>/dev/null; then
    report PASS ufw.ipv6 'IPV6=yes'
  else
    report FAIL ufw.ipv6 '/etc/default/ufw 中不是 IPV6=yes'
  fi

  if ufw_added_rules | ufw_rules_allow_port 80; then
    report FAIL ufw.port80 '存在放行 80 端口的规则（D14 要求不开放）'
  else
    report PASS ufw.port80 '没有放行 80 端口的规则'
  fi
  if have_record; then
    verify_ufw_record
  else
    skip_without_state ufw.rules
    skip_without_state ufw.panel
  fi
}

# FR-06: exactly the rules apply wrote, none for the panel port.
verify_ufw_record() {
  local panel
  if [ -f "$VH_UFW_RULES_FILE" ] && diff <(sort "$VH_UFW_RULES_FILE") <(ufw_status_rules | sort) >"$VH_TMP/ufw.diff"; then
    report PASS ufw.rules "规则与应用时一致（$(wc -l <"$VH_UFW_RULES_FILE") 条，IPv4 和 IPv6 分别计）"
  else
    report FAIL ufw.rules "规则与应用时不一致：$(grep -E '^[<>]' "$VH_TMP/ufw.diff" 2>/dev/null | sed 's/^</缺少 /; s/^>/多出 /; s/  */ /g' | paste -sd ';')"
  fi
  panel="$(state_get panel_port)"
  if ufw_added_rules | ufw_rules_allow_port "$panel"; then
    report FAIL ufw.panel "存在放行面板端口 $panel 的规则（面板只经 SSH 隧道访问）"
  else
    report PASS ufw.panel "没有放行面板端口 $panel 的规则"
  fi
}

# Reads `ufw show added` rule lines on stdin; true when an inbound allow or
# limit rule names the port, alone or in a list (80, 80/tcp, port 80,443).
ufw_rules_allow_port() {
  awk -v port="$1" '
    function names(spec, n, parts, i) {
      sub(/\/(tcp|udp)$/, "", spec)
      n = split(spec, parts, ",")
      for (i = 1; i <= n; i++) if (parts[i] == port) return 1
      return 0
    }
    $1 == "allow" || $1 == "limit" {
      if ($2 == "out") next
      for (i = 2; i <= NF; i++) {
        if ($i == "port" && names($(i + 1))) found = 1
        if ($i ~ /^[0-9,]+(\/(tcp|udp))?$/ && $(i - 1) != "port" && names($i)) found = 1
      }
    }
    END { exit found ? 0 : 1 }
  '
}

# FR-08 values as `fail2ban-client get` reports them, as "ARGS|VALUE" after
# f2b_get: times in seconds, 127.0.0.1/8 as the network 127.0.0.0/8. Only a
# systemd-backend jail has a journalmatch. The mode and the banaction cannot
# be read back from the server; f2b.files covers them through the jail file.
f2b_expected_values() {
  cat <<'EOF'
sshd bantime|86400
sshd findtime|600
sshd maxretry|5
sshd bantime.increment|True
sshd bantime.maxtime|2419200
sshd bantime.rndtime|600
sshd ignoreself|True
sshd ignoreip|127.0.0.0/8 ::1
sshd usedns|no
sshd journalmatch|_SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session
sshd actions|nftables
sshd action nftables port|22
sshd action nftables protocol|tcp
dbpurgeage|2592000
EOF
}

# f2b_get ARGS...: the value `fail2ban-client get ARGS...` prints, on one line.
# A value spanning lines has a header line first ("Current match filter:")
# and may mark list items with "|- " or "`- "; items are sorted and joined.
f2b_get() {
  local out
  out="$(bounded fail2ban-client get "$@" 2>/dev/null)" || return 1
  if [ "$(wc -l <<<"$out")" -gt 1 ]; then
    out="$(sed '1d' <<<"$out")"
  fi
  sed -E 's/^[|`]- //; s/^([0-9]+)seconds$/\1/' <<<"$out" | sort | paste -sd ' '
}

verify_fail2ban() {
  local jails responding=0 out

  if ! pkg_installed fail2ban; then
    report FAIL f2b.installed 'Fail2ban 未安装'
    return 0
  fi
  report PASS f2b.installed 'Fail2ban 已安装'

  if unit_enabled fail2ban.service && unit_active fail2ban.service; then
    report PASS f2b.service 'fail2ban 服务已启用并在运行'
  else
    report FAIL f2b.service 'fail2ban 服务没有启用或没有运行'
  fi

  if out="$(bounded fail2ban-client -t 2>&1)"; then
    report PASS f2b.config '配置检查通过（fail2ban-client -t）'
  else
    report FAIL f2b.config "配置检查失败：$(grep -m 1 -E 'ERROR|Error|error' <<<"$out" || head -n 1 <<<"$out")"
  fi

  if bounded fail2ban-client ping >/dev/null 2>&1; then
    responding=1
    jails="$(bounded fail2ban-client status 2>/dev/null | sed -n 's/^.*Jail list:[[:space:]]*//p')"
    if [ "$jails" = sshd ]; then
      report PASS f2b.jails '只有 sshd 一个 jail'
    else
      report FAIL f2b.jails "jail 列表应只有 sshd，实际为：${jails:-（空）}"
    fi
  else
    report FAIL f2b.jails 'fail2ban 服务没有响应'
  fi

  if [ "$responding" -eq 1 ]; then
    verify_fail2ban_values
  else
    report FAIL f2b.values 'fail2ban 服务没有响应，无法读取生效值'
  fi
  if have_record; then
    verify_fail2ban_files
  else
    skip_without_state f2b.files
  fi

  if dpkg --verify fail2ban 2>/dev/null | grep -qE ' /etc/fail2ban/(jail|fail2ban)\.conf$'; then
    report FAIL f2b.mainconf 'jail.conf 或 fail2ban.conf 被修改过'
  else
    report PASS f2b.mainconf 'jail.conf 和 fail2ban.conf 保持发行版原样'
  fi
}

# FR-08: the values the server uses, compared with f2b_expected_values.
verify_fail2ban_values() {
  local args want got count=0 bad=()
  while IFS='|' read -r args want; do
    count=$((count + 1))
    # shellcheck disable=SC2086 # ARGS is several words.
    got="$(f2b_get $args)" || got='（读取失败）'
    [ "$got" = "$want" ] || bad+=("${args#sshd } 为 ${got:-（空）}，应为 $want")
  done < <(f2b_expected_values)
  if [ "${#bad[@]}" -gt 0 ]; then
    report FAIL f2b.values "生效值与 FR-08 不一致：$(join_by '；' "${bad[@]}")"
  else
    report PASS f2b.values "生效值与 FR-08 一致（$count 项）"
  fi
}

# FR-08: the tool's two files as applied, and no other configuration that
# could change the jail: files the package did not install, or package files
# changed (jail.conf and fail2ban.conf are reported by f2b.mainconf).
verify_fail2ban_files() {
  local path extra changed bad=()
  for path in "$VH_F2B_JAIL" "$VH_F2B_LOCAL"; do
    same_as_applied "$path" || bad+=("$path 被修改或删除")
  done
  extra="$(comm -23 <(find /etc/fail2ban ! -type d 2>/dev/null | sort) \
    <({ dpkg-query -L fail2ban 2>/dev/null; printf '%s\n' "$VH_F2B_JAIL" "$VH_F2B_LOCAL"; } | sort -u) | paste -sd ' ')"
  [ -z "$extra" ] || bad+=("多出的配置文件：$extra")
  changed="$(dpkg --verify fail2ban 2>/dev/null | awk '{ print $NF }' |
    grep -vxE '/etc/fail2ban/(jail|fail2ban)\.conf' | paste -sd ' ')" || true
  [ -z "$changed" ] || bad+=("被修改的软件包文件：$changed")
  if [ "${#bad[@]}" -gt 0 ]; then
    report FAIL f2b.files "$(join_by '；' "${bad[@]}")"
  else
    report PASS f2b.files '本工具的两个配置文件与应用时一致，没有其他覆盖配置'
  fi
}

verify_nftables() {
  if unit_enabled nftables.service; then
    report FAIL nft.service 'nftables.service 已启用：它的默认配置开机时会清空全部规则'
  else
    report PASS nft.service 'nftables.service 未启用'
  fi
}

# The ${distro_*} placeholders are literal: unattended-upgrades expands them.
# shellcheck disable=SC2016
expected_auto_update_origins() {
  case "$VH_OS_ID" in
    debian)
      printf 'Origins-Pattern\torigin=Debian,codename=${distro_codename},label=Debian\n'
      printf 'Origins-Pattern\torigin=Debian,codename=${distro_codename},label=Debian-Security\n'
      printf 'Origins-Pattern\torigin=Debian,codename=${distro_codename}-security,label=Debian-Security\n'
      ;;
    ubuntu)
      printf 'Allowed-Origins\t${distro_id}:${distro_codename}-security\n'
      printf 'Allowed-Origins\t${distro_id}ESMApps:${distro_codename}-apps-security\n'
      printf 'Allowed-Origins\t${distro_id}ESM:${distro_codename}-infra-security\n'
      ;;
  esac
}

actual_auto_update_origins() {
  local list
  for list in Origins-Pattern Allowed-Origins; do
    apt_config_list "Unattended-Upgrade::$list" | sed "s/^/$list\t/"
  done
}

verify_auto_updates() {
  local lists updates reboot timer bad=()

  if pkg_installed unattended-upgrades; then
    report PASS uu.installed 'unattended-upgrades 已安装'
  else
    report FAIL uu.installed 'unattended-upgrades 未安装'
  fi

  lists="$(apt_config_scalar APT::Periodic::Update-Package-Lists)"
  updates="$(apt_config_scalar APT::Periodic::Unattended-Upgrade)"
  if [ "$lists" = 1 ] && [ "$updates" = 1 ]; then
    report PASS uu.periodic '每天更新索引、每天执行无人值守升级'
  else
    report FAIL uu.periodic "APT::Periodic 的两个值应为 1，实际为 ${lists:-未设置} 和 ${updates:-未设置}"
  fi

  reboot="$(apt_config_scalar Unattended-Upgrade::Automatic-Reboot)"
  case "${reboot:-false}" in
    false | no | 0 | off) report PASS uu.reboot '不自动重启' ;;
    *) report FAIL uu.reboot "Unattended-Upgrade::Automatic-Reboot 为 $reboot，应为 false" ;;
  esac

  if diff <(expected_auto_update_origins | sort -u) <(actual_auto_update_origins | sort -u) >"$VH_TMP/origins.diff"; then
    report PASS uu.origins '自动更新来源与 FR-09 一致'
  else
    report FAIL uu.origins "自动更新来源与 FR-09 不一致：$(grep -E '^[<>]' "$VH_TMP/origins.diff" | sed 's/^</缺少/; s/^>/多出/' | tr '\t\n' ' ;')"
  fi

  if ! have_record; then
    skip_without_state uu.dropin
  elif same_as_applied "$VH_APT_CONF"; then
    report PASS uu.dropin "$VH_APT_CONF 与应用时一致"
  else
    report FAIL uu.dropin "$VH_APT_CONF 被修改或删除"
  fi

  for timer in apt-daily.timer apt-daily-upgrade.timer; do
    if ! unit_enabled "$timer" || ! unit_active "$timer"; then
      bad+=("$timer")
    fi
  done
  if [ "${#bad[@]}" -gt 0 ]; then
    report FAIL uu.timers "$(join_by '、' "${bad[@]}") 没有启用或没有运行"
  else
    report PASS uu.timers 'apt-daily 和 apt-daily-upgrade 定时器已启用并在运行'
  fi
}

verify_boundary() {
  local found=()

  if have dockerd || have docker || unit_exists docker.service; then
    found+=(Docker)
  fi
  if have podman; then
    found+=(Podman)
  fi
  if [ "${#found[@]}" -gt 0 ]; then
    report FAIL boundary.container "已安装 $(join_by '、' "${found[@]}")，它会绕过 UFW"
  else
    report PASS boundary.container '没有安装 Docker 或 Podman'
  fi

  if [ -e /etc/sysctl.d/99-bbr-x-ui.conf ]; then
    report FAIL boundary.xui-bbr '存在 /etc/sysctl.d/99-bbr-x-ui.conf：3X-UI 的 BBR 菜单会覆盖 vps-tuning 的设置'
  else
    report PASS boundary.xui-bbr '没有 3X-UI 的 BBR 配置'
  fi

  # The same test for an installed 3X-UI as new-host.xui in preflight.
  if ! unit_exists x-ui.service && [ ! -e /usr/local/x-ui ]; then
    report INFO boundary.panel-listen '未安装 3X-UI'
  elif have_record; then
    verify_panel_listen
  else
    skip_without_state boundary.panel-listen
  fi
}

# True for a loopback address as ss prints it (127.0.0.1, [::1],
# [::ffff:127.0.0.1]), also with an interface suffix such as %lo.
is_loopback_address() {
  case "${1%%\%*}" in
    127.* | '[::1]' | '[::ffff:127.'*) return 0 ;;
  esac
  return 1
}

# D16: the declared panel port listens on loopback only (the panel is reached
# through an SSH tunnel). Without a listener the check cannot decide.
verify_panel_listen() {
  local panel addr addrs exposed=()
  panel="$(state_get panel_port)"
  addrs="$(tcp_listen_addresses "$panel")"
  while IFS= read -r addr; do
    [ -n "$addr" ] || continue
    is_loopback_address "$addr" || exposed+=("$addr")
  done <<<"$addrs"
  if [ "${#exposed[@]}" -gt 0 ]; then
    report FAIL boundary.panel-listen "面板端口 $panel 在非回环地址上监听：$(join_by '、' "${exposed[@]}")（面板只经 SSH 隧道访问）"
  elif [ -n "$addrs" ]; then
    report PASS boundary.panel-listen "面板端口 $panel 只在回环地址上监听"
  elif unit_active x-ui.service; then
    report WARN boundary.panel-listen "x-ui 在运行，但面板端口 $panel 上没有监听：面板可能改用了其他端口，无法核对"
  else
    report WARN boundary.panel-listen "x-ui 没有运行，无法核对面板端口 $panel 的监听地址"
  fi
}

verify_reboot() {
  if [ -e /var/run/reboot-required ]; then
    report WARN reboot.required '系统需要重启才能让已安装的更新生效'
  else
    report PASS reboot.required '不需要重启'
  fi
}
