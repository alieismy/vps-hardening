# shellcheck shell=bash
# Read-only verification (FR-10). Never changes files, services or rules.
#
# Checks that need the apply record (declared ports, file digests) report SKIP
# until the record exists; apply writes it from milestone M2.

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

verify_state() {
  if [ -e "$VH_STATE_DIR" ]; then
    report FAIL state "存在 $VH_STATE_DIR，但这个版本还不能读取应用记录"
  else
    report FAIL state '未应用：没有本工具的应用记录'
  fi
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
  skip_without_state ssh.dropin
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
    if printf '%s\n' "$status" | grep -qx 'Default: deny (incoming), allow (outgoing), deny (routed)'; then
      report PASS ufw.defaults '默认拒绝入站、允许出站、拒绝转发'
    else
      report FAIL ufw.defaults "默认策略不符合：$(printf '%s\n' "$status" | grep '^Default:' || printf '未知')"
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
  skip_without_state ufw.rules
  skip_without_state ufw.panel
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

verify_fail2ban() {
  local jails

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

  if bounded fail2ban-client ping >/dev/null 2>&1; then
    jails="$(bounded fail2ban-client status 2>/dev/null | sed -n 's/^.*Jail list:[[:space:]]*//p')"
    if [ "$jails" = sshd ]; then
      report PASS f2b.jails '只有 sshd 一个 jail'
    else
      report FAIL f2b.jails "jail 列表应只有 sshd，实际为：${jails:-（空）}"
    fi
  else
    report FAIL f2b.jails 'fail2ban 服务没有响应'
  fi
  # Effective jail values are checked from milestone M3.
  skip_without_state f2b.values

  if dpkg --verify fail2ban 2>/dev/null | grep -qE ' /etc/fail2ban/(jail|fail2ban)\.conf$'; then
    report FAIL f2b.mainconf 'jail.conf 或 fail2ban.conf 被修改过'
  else
    report PASS f2b.mainconf 'jail.conf 和 fail2ban.conf 保持发行版原样'
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

  if unit_exists x-ui.service; then
    skip_without_state boundary.panel-listen
  else
    report INFO boundary.panel-listen '未安装 3X-UI'
  fi
}

verify_reboot() {
  if [ -e /var/run/reboot-required ]; then
    report WARN reboot.required '系统需要重启才能让已安装的更新生效'
  else
    report PASS reboot.required '不需要重启'
  fi
}
