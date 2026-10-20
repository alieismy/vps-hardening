# shellcheck shell=bash
# Read-only preflight (FR-01) including the new-host test (FR-02).

cmd_preflight() {
  parse_host_options "$@"
  run_preflight_checks
  finish_checks
}

# Checks that the rest of preflight depends on; failure stops early.
preflight_gate() {
  if [ "$(id -u)" -ne 0 ]; then
    report FAIL root '需要 root 权限：请在 root shell 中运行，或使用 sudo'
    return 1
  fi
  report PASS root '以 root 权限运行'

  detect_platform
  if [ -z "$VH_PLATFORM" ]; then
    report FAIL platform "不支持的平台：${VH_OS_PRETTY:-未知系统}（${VH_ARCH}）。支持 Debian 12/13、Ubuntu 24.04 LTS，x86_64/aarch64"
    return 1
  fi
  if ! pid1_is_systemd; then
    report FAIL platform 'PID 1 不是 systemd'
    return 1
  fi
  if in_container; then
    report FAIL platform '运行在容器中；只支持虚拟机或物理主机'
    return 1
  fi
  report PASS platform "$VH_OS_PRETTY（$VH_ARCH）"
}

run_preflight_checks() {
  vh_tmp_init
  preflight_gate || return 0
  preflight_inputs
  preflight_new_host
  preflight_sshd
  preflight_accounts
  preflight_packages
}

preflight_inputs() {
  local open_desc
  report PASS inputs.panel-port "面板端口 $VH_IN_PANEL_PORT：不开放，只经 SSH 隧道访问"
  if [ "${#VH_IN_OPEN[@]}" -eq 0 ]; then
    report WARN inputs.open '没有声明公开端口；UFW 将只放行 22/tcp'
  else
    open_desc="$(join_by ', ' "${VH_IN_OPEN[@]}")"
    report PASS inputs.open "公开端口：$open_desc"
  fi
  report PASS inputs.confirm-timeout "确认时限：$VH_IN_TIMEOUT 分钟"
}

preflight_new_host() {
  local found=()

  if unit_exists x-ui.service || [ -e /usr/local/x-ui ]; then
    report FAIL new-host.xui '已安装 3X-UI（存在 x-ui.service 或 /usr/local/x-ui）：存量主机不在支持范围内（D6）'
  else
    report PASS new-host.xui '没有安装 3X-UI'
  fi

  if have dockerd || have docker || unit_exists docker.service; then
    found+=(Docker)
  fi
  if have podman; then
    found+=(Podman)
  fi
  if [ "${#found[@]}" -gt 0 ]; then
    report FAIL new-host.container "已安装 $(join_by '、' "${found[@]}")：它会绕过 UFW，存量主机不在支持范围内（D6）"
  else
    report PASS new-host.container '没有安装 Docker 或 Podman'
  fi

  if ufw_active; then
    report FAIL new-host.ufw 'UFW 已启用：存量主机不在支持范围内（D6）'
  elif have ufw; then
    report PASS new-host.ufw 'UFW 已安装但未启用'
  else
    report PASS new-host.ufw 'UFW 未安装'
  fi

  if fail2ban_has_custom_config; then
    report FAIL new-host.fail2ban 'Fail2ban 有自定义配置：存量主机不在支持范围内（D6）'
  elif pkg_installed fail2ban; then
    report PASS new-host.fail2ban 'Fail2ban 只有发行版默认配置'
  else
    report PASS new-host.fail2ban 'Fail2ban 未安装'
  fi

  if [ ! -e "$VH_STATE_DIR" ]; then
    report PASS new-host.state '本工具没有在这台主机上执行过'
    return 0
  fi
  # FR-02: a host whose earlier apply was fully rolled back counts as new.
  case "$(state_get status)" in
    rolled-back) report PASS new-host.state "上次应用已完全回滚（$(state_get rollback_reason)）" ;;
    pending) report FAIL new-host.state '有待确认的变更：请先确认，或等待自动恢复' ;;
    applied) report FAIL new-host.state '本工具已在这台主机上应用过' ;;
    *) report FAIL new-host.state "本工具的状态为 $(state_get status | sed 's/^$/未知/')，详见 $VH_LOG_FILE" ;;
  esac
}

preflight_sshd() {
  local dropin="$VH_SSHD_DROPIN_DIR/$VH_SSHD_DROPIN_NAME" file name early=()

  if ! bounded /usr/sbin/sshd -t 2>"$VH_TMP/sshd-t.err"; then
    report FAIL sshd.config "sshd 配置检查失败：$(head -n 1 "$VH_TMP/sshd-t.err")"
    return 0
  fi
  if ! sshd_effective root >/dev/null; then
    report FAIL sshd.config "无法读取 sshd 生效配置：$(head -n 1 "$VH_TMP/sshd-T.err")"
    return 0
  fi
  report PASS sshd.config '能读取 sshd 生效配置'

  if sshd_include_first; then
    report PASS sshd.include "$VH_SSHD_MAIN 先包含 $VH_SSHD_DROPIN_DIR/*.conf"
  else
    report FAIL sshd.include "$VH_SSHD_MAIN 中，Include $VH_SSHD_DROPIN_DIR/*.conf 之前已经设置了受管选项或 Match，本工具的片段无法生效"
  fi

  # Drop-ins sorting before ours would win for the managed keywords.
  for file in "$VH_SSHD_DROPIN_DIR"/*.conf; do
    [ -f "$file" ] || continue
    name="${file##*/}"
    [ "$name" != "$VH_SSHD_DROPIN_NAME" ] || continue
    if [[ "$name" < "$VH_SSHD_DROPIN_NAME" ]] && sshd_file_sets_managed "$file"; then
      early+=("$name")
    fi
  done
  if [ "${#early[@]}" -gt 0 ]; then
    report FAIL sshd.dropin-order "$(join_by '、' "${early[@]}") 排在 $VH_SSHD_DROPIN_NAME 之前并设置了受管选项"
  elif [ -e "$dropin" ]; then
    report FAIL sshd.dropin-order "$dropin 已存在"
  else
    report PASS sshd.dropin-order "$VH_SSHD_DROPIN_NAME 将先于其他片段生效"
  fi

  check_root_keys
}

# Root is the only administrative login (D22), so applying without a usable
# root key would lock the administrator out. verify runs the same check.
check_root_keys() {
  local entry
  scan_root_keys
  for entry in "${VH_ROOT_KEYS[@]}"; do
    report INFO root.key "$entry"
  done
  if [ "${#VH_ROOT_KEYS[@]}" -gt 0 ]; then
    if [ "$VH_ROOT_KEYS_SKIPPED" -gt 0 ]; then
      report PASS root.keys "root 有 ${#VH_ROOT_KEYS[@]} 把可用的公钥（另有 $VH_ROOT_KEYS_SKIPPED 行未计入）"
    else
      report PASS root.keys "root 有 ${#VH_ROOT_KEYS[@]} 把可用的公钥"
    fi
  elif [ "$VH_ROOT_KEYS_SKIPPED" -gt 0 ]; then
    report FAIL root.keys "root 没有可用的公钥：$VH_ROOT_KEYS_SKIPPED 行带选项（如 command=）、无法解析，或算法不被 sshd 接受。请先为 root 配置不带选项的公钥"
  else
    report FAIL root.keys 'root 的 authorized_keys 中没有公钥。请先为 root 配置公钥'
  fi
}

# The main config must reach the drop-in Include before setting any managed
# keyword or opening a Match block, because sshd keeps the first value.
sshd_include_first() {
  awk -v managed=" $VH_SSHD_MANAGED " -v dir="$VH_SSHD_DROPIN_DIR/" '
    /^[[:space:]]*(#|$)/ { next }
    {
      key = tolower($1)
      if (key == "include") {
        for (i = 2; i <= NF; i++) if (index($i, dir) == 1) { found = 1; exit }
        next
      }
      if (key == "match" || index(managed, " " key " ") > 0) { exit }
    }
    END { exit found ? 0 : 1 }
  ' "$VH_SSHD_MAIN"
}

sshd_file_sets_managed() {
  awk -v managed=" $VH_SSHD_MANAGED " '
    /^[[:space:]]*(#|$)/ { next }
    { key = tolower($1); if (key == "match" || index(managed, " " key " ") > 0) { hit = 1; exit } }
    END { exit hit ? 0 : 1 }
  ' "$1"
}

preflight_accounts() {
  local accounts

  accounts="$(nopasswd_key_accounts | paste -sd ' ')"
  if [ -n "$accounts" ]; then
    report INFO sudo.nopasswd-accounts "$accounts 有 SSH 密钥和免密 sudo：应用时将禁止其经 SSH 登录，sudo 规则不变（D13）"
  else
    report PASS sudo.nopasswd-accounts '没有带 SSH 密钥的免密 sudo 账户'
  fi
}

preflight_packages() {
  local pkg candidate missing=()

  if package_manager_busy; then
    report FAIL apt.idle '包管理器正在运行；请等它结束后再试'
  else
    report PASS apt.idle '包管理器空闲'
  fi

  for pkg in "${VH_PACKAGES[@]}"; do
    candidate="$(apt_candidate "$pkg")"
    if [ -z "$candidate" ] || [ "$candidate" = '(none)' ]; then
      missing+=("$pkg")
    elif [ "$pkg" = fail2ban ] && [ "$VH_PLATFORM" = ubuntu2404 ] &&
      ! dpkg --compare-versions "$candidate" ge 1.0.2-3ubuntu0.1; then
      report FAIL apt.fail2ban-version "fail2ban 候选版本 $candidate 在 Python 3.12 下会报错；需要启用 noble-updates 取得 1.0.2-3ubuntu0.1 或更新版本"
    fi
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    report FAIL apt.candidates "找不到可安装的软件包：$(join_by ' ' "${missing[@]}")。请先执行 apt-get update"
  else
    report PASS apt.candidates "官方仓库可提供：${VH_PACKAGES[*]}"
  fi
}
