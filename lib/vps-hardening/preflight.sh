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
  preflight_sudo
  preflight_packages
}

preflight_inputs() {
  local i open_desc
  report PASS inputs.user "管理用户：$VH_IN_USER"
  for i in "${!VH_KEY_LINES[@]}"; do
    report INFO inputs.pubkey "${VH_KEY_TYPES[$i]} ${VH_KEY_FPRS[$i]}"
  done
  report PASS inputs.pubkeys "公钥 ${#VH_KEY_LINES[@]} 把，格式有效"
  report PASS inputs.panel-port "面板端口 $VH_IN_PANEL_PORT：不开放，只经 SSH 隧道访问"
  if [ "${#VH_IN_OPEN[@]}" -eq 0 ]; then
    report WARN inputs.open '没有声明公开端口；UFW 将只放行 22/tcp'
  else
    open_desc="$(join_by ', ' "${VH_IN_OPEN[@]}")"
    report PASS inputs.open "公开端口：$open_desc"
  fi
  report PASS inputs.fail2ban "Fail2ban maxretry：$VH_IN_MAXRETRY"
  report PASS inputs.confirm-timeout "确认时限：$VH_IN_TIMEOUT 分钟"

  if getent passwd "$VH_IN_USER" >/dev/null; then
    report FAIL inputs.user-free "账户 $VH_IN_USER 已存在；请换一个用户名"
  elif getent group "$VH_IN_USER" >/dev/null; then
    report FAIL inputs.user-free "已存在同名用户组 $VH_IN_USER；请换一个用户名"
  else
    report PASS inputs.user-free "账户 $VH_IN_USER 尚不存在"
  fi
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

  if [ -e "$VH_STATE_DIR" ]; then
    report FAIL new-host.state "已存在本工具的状态目录 $VH_STATE_DIR"
  else
    report PASS new-host.state '本工具没有在这台主机上执行过'
  fi
}

preflight_sshd() {
  local dropin="$VH_SSHD_DROPIN_DIR/$VH_SSHD_DROPIN_NAME" file name early=() accepted type i bad=()

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

  # A key type sshd does not accept would lock the admin out.
  accepted=" $(sshd_effective root | sshd_value pubkeyacceptedalgorithms | tr ',' ' ') "
  for i in "${!VH_KEY_TYPES[@]}"; do
    type="${VH_KEY_TYPES[$i]}"
    case "$type" in
      ssh-rsa)
        case "$accepted" in
          *' rsa-sha2-512 '* | *' rsa-sha2-256 '* | *' ssh-rsa '*) continue ;;
        esac
        ;;
      *)
        case "$accepted" in
          *" $type "*) continue ;;
        esac
        ;;
    esac
    bad+=("$type ${VH_KEY_FPRS[$i]}")
  done
  if [ "${#bad[@]}" -gt 0 ]; then
    report FAIL sshd.key-types "sshd 不接受这些公钥的算法：$(join_by '；' "${bad[@]}")"
  else
    report PASS sshd.key-types 'sshd 接受全部公钥的算法'
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

preflight_sudo() {
  local accounts

  if ! have sudo; then
    report FAIL sudo.present '没有安装 sudo；管理用户需要它来提权'
    return 0
  fi
  report PASS sudo.present '已安装 sudo'

  if ! getent group sudo >/dev/null; then
    report FAIL sudo.group '没有 sudo 用户组'
  elif sudoers_sudo_group_nopasswd; then
    report FAIL sudo.group 'sudoers 让 sudo 组免密提权，管理用户会继承免密 sudo；本工具不修改 sudoers'
  elif sudoers_sudo_group_rule; then
    report PASS sudo.group 'sudo 组的规则需要密码'
  else
    report FAIL sudo.group 'sudoers 中没有 sudo 组的提权规则（%sudo ALL=(ALL:ALL) ALL）'
  fi

  accounts="$(nopasswd_key_accounts | paste -sd ' ')"
  if [ -n "$accounts" ]; then
    report INFO sudo.nopasswd-accounts "$accounts 有 SSH 密钥和免密 sudo：应用时将禁止其经 SSH 登录，sudo 规则不变（D13）"
  else
    report PASS sudo.nopasswd-accounts '没有带 SSH 密钥的免密 sudo 账户'
  fi
}

# sudo reads files in /etc/sudoers.d whose names contain no dot and do not end in ~.
sudoers_files() {
  local file
  printf '%s\n' /etc/sudoers
  for file in /etc/sudoers.d/*; do
    [ -f "$file" ] || continue
    case "${file##*/}" in
      *.* | *'~') continue ;;
    esac
    printf '%s\n' "$file"
  done
}

sudoers_grep() {
  local files=()
  mapfile -t files < <(sudoers_files)
  grep -qsE -- "$1" "${files[@]}"
}

sudoers_sudo_group_nopasswd() {
  sudoers_grep '^[[:space:]]*(%sudo[[:space:]].*NOPASSWD|Defaults.*!authenticate)'
}

sudoers_sudo_group_rule() {
  sudoers_grep '^[[:space:]]*%sudo[[:space:]]+ALL[[:space:]]*=[[:space:]]*\(ALL(:ALL)?\)[[:space:]]+ALL[[:space:]]*$'
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
