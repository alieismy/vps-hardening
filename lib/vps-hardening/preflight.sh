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
  local found=() rules changed=()

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

  # `ufw allow` also works while UFW is inactive; such rules would take effect
  # with apply's `ufw enable`, outside the declaration.
  if ufw_active; then
    report FAIL new-host.ufw 'UFW 已启用：存量主机不在支持范围内（D6）'
  elif ! have ufw; then
    report PASS new-host.ufw 'UFW 未安装'
  else
    if ! rules="$(ufw_added_rules)"; then
      report FAIL new-host.ufw '无法读取 UFW 已添加的规则（ufw show added）'
    elif [ -n "$rules" ]; then
      report FAIL new-host.ufw "UFW 未启用，但已有 $(printf '%s\n' "$rules" | wc -l) 条规则（ufw show added）：存量主机不在支持范围内（D6）"
    else
      report PASS new-host.ufw 'UFW 已安装但未启用，没有已添加的规则'
    fi
    mapfile -t changed < <(ufw_framework_changed)
    if [ "${#changed[@]}" -gt 0 ]; then
      report FAIL new-host.ufw-framework "$(join_by '、' "${changed[@]}") 与软件包的原始文件不同，其中的规则不显示在 ufw status 中：存量主机不在支持范围内（D6）"
    else
      report PASS new-host.ufw-framework 'UFW 的 before/after 文件与软件包的原始文件相同'
    fi
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
    pending | ports-pending) report FAIL new-host.state '有待确认的变更：请先确认，或等待自动恢复' ;;
    applied) report FAIL new-host.state '本工具已在这台主机上应用过' ;;
    # An apply stopped before it could restore, or a restore that did not finish.
    applying | restoring | restore-failed)
      report FAIL new-host.state "本工具的状态为 $(state_get status)：请先执行 vps-hardening rollback，详见 $VH_LOG_FILE"
      ;;
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

  check_sshd_match sshd.match
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

# awk functions that split an sshd config line as sshd does, so that a quoted
# keyword or a quoted or escaped Include path is read the same way. They
# follow load_server_config() and process_server_config_line_depth() in
# servconf.c and strdelim_internal() and argv_split() in misc.c, which are the
# same in OpenSSH 9.2p1, 9.6p1 and 10.0p2. "\047" is a single quote.
readonly VH_SSHD_AWK='
# The keyword of a line, lowercased, or "" for a blank or comment line or one
# that sshd ignores. Leaves the rest of the line in sshd_rest.
function sshd_keyword(line,    key) {
  sub(/^[ \t\r]+/, "", line)
  sub(/[ \t\r\n\f]+$/, "", line)
  sshd_rest = line
  key = sshd_delim()
  if (key == "") key = sshd_delim()
  if (substr(key, 1, 1) == "#") key = ""
  return tolower(key)
}

# strdelim(): the next word of sshd_rest, ended by a blank, a "=" or a double
# quote. A double-quoted part joins the word; an unclosed one gives "". Skips
# the blanks after the word, and one "=" unless the word ended at one.
function sshd_delim(    s, i, c, word) {
  s = sshd_rest
  i = match(s, /[ \t\r\n"=]/)
  if (i == 0) { sshd_rest = ""; return s }
  c = substr(s, i, 1)
  word = substr(s, 1, i - 1)
  s = substr(s, i + 1)
  if (c == "\"") {
    i = index(s, "\"")
    if (i == 0) { sshd_rest = ""; return "" }
    word = word substr(s, 1, i - 1)
    s = substr(s, i + 1)
    sub(/^[ \t\r\n]+/, "", s)
  } else {
    sub(/^[ \t\r\n]+/, "", s)
    if (c != "=" && substr(s, 1, 1) == "=") {
      s = substr(s, 2)
      sub(/^[ \t\r\n]+/, "", s)
    }
  }
  sshd_rest = s
  return word
}

# argv_split(): the arguments of s into args[1..n]; returns n, or -1 for an
# unclosed quote. Blanks separate arguments and single or double quotes group
# them. A backslash escapes a quote, a backslash or, outside quotes, a space,
# and stays otherwise. A "#" that starts an argument ends the line.
function sshd_args(s, args,    n, i, len, c, d, q, arg) {
  n = 0
  len = length(s)
  i = 1
  while (i <= len) {
    c = substr(s, i, 1)
    if (c == " " || c == "\t") { i++; continue }
    if (c == "#") break
    q = ""
    arg = ""
    for (; i <= len; i++) {
      c = substr(s, i, 1)
      if (c == "\\") {
        d = substr(s, i + 1, 1)
        if (d == "\047" || d == "\"" || d == "\\" || (q == "" && d == " ")) {
          i++
          arg = arg d
        } else {
          arg = arg c
        }
      } else if (q == "" && (c == " " || c == "\t")) {
        break
      } else if (q == "" && (c == "\"" || c == "\047")) {
        q = c
      } else if (q != "" && c == q) {
        q = ""
      } else {
        arg = arg c
      }
    }
    args[++n] = arg
    if (i > len) {
      if (q != "") return -1
      break
    }
    i++
  }
  return n
}
'

# The main config must reach the drop-in Include before setting any managed
# keyword or opening a Match block, because sshd keeps the first value.
sshd_include_first() {
  awk -v managed=" $VH_SSHD_MANAGED " -v dir="$VH_SSHD_DROPIN_DIR/" "$VH_SSHD_AWK"'
    {
      key = sshd_keyword($0)
      if (key == "") next
      if (key == "include") {
        n = sshd_args(sshd_rest, args)
        for (i = 1; i <= n; i++) if (index(args[i], dir) == 1) { found = 1; exit }
        next
      }
      if (key == "match" || index(managed, " " key " ") > 0) { exit }
    }
    END { exit found ? 0 : 1 }
  ' "$VH_SSHD_MAIN"
}

sshd_file_sets_managed() {
  awk -v managed=" $VH_SSHD_MANAGED " "$VH_SSHD_AWK"'
    {
      key = sshd_keyword($0)
      if (key != "" && (key == "match" || index(managed, " " key " ") > 0)) { hit = 1; exit }
    }
    END { exit hit ? 0 : 1 }
  ' "$1"
}

# check_sshd_match ID: sshd -T evaluates one placeholder connection, so it
# cannot vouch for a Match block that other connections meet, such as one by
# source address. No active Match is supported anywhere in the config (FR-04).
check_sshd_match() {
  local file found=()
  while IFS= read -r file; do
    if awk "$VH_SSHD_AWK"'
      sshd_keyword($0) == "match" { hit = 1; exit }
      END { exit hit ? 0 : 1 }
    ' "$file"; then
      found+=("$file")
    fi
  done < <(sshd_config_files)
  if [ "${#found[@]}" -gt 0 ]; then
    report FAIL "$1" "$(join_by '、' "${found[@]}") 中有 Match 块：sshd -T 只能按一个连接求值，无法确认它对所有来源都只允许密钥登录，不支持（FR-04）"
  else
    report PASS "$1" 'sshd 配置中没有 Match 块'
  fi
}

# The main sshd config and, recursively, every file an Include names. sshd
# resolves a relative Include under /etc/ssh. Paths may contain blanks but not
# newlines, since each Include argument comes from one line.
sshd_config_files() {
  local queue=("$VH_SSHD_MAIN") listed=$'\n' file pattern path
  while [ "${#queue[@]}" -gt 0 ]; do
    file="${queue[0]}"
    queue=("${queue[@]:1}")
    case "$listed" in
      *$'\n'"$file"$'\n'*) continue ;;
    esac
    listed="$listed$file"$'\n'
    printf '%s\n' "$file"
    while IFS= read -r pattern; do
      [[ "$pattern" == /* ]] || pattern="${VH_SSHD_MAIN%/*}/$pattern"
      while IFS= read -r path; do
        if [ -f "$path" ]; then
          queue+=("$path")
        fi
      done < <(compgen -G "$pattern")
    done < <(sshd_includes "$file")
  done
}

# The arguments of the Include lines of one sshd config file, one per line.
sshd_includes() {
  awk "$VH_SSHD_AWK"'
    sshd_keyword($0) == "include" {
      n = sshd_args(sshd_rest, args)
      for (i = 1; i <= n; i++) if (args[i] != "") print args[i]
    }
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
