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
  # Apply declares IPv6 rules too (IPV6=yes), and the SSH endpoint probe reads
  # IPv6 settings; IPv4-only hosts are not supported.
  if ipv6_disabled; then
    report FAIL platform.ipv6 '内核以 ipv6.disable=1 启动，没有 IPv6 协议栈：本工具同时写入 IPv4 和 IPv6 的 UFW 规则，不支持只有 IPv4 的主机。去掉这个内核参数并重启后再运行；未做变更'
    return 1
  fi
}

run_preflight_checks() {
  vh_tmp_init
  preflight_gate || return 0
  if ! have python3; then
    report FAIL sshd.endpoint '缺少 python3：只读入口解析需要 Python 3 标准库；未做变更'
    return 0
  fi
  if ! have busctl; then
    report FAIL sshd.endpoint '缺少 busctl：需要 systemd 的只读结构化启动参数查询；未做变更'
    return 0
  fi
  if ssh_endpoint_discover; then
    report PASS sshd.endpoint "本机 SSH $VH_SSH_PORT/tcp（$VH_SSH_ACTIVATION），监听 $VH_SSH_LISTENERS"
    case " $VH_SSH_LISTENERS " in
      *' ipv6,'*) ;;
      *) report WARN sshd.listen '保留现有 IPv4-only SSH 入口，不新增 IPv6 监听' ;;
    esac
    validate_ssh_port_inputs
  else
    report FAIL sshd.endpoint "$VH_SSH_ERROR"
    return 0
  fi
  preflight_inputs
  preflight_new_host
  preflight_sshd
  preflight_accounts
  preflight_packages
  verify_reboot
}

preflight_inputs() {
  local open_desc
  report PASS inputs.panel-port "面板端口 $VH_IN_PANEL_PORT：不开放，只经 SSH 隧道访问"
  if [ "${#VH_IN_OPEN[@]}" -eq 0 ]; then
    report PASS inputs.open "没有声明公开端口：UFW 只放行 $VH_SSH_PORT/tcp；安装 3X-UI 时用 ports --add 开放它的端口"
  else
    open_desc="$(join_by ', ' "${VH_IN_OPEN[@]}")"
    report PASS inputs.open "公开端口：$open_desc"
  fi
  report PASS inputs.confirm-timeout "确认时限：$VH_IN_TIMEOUT 分钟"
}

preflight_new_host() {
  local found=() rules changed=() units=() tables=() out

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

  # Other firewalls keep rules UFW does not show; nftables.service's default
  # configuration also flushes every table, UFW's included, when it starts.
  mapfile -t units < <(units_enabled_or_active nftables.service netfilter-persistent.service firewalld.service)
  if [ "${#units[@]}" -gt 0 ]; then
    report FAIL new-host.firewall "$(join_by '、' "${units[@]}") 已启用或在运行：它另行管理防火墙规则，ufw status 中看不到；存量主机不在支持范围内（D6）"
  else
    report PASS new-host.firewall '没有启用或运行 nftables.service、netfilter-persistent.service、firewalld.service'
  fi
  # A warning only: such a table may be harmless, but its rules apply next to
  # UFW's and can still block a port UFW allows.
  if ! have nft; then
    report SKIP new-host.nft '未安装 nft，无法列出 nf_tables 的表'
  elif ! out="$(nft_other_tables)"; then
    report WARN new-host.nft '无法列出 nf_tables 的表（nft list tables）'
  elif [ -n "$out" ]; then
    mapfile -t tables <<<"$out"
    report WARN new-host.nft "nf_tables 中有 UFW 和 Fail2ban 以外的表：$(join_by '、' "${tables[@]}")。其中的规则与 UFW 的同时生效，可能让 UFW 放行的端口仍然不通"
  else
    report PASS new-host.nft 'nf_tables 中没有 UFW 和 Fail2ban 以外的表'
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

  if ! bounded /usr/sbin/sshd "${VH_SSHD_ARGS[@]}" -t 2>"$VH_TMP/sshd-t.err"; then
    report FAIL sshd.config "sshd 配置检查失败：$(head -n 1 "$VH_TMP/sshd-t.err")"
    return 0
  fi
  if ! sshd_effective root >/dev/null; then
    report FAIL sshd.config "无法读取 sshd 生效配置：$(head -n 1 "$VH_TMP/sshd-T.err")"
    return 0
  fi
  report PASS sshd.config '能读取 sshd 生效配置'

  if sshd_include_first; then
    report PASS sshd.include "${VH_SSHD_CONFIG:-$VH_SSHD_MAIN} 先包含 $VH_SSHD_DROPIN_DIR/*.conf"
  else
    report FAIL sshd.include "${VH_SSHD_CONFIG:-$VH_SSHD_MAIN} 中，Include $VH_SSHD_DROPIN_DIR/*.conf 之前已经设置了受管选项或 Match，本工具的片段无法生效"
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
  check_root_login
  check_sshd_loginuid
}

# sshd also refuses root through AllowUsers, DenyUsers, AllowGroups and
# DenyGroups (allowed_user() in auth.c) or AuthenticationMethods (auth2.c).
# sshd -T only lists them: it does not test whether the user may log in. A
# wildcard or a host part cannot be settled for every source, so only literal
# names count. Applying denies every other login account, so root must stay.
check_root_login() {
  local config groups entry list allowed problems=()
  config="$(sshd_effective root)"
  groups=" $(id -Gn root) "
  while IFS= read -r entry; do
    case "${entry%@*}" in
      root | *[*?]*) problems+=("DenyUsers $entry") ;;
    esac
  done < <(sshd_values denyusers <<<"$config")
  while IFS= read -r entry; do
    if [[ "$entry" == *[*?]* || "$groups" == *" $entry "* ]]; then
      problems+=("DenyGroups $entry")
    fi
  done < <(sshd_values denygroups <<<"$config")
  list="$(sshd_values allowusers <<<"$config")"
  if [ -n "$list" ] && ! grep -qxF root <<<"$list"; then
    problems+=('AllowUsers 未列出 root')
  fi
  list="$(sshd_values allowgroups <<<"$config")"
  if [ -n "$list" ]; then
    allowed=''
    while IFS= read -r entry; do
      [[ "$groups" != *" $entry "* ]] || allowed=yes
    done <<<"$list"
    [ -n "$allowed" ] || problems+=("AllowGroups 未列出 root 所在的组（${groups:1:-1}）")
  fi
  # Each list must be completed in full; after apply only publickey is on.
  list="$(sshd_values authenticationmethods <<<"$config")"
  if [ -n "$list" ] && ! grep -qxE 'any|publickey' <<<"$list"; then
    problems+=("AuthenticationMethods $(paste -sd ' ' <<<"$list")")
  fi
  if [ "${#problems[@]}" -gt 0 ]; then
    report FAIL sshd.root-login "应用后只有 root 能用密钥登录，但 sshd 会拒绝 root 或无法确认允许：$(join_by '；' "${problems[@]}")。只按字面的用户名和组名判定，含通配符或 @ 的条目不支持"
  else
    report PASS sshd.root-login 'sshd 的用户、组和认证方式限制不阻止 root 用密钥登录'
  fi
}

# confirm recognizes a new root session by the audit login UID and session ID
# that pam_loginuid sets at login (design 2.6). Without them every confirm is
# refused and the change is restored when the window ends. OpenSSH 9.8 and
# later take the PAM service from PAMServiceName (default sshd); earlier
# versions do not list the keyword and always use sshd.
check_sshd_loginuid() {
  local config usepam service
  config="$(sshd_effective root)"
  usepam="$(sshd_value usepam <<<"$config")"
  service="$(sshd_value pamservicename <<<"$config")"
  service="${service:-sshd}"
  # pam_start() keeps the part after the last "/" and lowercases it.
  service="${service##*/}"
  service="${service,,}"
  if [ "$usepam" != yes ]; then
    report FAIL sshd.loginuid "sshd 的 UsePAM 不是 yes（${usepam:-未设置}）：新的 SSH 会话没有登录会话编号，confirm 无法确认，变更会在时限到后自动恢复"
  elif ! pam_session_loads "$service" pam_loginuid.so; then
    report FAIL sshd.loginuid "/etc/pam.d/$service 的 session 栈没有加载 pam_loginuid.so：新的 SSH 会话没有登录会话编号，confirm 无法确认，变更会在时限到后自动恢复"
  elif [ ! -r "/proc/$$/loginuid" ] || [ ! -r "/proc/$$/sessionid" ]; then
    report FAIL sshd.loginuid '内核不提供 /proc/<pid>/loginuid 或 sessionid（审计支持）：confirm 无法识别新的 SSH 会话'
  else
    report PASS sshd.loginuid 'sshd 经 PAM 的 pam_loginuid.so 为新会话设置登录会话编号，confirm 能识别新的 root 会话'
  fi
}

# pam_session_loads SERVICE MODULE: the PAM configuration of SERVICE, with
# @include lines and session include and substack lines followed, has a
# session line for MODULE. A leading "-" (skip a missing module) counts;
# a control in brackets may contain blanks. Linux-PAM reads a relative
# include under /etc/pam.d and matches the type and control in any case.
# Like _pam_assemble_line(), a line ending in a backslash continues on the
# next one, blank and comment lines in between are skipped, and a "#" ends
# the logical line. Controls are not followed: an earlier sufficient line or
# jump that passes over MODULE still counts as loading it (design 3).
pam_session_loads() {
  local queue=("/etc/pam.d/$1") listed=$'\n' file line
  while [ "${#queue[@]}" -gt 0 ]; do
    file="${queue[0]}"
    queue=("${queue[@]:1}")
    case "$listed" in
      *$'\n'"$file"$'\n'*) continue ;;
    esac
    listed="$listed$file"$'\n'
    [ -f "$file" ] || continue
    while IFS= read -r line; do
      case "$line" in
        =) return 0 ;;
        /*) queue+=("$line") ;;
        *) queue+=("/etc/pam.d/$line") ;;
      esac
    done < <(awk -v module="$2" '
      /^[ \t]*$/ || /^[ \t]*#/ { next }
      {
        line = $0
        i = index(line, "#")
        if (i > 0) line = substr(line, 1, i - 1)
        else if (sub(/\\[ \t]*$/, " ", line)) { held = held line; next }
        $0 = held line
        held = ""
        if ($1 == "@include") { if (NF > 1) print $2; next }
        type = tolower($1)
        if (type != "session" && type != "-session") next
        rest = $0
        sub(/^[ \t]*[^ \t]+[ \t]+/, "", rest)
        if (substr(rest, 1, 1) == "[") {
          i = index(rest, "]")
          if (i == 0) next
          control = ""
          rest = substr(rest, i + 1)
        } else {
          control = tolower(rest)
          sub(/[ \t].*/, "", control)
          sub(/^[^ \t]+/, "", rest)
        }
        sub(/^[ \t]+/, "", rest)
        sub(/[ \t].*/, "", rest)
        if (rest == "") next
        if (control == "include" || control == "substack") { print rest; next }
        sub(/.*\//, "", rest)
        if (rest == module) { print "="; exit }
      }
    ' "$file")
  done
  return 1
}

# Root is the only administrative login (D22), so applying without a usable
# root key would lock the administrator out. verify runs the same check.
# check_root_keys [FILE PREFIX]: rollback passes the sshd -T output of the
# configuration the restore leaves, and a prefix that says so (FR-12).
check_root_keys() {
  local entry where="${2-}"
  scan_root_keys "${1-}"
  for entry in "${VH_ROOT_KEYS[@]}"; do
    report INFO root.key "$entry"
  done
  if [ "${#VH_ROOT_KEYS[@]}" -gt 0 ]; then
    if [ "$VH_ROOT_KEYS_SKIPPED" -gt 0 ]; then
      report PASS root.keys "${where}root 有 ${#VH_ROOT_KEYS[@]} 把可用的公钥（另有 $VH_ROOT_KEYS_SKIPPED 行未计入）"
    else
      report PASS root.keys "${where}root 有 ${#VH_ROOT_KEYS[@]} 把可用的公钥"
    fi
  elif [ "$VH_ROOT_KEYS_SKIPPED" -gt 0 ]; then
    report FAIL root.keys "${where}root 没有可用的公钥：$VH_ROOT_KEYS_SKIPPED 行带选项（如 command=）、无法解析，或算法不被 sshd 接受。请先为 root 配置不带选项的公钥"
  else
    report FAIL root.keys "${where}root 的 authorized_keys 中没有公钥。请先为 root 配置公钥"
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
  ' "${VH_SSHD_CONFIG:-$VH_SSHD_MAIN}"
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
  local queue=("${VH_SSHD_CONFIG:-$VH_SSHD_MAIN}") listed=$'\n' file pattern path
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
