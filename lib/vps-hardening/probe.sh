# shellcheck shell=bash
# Read-only probes of the host. Nothing here may change files, services or rules.

pkg_installed() {
  [ "$(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null)" = installed ]
}

unit_exists() {
  systemctl cat -- "$1" >/dev/null 2>&1
}

unit_enabled() {
  case "$(systemctl is-enabled -- "$1" 2>/dev/null)" in
    enabled | enabled-runtime | alias | static | indirect | generated) return 0 ;;
  esac
  return 1
}

# True when the unit is enabled in /etc and so starts at every boot. Unlike
# unit_enabled, enabled-runtime (gone after a reboot), static and the like do
# not count: the managed units are enabled by apply (requirements D60).
unit_enabled_at_boot() {
  [ "$(systemctl is-enabled -- "$1" 2>/dev/null)" = enabled ]
}

unit_active() {
  systemctl is-active --quiet -- "$1"
}

# Effective sshd configuration evaluated for one user, as `key value` lines.
# Cached per user; Match blocks are evaluated against a placeholder address.
sshd_effective() {
  local user="$1" cache
  vh_tmp_init
  cache="$VH_TMP/sshd-T.$user"
  if [ ! -s "$cache" ]; then
    bounded /usr/sbin/sshd "${VH_SSHD_ARGS[@]}" -T -C "user=$user,host=vps-hardening.invalid,addr=192.0.2.1,laddr=192.0.2.2,lport=${VH_SSH_PORT:-22}" >"$cache" 2>"$VH_TMP/sshd-T.err" ||
      return 1
  fi
  cat -- "$cache"
}

# Forget cached sshd -T output after the configuration on disk changed.
sshd_cache_clear() {
  [ -z "$VH_TMP" ] || rm -f -- "$VH_TMP"/sshd-T.*
}

# All values of one keyword from sshd -T output on stdin, one per line.
# Array keywords (denyusers) may appear on several lines or space-separated.
sshd_values() {
  awk -v key="$1" '$1 == key { for (i = 2; i <= NF; i++) print $i }'
}

sshd_value() {
  awk -v key="$1" '$1 == key && !seen { print $2; seen = 1 }'
}

# Accounts other than root whose shell lets sshd log them in, as allowed_user()
# in OpenSSH's auth.c decides: the shell (empty means /bin/sh) is a regular
# file with an execute bit; -x tests that as root. /etc/shells plays no part
# there (requirements D61). Like sshd, skip the shell test when ChrootDirectory
# is set: then every account counts. The Match check leaves only a global
# value, so root's evaluation stands for all; when sshd -T fails, the shell
# test applies and the sshd checks report the failure. Accounts sshd refuses
# for other reasons stay in: denying them as well changes nothing.
login_accounts() {
  local name _pw _uid _gid _gecos _home shell chroot
  chroot="$(sshd_effective root | sshd_value chrootdirectory)" || chroot=''
  while IFS=: read -r name _pw _uid _gid _gecos _home shell; do
    [ "$name" != root ] || continue
    shell="${shell:-/bin/sh}"
    if [ -n "$chroot" ] && [ "${chroot,,}" != none ]; then
      printf '%s\n' "$name"
    elif [ -f "$shell" ] && [ -x "$shell" ]; then
      printf '%s\n' "$name"
    fi
  done < <(getent passwd)
}

# sshd_config_of USER [FILE]: sshd -T output for USER, read from FILE when
# given (rollback evaluates the configuration the restore leaves), otherwise
# the current configuration.
sshd_config_of() {
  if [ -n "${2-}" ]; then
    cat -- "$2"
  else
    sshd_effective "$1"
  fi
}

# authorized_keys_files USER [FILE]: expand AuthorizedKeysFile tokens
# (%h %u %U %%) for one user, under the configuration sshd_config_of gives.
authorized_keys_files() {
  local user="$1" config="${2-}" home uid token path
  home="$(getent passwd "$user" | cut -d: -f6)"
  uid="$(id -u "$user" 2>/dev/null)" || return 0
  sshd_config_of "$user" "$config" | sshd_values authorizedkeysfile | while IFS= read -r token; do
    [ "$token" != none ] || continue
    path="${token//%%/$'\001'}"
    path="${path//%h/$home}"
    path="${path//%u/$user}"
    path="${path//%U/$uid}"
    path="${path//$'\001'/%}"
    case "$path" in
      /*) printf '%s\n' "$path" ;;
      *) printf '%s/%s\n' "$home" "$path" ;;
    esac
  done
}

account_has_keys() {
  local file
  while IFS= read -r file; do
    [ -f "$file" ] || continue
    if grep -qvE '^[[:space:]]*(#|$)' -- "$file"; then
      return 0
    fi
  done < <(authorized_keys_files "$1")
  return 1
}

# key_type_accepted TYPE " ALGORITHMS ": an ssh-rsa key works with any RSA signature algorithm.
key_type_accepted() {
  case "$1" in
    ssh-rsa)
      case "$2" in
        *' rsa-sha2-512 '* | *' rsa-sha2-256 '* | *' ssh-rsa '*) return 0 ;;
      esac
      ;;
    *)
      case "$2" in
        *" $1 "*) return 0 ;;
      esac
      ;;
  esac
  return 1
}

# Root's usable keys (FR-03) as "type fingerprint" in VH_ROOT_KEYS, unique by
# fingerprint. A line counts when it is a plain key that ssh-keygen parses and
# whose algorithm sshd accepts. Lines with options do not count: cloud-init
# disables root login with a command= prefix. Other non-comment lines are
# counted in VH_ROOT_KEYS_SKIPPED. Sets globals, so call it in the main shell.
# With FILE, the files and algorithms come from that sshd -T output.
VH_ROOT_KEYS=()
VH_ROOT_KEYS_SKIPPED=0
scan_root_keys() {
  local config="${1-}" file line type fpr accepted keyfile="$VH_TMP/root-key" seen=' '
  accepted=" $(sshd_config_of root "$config" | sshd_value pubkeyacceptedalgorithms | tr ',' ' ') "
  while IFS= read -r file; do
    [ -f "$file" ] || continue
    while IFS= read -r line || [ -n "$line" ]; do
      line="${line%$'\r'}"
      line="${line#"${line%%[![:space:]]*}"}"
      case "$line" in
        '' | '#'*) continue ;;
      esac
      fpr=''
      if [[ "$line" =~ ^(ssh-[a-z0-9-]+|ecdsa-sha2-[a-z0-9-]+|sk-[a-z0-9@.-]+)[[:space:]]+[A-Za-z0-9+/]+=*([[:space:]].*)?$ ]]; then
        type="${BASH_REMATCH[1]}"
        if key_type_accepted "$type" "$accepted"; then
          printf '%s\n' "$line" >"$keyfile"
          fpr="$(ssh-keygen -l -E sha256 -f "$keyfile" 2>/dev/null | awk '{print $2}')" || fpr=''
        fi
      fi
      if [ -z "$fpr" ]; then
        VH_ROOT_KEYS_SKIPPED=$((VH_ROOT_KEYS_SKIPPED + 1))
        continue
      fi
      case "$seen" in
        *" $fpr "*) continue ;;
      esac
      seen="$seen$fpr "
      VH_ROOT_KEYS+=("$type $fpr")
    done <"$file"
  done < <(authorized_keys_files root "$config")
  rm -f -- "$keyfile"
}

# True when sudo lets the account run commands without a password.
account_nopasswd_sudo() {
  local out
  out="$(bounded sudo -n -l -U "$1" 2>/dev/null)" || return 1
  case "$out" in
    *NOPASSWD* | *'!authenticate'*) return 0 ;;
  esac
  return 1
}

account_denied_by_sshd() {
  local user="$1"
  sshd_effective "$user" | sshd_values denyusers | grep -qxF -- "$user"
}

# Login accounts that have keys and password-less sudo (decision D13).
nopasswd_key_accounts() {
  local user
  while IFS= read -r user; do
    account_has_keys "$user" || continue
    account_nopasswd_sudo "$user" || continue
    printf '%s\n' "$user"
  done < <(login_accounts)
}

# Local addresses listening on a TCP port, one per line (for example 0.0.0.0, [::], 127.0.0.1).
tcp_listen_addresses() {
  ss -H -ltn "sport = :$1" 2>/dev/null | awk '{ addr = $4; sub(/:[0-9]+$/, "", addr); print addr }' | sort -u
}

ufw_active() {
  have ufw && bounded ufw status 2>/dev/null | awk 'NR == 1 { s = $0 } END { exit s == "Status: active" ? 0 : 1 }'
}

# Lines of `ufw show added`, without the header. They do not show the address
# family: a rule limited to 0.0.0.0/0 or ::/0 is listed like one for both.
ufw_added_rules() {
  bounded ufw show added 2>/dev/null | sed -n 's/^ufw //p'
}

# Rule lines of `ufw status` (active firewall only), one per address family.
ufw_status_rules() {
  bounded ufw status 2>/dev/null | awk 'seen && NF { print } /^--/ { seen = 1 }'
}

# The UFW files whose rules `ufw status` does not show and that differ from
# the package's originals in /usr/share/ufw (FR-06), one per line.
ufw_framework_changed() {
  local name
  for name in "${VH_UFW_FRAMEWORK[@]}"; do
    cmp -s -- "/etc/ufw/$name" "/usr/share/ufw/$name" || printf '/etc/ufw/%s\n' "$name"
  done
}

# `apt-config dump` output, cached. Readers consume all of it: an early exit
# would kill apt-config with SIGPIPE and fail the pipeline under pipefail.
apt_config_dump() {
  local cache
  vh_tmp_init
  cache="$VH_TMP/apt-config"
  if [ ! -s "$cache" ]; then
    bounded apt-config dump >"$cache" 2>/dev/null || return 1
  fi
  cat -- "$cache"
}

apt_config_scalar() {
  apt_config_dump |
    awk -v key="$1" 'index($0, key " \"") == 1 && !seen { v = substr($0, length(key) + 3); sub(/";$/, "", v); print v; seen = 1 }'
}

apt_config_list() {
  apt_config_dump |
    awk -v key="$1::" 'index($0, key " \"") == 1 { v = substr($0, length(key) + 3); sub(/";$/, "", v); print v }'
}

# Lock holders, plus apt or dpkg processes between taking locks. Process names
# alone are not used for unattended-upgrades: its shutdown helper always runs
# under the same truncated name, so the run lock is checked instead.
package_manager_busy() {
  local lock locks name
  locks="$(lslocks -n -o PATH 2>/dev/null)" || locks=''
  for lock in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock \
    /var/cache/apt/archives/lock /run/unattended-upgrades.lock; do
    if grep -qxF -- "$lock" <<<"$locks"; then
      return 0
    fi
  done
  # One name per call: pgrep matches nothing when the whole pattern is longer
  # than 15 characters, even for an alternation of short names.
  for name in apt apt-get aptitude dpkg; do
    if pgrep -x -- "$name" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

apt_candidate() {
  bounded apt-cache policy -- "$1" 2>/dev/null | awk '$1 == "Candidate:" && !seen { print $2; seen = 1 }'
}

# Fail2ban package files that dpkg reports as changed, one path per line.
# dpkg --verify exits 0 even when files differ; non-zero means it could not
# check (1: not installed, 2: a read error, output possibly cut short), and
# this returns 1. The output is captured whole: dpkg writes line by line, and
# a reader that stops early fails the pipeline under pipefail.
fail2ban_changed_files() {
  local out
  out="$(dpkg --verify fail2ban 2>/dev/null)" || return 1
  awk 'NF { print $NF }' <<<"$out"
}

fail2ban_has_custom_config() {
  local entry changed
  [ -d /etc/fail2ban ] || return 1
  if find /etc/fail2ban -name '*.local' -print -quit 2>/dev/null | grep -q .; then
    return 0
  fi
  for entry in /etc/fail2ban/jail.d/* /etc/fail2ban/fail2ban.d/*; do
    [ -e "$entry" ] || continue
    [ "$entry" = /etc/fail2ban/jail.d/defaults-debian.conf ] && continue
    return 0
  done
  pkg_installed fail2ban || return 1
  # A package that cannot be checked counts as changed (detailed design 6).
  changed="$(fail2ban_changed_files)" || return 0
  [ -n "$changed" ]
}

# D64: one verified management endpoint baseline. Values are never defaults.
# These globals are consumed by the command modules after successful discovery.
# shellcheck disable=SC2034
VH_SSH_PORT=''
VH_SSH_ACTIVATION=''
VH_SSH_LISTENERS=''
VH_SSH_ERROR=''
VH_SSH_LEGACY=no
# shellcheck disable=SC2034 # actual configuration entry, read by preflight
VH_SSHD_CONFIG=/etc/ssh/sshd_config
# shellcheck disable=SC2034 # source validity, read by verify
VH_SSHD_VERIFIED=no
VH_SSHD_ARGS=()

# A single read-only helper keeps IP, systemd and /proc parsing at their trust
# boundary. No configuration value is executed as shell code. The outer and
# individual command bounds also cover a blocked systemd or sshd query.
ssh_probe_python() {
  bounded python3 - "$@" <<'VH_SSH_PY'
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys


def fail(message):
    raise ValueError(message)


def run(*args):
    try:
        result = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail("无法核实：读取命令失败或超时（" + args[0] + "）：" + str(exc))
    if result.returncode:
        fail("无法核实：" + args[0] + " 返回非零状态")
    return result.stdout


def properties(unit):
    keys = ["LoadState", "ActiveState", "NeedDaemonReload", "MainPID",
            "Listen", "BindIPv6Only", "Accept",
            "FragmentPath", "DropInPaths", "RootDirectory", "RootImage",
            "NetworkNamespacePath", "PrivateNetwork"]
    args = ["systemctl", "show", unit]
    for key in keys:
        args += ["-p", key]
    result = {}
    for line in run(*args).splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        # systemctl emits one Listen= line per socket endpoint. A dictionary
        # comprehension silently discarded all but the last address family.
        if key == "Listen" and key in result:
            result[key] += " " + value
        else:
            result[key] = value
    return result


def port(value):
    if not re.fullmatch(r"[1-9][0-9]{0,4}", value) or int(value) > 65535:
        fail("无法核实：非法端口")
    return str(int(value))


def address(value, number, family=None, dual=False):
    number = port(number)
    value = value.strip("[]")
    if value == "*":
        if family not in (4, 6):
            fail("无法核实：通配地址的地址族未知")
        value = "0.0.0.0" if family == 4 else "::"
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        fail("无法核实：只接受可归一化的数值监听地址")
    if getattr(ip, "scope_id", None):
        fail("无法核实：带作用域的监听地址")
    if family is not None and ip.version != family:
        fail("无法核实：监听地址族不一致")
    # IPv4-mapped sockets accept IPv4 only, not the entire IPv6 address space.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return {("ipv4", str(ip.ipv4_mapped), number)}
    values = {("ipv" + str(ip.version), str(ip), number)}
    if ip.version == 6 and ip.is_unspecified and dual:
        values.add(("ipv4", "0.0.0.0", number))
    return values


def endpoint(value, family=None, dual=False):
    if value.isdigit():
        return address("::", value, 6, dual)
    match = re.fullmatch(r"\[([^]]+)\]:(\d+)", value)
    if not match:
        match = re.fullmatch(r"(.+):(\d+)", value)
    if not match:
        fail("无法核实：无法解析监听端点")
    return address(match[1], match[2], family, dual)


def serial(values):
    return " ".join(",".join(v) for v in sorted(values))


def config_endpoints(text):
    # sshd -T already expands unqualified ListenAddress against all effective
    # Port values and retains an explicit ListenAddress port. Its port lines
    # alone therefore are not the listening port set.
    values = set()
    for line in text.splitlines():
        pieces = line.split()
        if pieces and pieces[0] == "listenaddress":
            if len(pieces) != 2:
                fail("无法核实：不支持的 ListenAddress 输出")
            values.update(endpoint(pieces[1]))
    if not values:
        fail("无法核实：sshd 没有有效监听地址")
    return values


def split(value):
    try:
        tokens = shlex.split(value, posix=True)
    except ValueError:
        fail("无法核实：systemd 参数引号不完整")
    if any("\n" in token or "\r" in token or "\x00" in token for token in tokens):
        fail("无法核实：启动参数含控制字符")
    return tokens


def environment_file(text):
    # EnvironmentFile is not shell syntax: quotes inside an unquoted value
    # survive until ExecStart expands $VAR. Only a quote at PRE_VALUE opens
    # a quoted value. See systemd's parse_env_file_internal (v252+).
    if "\x00" in text:
        fail("无法核实：环境文件含 NUL")
    values = {}
    state, key, value, trim = "key-start", "", [], None
    for char in text + "\n":
        if state == "key-start":
            if char in "#;":
                state = "comment"
            elif char not in " \t\r\n":
                key, state = char, "key"
        elif state == "comment":
            if char == "\\":
                state = "comment-escape"
            elif char == "\n":
                state = "key-start"
        elif state == "comment-escape":
            state = "comment"
        elif state == "key":
            if char == "\n":
                state = "key-start"  # systemd ignores lines without '='
            elif char == "=":
                key = key.rstrip(" \t\r")
                if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", key):
                    fail("无法核实：环境文件变量名非法")
                state, value, trim = "value-start", [], None
            else:
                key += char
        elif state in ("value-start", "value"):
            if char == "\n":
                values[key] = "".join(value if trim is None else value[:trim])
                state = "key-start"
            elif char == "\\":
                state, trim = "escape", None
            elif state == "value-start" and char in "\"'":
                state = "double" if char == '"' else "single"
            elif state == "value-start" and char in " \t\r":
                continue
            else:
                state = "value"
                trim = (len(value) if trim is None else trim) if char in " \t\r" else None
                value.append(char)
        elif state == "escape":
            if char != "\n":
                value.append(char)
            state = "value"
        elif state in ("single", "double"):
            if char == ("'" if state == "single" else '"'):
                state = "value-start"
            elif state == "double" and char == "\\":
                state = "double-escape"
            else:
                value.append(char)
        elif state == "double-escape":
            if char != "\n":
                if char not in '\\"`$':
                    value.append("\\")
                value.append(char)
            state = "double"
    if state != "key-start":
        fail("无法核实：环境文件含未结束的引号或续行")
    return values


def service_property(name, signature):
    # systemctl show joins argv with spaces and loses argument boundaries.
    # busctl is shipped with systemd; JSON preserves the typed D-Bus arrays.
    result = json.loads(run("busctl", "--system", "--json=short", "get-property",
                            "org.freedesktop.systemd1",
                            "/org/freedesktop/systemd1/unit/ssh_2eservice",
                            "org.freedesktop.systemd1.Service", name))
    if not isinstance(result, dict) or result.get("type") != signature or not isinstance(result.get("data"), list):
        fail("无法核实：systemd 属性格式不符：" + name)
    return result["data"]


def environment_words(value):
    # ExecStart's standalone $VAR uses EXTRACT_UNQUOTE: backslash quotes the
    # next character even inside quotes, unlike POSIX shlex. Reject unfinished
    # input rather than relying on systemd's permissive EXTRACT_RELAX behavior.
    words, word, quote, escaped, started = [], [], "", False, False
    for char in value:
        if escaped:
            word.append(char)
            escaped = False
        elif char == "\\":
            escaped, started = True, True
        elif quote:
            if char == quote:
                quote = ""
            else:
                word.append(char)
        elif char in "\"'":
            quote, started = char, True
        elif char in " \t\r\n":
            if started:
                words.append("".join(word))
                word, started = [], False
        else:
            word.append(char)
            started = True
    if quote or escaped:
        fail("无法核实：启动环境选项含未结束的引号或转义")
    if started:
        words.append("".join(word))
    if any(any(c in word for c in "\n\r\x00") for word in words):
        fail("无法核实：启动环境选项含控制字符")
    return words


def service_arguments(pid):
    commands = service_property("ExecStart", "a(sasbttttuii)")
    if len(commands) != 1 or not isinstance(commands[0], list) or len(commands[0]) != 10:
        fail("无法核实：不支持多条或无法解析的 ExecStart")
    command, argv = commands[0], commands[0][1]
    if not isinstance(argv, list) or not argv or any(not isinstance(arg, str) or any(c in arg for c in "\n\r\x00") for arg in argv):
        fail("无法核实：ExecStart 参数数组非法")
    if command[0] != argv[0] or Path(argv[0]).resolve() != Path("/usr/sbin/sshd").resolve():
        fail("无法核实：SSH 未由已知 sshd 原生入口启动")
    environment = {}
    for entry in service_property("Environment", "as"):
        if not isinstance(entry, str) or "=" not in entry:
            fail("无法核实：systemd Environment 非法")
        key, value = entry.split("=", 1)
        environment[key] = value
    for entry in service_property("EnvironmentFiles", "a(sb)"):
        if not isinstance(entry, list) or len(entry) != 2 or not isinstance(entry[0], str) or not isinstance(entry[1], bool):
            fail("无法核实：systemd EnvironmentFiles 非法")
        path, optional = entry
        if not path.startswith("/") or any(c in path for c in "*?%\\"):
            fail("无法核实：不支持的环境文件路径")
        source = Path(path)
        if not source.exists() and optional:
            continue
        environment.update(environment_file(source.read_text(encoding="utf-8")))
    expanded = [argv[0]]
    for token in argv[1:]:
        match = re.fullmatch(r"\$(?:([A-Za-z_][A-Za-z_0-9]*)|\{([A-Za-z_][A-Za-z_0-9]*)\})", token)
        if match:
            key = match[1] or match[2]
            value = environment.get(key, "")
            expanded.extend(environment_words(value) if match[1] else [value])
        elif "$" in token or "%" in token:
            fail("无法核实：不支持的启动参数展开")
        else:
            expanded.append(token)
    if any(any(c in arg for c in "\n\r\x00") for arg in expanded):
        fail("无法核实：启动参数含控制字符")
    if pid:
        # OpenSSH setproctitle overwrites the original environment area.
        # /proc/PID/environ cannot prove drift; compare the actual argv/title.
        raw = Path("/proc", str(pid), "cmdline").read_bytes()
        title = raw.replace(b"\x00", b" ").decode().strip()
        if "[listener]" in title:
            title = title.split("[listener]", 1)[0].strip()
            if title.startswith("sshd: "):
                title = title[6:]
            # OpenSSH's listener title joins argv with spaces; reparsing it
            # would lose argument boundaries in valid -o or -f values.
            matches_runtime = title == " ".join(expanded)
        else:
            runtime_argv = [arg.decode() for arg in raw.split(b"\x00") if arg]
            matches_runtime = runtime_argv == expanded
        if not matches_runtime:
            fail("无法核实：运行中 sshd 的启动参数与服务配置不一致或标题无法完整解析")
    effective = []
    i = 1
    config = "/etc/ssh/sshd_config"
    while i < len(expanded):
        token = expanded[i]
        if token in ("-D", "-e", "-q"):
            i += 1
            continue
        if token in ("-4", "-6"):
            effective.append(token)
            i += 1
            continue
        if len(token) >= 2 and token[:2] in ("-f", "-p", "-o", "-h", "-c", "-E", "-g", "-u"):
            option = token[:2]
            if len(token) > 2:
                value = token[2:]
            else:
                i += 1
                if i >= len(expanded):
                    fail("无法核实：启动参数缺少值")
                value = expanded[i]
            if option == "-o":
                tokens = split(value)
                if not tokens:
                    fail("无法核实：空的 sshd -o 配置选项")
                keyword = re.split(r"[\s=]", tokens[0], maxsplit=1)[0].lower()
                if keyword in {"permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication",
                               "pubkeyauthentication", "denyusers", "include", "match"}:
                    fail("不支持：启动参数覆盖受管认证选项、Include 或 Match：" + keyword)
            if option == "-f":
                if not value.startswith("/"):
                    fail("无法核实：SSH 配置路径不是绝对路径")
                config = value
            # -E is recognized but omitted: configuration test mode must not
            # open the daemon log file during a read-only probe.
            if option != "-E":
                effective += [option, value]
            i += 1
            continue
        fail("无法核实：不支持的 sshd 启动选项 " + token)
    return effective, config


def process_exe(pid):
    try:
        return Path(os.readlink("/proc/" + str(pid) + "/exe")).name
    except (OSError, ValueError):
        return ""


def listening(expected, main_pid, socket_mode):
    actual = set()
    for family in (4, 6):
        for line in run("ss", "-H", "-ltnpe", "-" + str(family)).splitlines():
            fields = line.split()
            if len(fields) < 5:
                fail("无法核实：无法解析 TCP 监听输出")
            pids = {int(x) for x in re.findall(r"pid=(\d+)", line)}
            ssh_pids = {pid for pid in pids if process_exe(pid) in ("sshd", "sshd-session")}
            management_pids = set()
            for pid in ssh_pids:
                title = Path("/proc", str(pid), "cmdline").read_bytes()
                if pid == main_pid or b"[listener]" in title:
                    management_pids.add(pid)
            # Unrelated listeners (including link-local scoped addresses) do
            # not belong to SSH discovery. Only parse their address if their
            # port could collide with an expected management endpoint.
            if not management_pids and fields[3].rsplit(":", 1)[-1] not in {v[2] for v in expected}:
                continue
            raw_values = endpoint(fields[3], family)
            is_expected = bool(raw_values & expected)
            if not management_pids and not (socket_mode and 1 in pids and is_expected):
                if is_expected:
                    fail("不一致：管理端点的监听不属于对应 SSH 服务/socket")
                continue
            bind_dual = False
            if family == 6 and fields[3].rsplit(":", 1)[0].strip("[]") in ("*", "::"):
                match = re.search(r"v6only:([01])", line)
                if not match:
                    fail("无法核实：IPv6 通配监听缺少 v6only 属性")
                bind_dual = match[1] == "0"
            values = endpoint(fields[3], family, bind_dual)
            is_expected = bool(values & expected)
            owned = bool(management_pids) or (socket_mode and 1 in pids and is_expected)
            if management_pids and (not main_pid or management_pids != {main_pid}):
                fail("无法核实：额外 SSH 实例或监听归属不明确")
            if owned:
                actual.update(values)
            elif is_expected:
                fail("不一致：管理端点的监听不属于对应 SSH 服务/socket")
    return actual


def socket_endpoints(props):
    text = props.get("Listen", "")
    tokens = re.findall(r"(\S+) \(([^)]+)\)", text)
    if not tokens or any(kind != "Stream" for _, kind in tokens):
        fail("无法核实：不支持的 ssh.socket 监听类型")
    policy = props.get("BindIPv6Only", "default")
    if policy == "default":
        policy = "ipv6-only" if Path("/proc/sys/net/ipv6/bindv6only").read_text().strip() == "1" else "both"
    if policy not in ("both", "ipv6-only"):
        fail("无法核实：未知 BindIPv6Only")
    dual = policy == "both"
    loaded = set()
    for value, _kind in tokens:
        loaded.update(endpoint(value, dual=dual))
    # cat reads the current fragment/drop-ins, including generated addresses.
    # NeedDaemonReload catches edits to native fragments; comparing the sshd
    # derivation below catches changed generator inputs without running it.
    section = ""
    persistent = []
    for raw in run("systemctl", "cat", "ssh.socket").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            section = line
        elif section == "[Socket]" and line.startswith("ListenStream="):
            value = line.split("=", 1)[1].strip()
            if value:
                persistent.append(value)
            else:
                persistent = []
    on_disk = set()
    for value in persistent:
        on_disk.update(endpoint(value, dual=dual))
    if loaded != on_disk:
        fail("不一致：ssh.socket 持久化与加载端点不同")
    return loaded


def native_source(unit, props):
    source = props.get("FragmentPath", "")
    if not source.startswith(("/etc/systemd/", "/lib/systemd/", "/usr/lib/systemd/")):
        fail("无法核实：" + unit + " 不是已知持久化原生来源")
    drops = split(props.get("DropInPaths", ""))
    if any(not item.startswith(("/etc/systemd/", "/lib/systemd/", "/usr/lib/systemd/", "/run/systemd/generator/", "/run/systemd/generator.early/", "/run/systemd/generator.late/")) for item in drops):
        fail("无法核实：SSH 单元存在不能证明重启持久化的运行期覆盖")


def startup_details(service):
    if service.get("LoadState") != "loaded" or service.get("NeedDaemonReload") != "no":
        fail("无法核实：ssh.service 未加载或需要 daemon-reload")
    native_source("ssh.service", service)
    if any(service.get(key, "") for key in ("RootDirectory", "RootImage", "NetworkNamespacePath")) or service.get("PrivateNetwork", "no") != "no":
        fail("无法核实：SSH 使用不同根目录或网络命名空间")
    pid = int(service.get("MainPID", "0"))
    if pid and process_exe(pid) != "sshd":
        fail("无法核实：SSH 主进程不是 sshd")
    owner = str(pid or 1)
    if os.readlink("/proc/" + owner + "/ns/net") != os.readlink("/proc/self/ns/net") or os.readlink("/proc/" + owner + "/root") != "/":
        fail("无法核实：SSH 与探测器不共享主机根目录和网络命名空间")
    args, config = service_arguments(pid)
    return args, config, pid


def startup():
    args, config, _pid = startup_details(properties("ssh.service"))
    print(config)
    print("\n".join(args), end="\n" if args else "")


def discover():
    service = properties("ssh.service")
    args, config, pid = startup_details(service)
    sock = properties("ssh.socket")
    socket_mode = sock.get("ActiveState") == "active"
    if socket_mode:
        if sock.get("NeedDaemonReload") != "no" or sock.get("Accept") != "no":
            fail("无法核实：ssh.socket 需要重新加载或采用不支持的 Accept 模式")
        native_source("ssh.socket", sock)
    if not socket_mode and (service.get("ActiveState") != "active" or not pid):
        fail("无法核实：SSH 服务未运行且没有活动 socket")
    expected = config_endpoints(run("/usr/sbin/sshd", *args, "-T"))
    if socket_mode and socket_endpoints(sock) != expected:
        fail("不一致：socket 配置与 sshd 有效端点不同")
    actual = listening(expected, pid, socket_mode)
    if expected != actual:
        fail("不一致：配置推导的完整端点集合与实际监听不同")
    ports = {entry[2] for entry in actual}
    if len(ports) != 1:
        fail("不支持：存在多个有效 SSH 管理端口")
    if not any(entry[:2] == ("ipv4", "0.0.0.0") for entry in actual):
        fail("不支持：SSH 缺少 IPv4 全地址监听")
    number = next(iter(ports))
    if number == "80":
        fail("不支持：SSH 管理端口不能为 80（D14）")
    # A new native unit edit during collection invalidates this observation.
    if properties("ssh.service").get("NeedDaemonReload") != "no":
        fail("无法核实：探测期间 SSH 单元发生变化")
    print(number)
    print("socket" if socket_mode else "service")
    print(serial(actual))
    print(config)
    print("\n".join(args), end="\n" if args else "")


def read_record(path, actual, digest, current_version):
    data = {}
    for line in Path(path).read_text().splitlines():
        if "=" not in line:
            fail("不兼容：状态记录不是键值格式")
        key, value = line.split("=", 1)
        if key in data:
            fail("不兼容：状态记录含重复字段")
        data[key] = value
    legacy_versions = {"0.1.0-rc.1", "0.1.0-rc.2", "0.1.0-rc.3", "0.1.0-rc.4", "0.1.0", "0.1.1", "0.1.2"}
    if data.get("version") not in legacy_versions | {current_version}:
        fail("不兼容：状态记录来源版本未知")
    keys = ("ssh_port", "ssh_activation", "ssh_listeners")
    present = [key in data for key in keys]
    if not any(present):
        if data.get("version") not in legacy_versions:
            fail("不兼容：缺少端口字段且不是已知旧版本")
        if actual[0] != "22" or not re.fullmatch(r"[a-f0-9]{64}", digest):
            fail("不兼容：旧 22 基线无法核实")
        if data.get("digest.5") != digest + " /etc/fail2ban/jail.d/99-vps-hardening.local":
            fail("不兼容：旧 jail 的记录摘要不能证明 22 基线")
        print("yes")
        return
    if not all(present):
        fail("不兼容：端口记录字段不完整")
    if data.get("version") in legacy_versions:
        fail("不兼容：旧版本记录含不属于其格式的新端口字段")
    number = port(data["ssh_port"])
    if data["ssh_activation"] not in ("service", "socket"):
        fail("不兼容：未知 SSH 启动方式")
    values = set()
    for item in data["ssh_listeners"].split():
        pieces = item.split(",")
        if len(pieces) != 3 or pieces[0] not in ("ipv4", "ipv6"):
            fail("不兼容：监听基线格式不合法")
        values.update(address(pieces[1], pieces[2], int(pieces[0][-1])))
    if not values or serial(values) != data["ssh_listeners"] or {v[2] for v in values} != {number}:
        fail("不兼容：监听基线没有规范化或端口不一致")
    if [number, data["ssh_activation"], data["ssh_listeners"]] != actual:
        fail("漂移：当前管理入口或启动方式与应用记录不同")
    print("no")


def connection(shell_pid, expected_port):
    ancestors = []
    pid = int(shell_pid)
    seen = set()
    while pid > 1 and pid not in seen:
        seen.add(pid)
        proc = Path("/proc", str(pid))
        if process_exe(pid) in ("sshd", "sshd-session"):
            title = proc.joinpath("cmdline").read_bytes()
            if b"[listener]" in title:
                break
            ancestors.append(pid)
        status = proc.joinpath("status").read_text()
        match = re.search(r"^PPid:\s+(\d+)$", status, re.M)
        if not match:
            fail("无法核实：进程父子关系不可读")
        pid = int(match[1])
    if not ancestors:
        fail("无法核实：没有实际 sshd 会话祖先")
    established = {}
    for family in ("tcp", "tcp6"):
        for line in Path("/proc/net", family).read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] == "01":
                established[fields[9]] = (fields[1], fields[2], str(int(fields[1].split(":")[1], 16)))
    # The privileged monitor nearest the listener owns the accepted transport,
    # while a session child may additionally own forwarded channel sockets.
    for pid in reversed(ancestors):
        transports = set()
        for fd in Path("/proc", str(pid), "fd").iterdir():
            try:
                match = re.fullmatch(r"socket:\[(\d+)\]", os.readlink(fd))
            except OSError:
                continue
            if match and match[1] in established:
                transports.add(established[match[1]])
        if transports:
            if len(transports) != 1:
                fail("无法核实：SSH 会话对应多个实际 TCP 连接")
            if next(iter(transports))[2] != expected_port:
                fail("不一致：当前 SSH 会话的本机连接端口不是记录 P")
            return
    fail("无法核实：无法将会话关联到实际 ESTABLISHED 连接")


try:
    mode = sys.argv[1]
    if mode == "discover":
        discover()
    elif mode == "startup":
        startup()
    elif mode == "config":
        print(serial(config_endpoints(Path(sys.argv[2]).read_text())))
    elif mode == "record":
        read_record(sys.argv[2], sys.argv[3:6], sys.argv[6], sys.argv[7])
    elif mode == "connection":
        connection(sys.argv[2], sys.argv[3])
    else:
        fail("未知 SSH 探测操作")
except (ValueError, OSError, IndexError, UnicodeError) as exc:
    print(str(exc), file=sys.stderr)
    sys.exit(1)
VH_SSH_PY
}

ssh_endpoint_clear() {
  VH_SSH_PORT='' VH_SSH_ACTIVATION='' VH_SSH_LISTENERS=''
  VH_SSHD_VERIFIED=no
  VH_SSHD_ARGS=()
}

ssh_endpoint_discover() {
  local output fields=()
  ssh_endpoint_clear
  VH_SSH_ERROR=''
  VH_SSH_LEGACY=no
  if ! output="$(ssh_probe_python discover 2>&1)"; then
    VH_SSH_ERROR="${output:-无法核实：SSH 入口探测失败或超时}"
    return 1
  fi
  mapfile -t fields <<<"$output"
  if [ "${#fields[@]}" -lt 4 ]; then
    VH_SSH_ERROR='无法核实：SSH 探测结果不完整'
    return 1
  fi
  VH_SSH_PORT="${fields[0]}"
  VH_SSH_ACTIVATION="${fields[1]}"
  VH_SSH_LISTENERS="${fields[2]}"
  VH_SSHD_CONFIG="${fields[3]}"
  VH_SSHD_ARGS=("${fields[@]:4}")
  # shellcheck disable=SC2034 # consumed by verify.sh
  VH_SSHD_VERIFIED=yes
  sshd_cache_clear
}

# Recovery can validate the startup/configuration source independently of a
# drifted or temporarily absent listener; it still must check the endpoint
# after the file and service restore, before disarming recovery.
ssh_startup_probe() {
  local output fields=()
  VH_SSHD_ARGS=()
  VH_SSHD_VERIFIED=no
  VH_SSH_ERROR=''
  if ! output="$(ssh_probe_python startup 2>&1)"; then
    VH_SSH_ERROR="${output:-无法核实：SSH 启动来源读取失败或超时}"
    return 1
  fi
  mapfile -t fields <<<"$output"
  [ "${#fields[@]}" -gt 0 ] && [ -n "${fields[0]}" ] || return 1
  # shellcheck disable=SC2034 # consumed by preflight.sh and rollback.sh
  VH_SSHD_CONFIG="${fields[0]}"
  VH_SSHD_ARGS=("${fields[@]:1}")
  # shellcheck disable=SC2034 # consumed by verify.sh
  VH_SSHD_VERIFIED=yes
  sshd_cache_clear
}

ssh_endpoint_check_record() {
  local legacy_digest='' output
  ssh_endpoint_discover || return 1
  # A known old template's digest proves the recorded jail's original port,
  # including after restore has removed that file. No on-disk migration occurs.
  if [ -z "$(state_get ssh_port)$(state_get ssh_activation)$(state_get ssh_listeners)" ] &&
    declare -F f2b_jail_content >/dev/null; then
    legacy_digest="$(f2b_jail_content | sha256sum | awk '{print $1}')" || legacy_digest=''
  fi
  if ! output="$(ssh_probe_python record "$VH_STATE_FILE" "$VH_SSH_PORT" "$VH_SSH_ACTIVATION" "$VH_SSH_LISTENERS" "$legacy_digest" "$VH_VERSION" 2>&1)"; then
    VH_SSH_ERROR="${output:-无法核实：SSH 记录检查失败或超时}"
    # Discovery succeeded: retain its safe configuration arguments for
    # independent authentication checks, but never expose its drifted P to
    # firewall/jail consumers after the baseline comparison failed.
    VH_SSH_PORT='' VH_SSH_ACTIVATION='' VH_SSH_LISTENERS=''
    return 1
  fi
  VH_SSH_LEGACY="$output"
}

ssh_endpoint_report() {
  local id="$1" hint=''
  if ssh_endpoint_check_record; then
    [ "$VH_SSH_LEGACY" != yes ] || hint='（旧 22 记录只读兼容）'
    report PASS "$id" "本机 SSH 入口符合记录：$VH_SSH_PORT/tcp，$VH_SSH_ACTIVATION$hint"
    return 0
  fi
  report FAIL "$id" "$VH_SSH_ERROR"
  return 1
}

ssh_endpoint_from_config() {
  ssh_probe_python config "$1"
}

ssh_confirm_connection() {
  local output
  if [ -z "$VH_SSH_PORT" ]; then
    VH_SSH_ERROR='无法核实：没有有效的 SSH 管理端口基线'
    return 1
  fi
  if ! output="$(ssh_probe_python connection "$$" "$VH_SSH_PORT" 2>&1)"; then
    VH_SSH_ERROR="${output:-无法核实：SSH 连接关联失败或超时}"
    return 1
  fi
}
