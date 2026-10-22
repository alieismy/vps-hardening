# shellcheck shell=bash
# Shared constants, reporting and small helpers. Sourced by bin/vps-hardening.
# Globals defined here are read by the other modules, which ShellCheck checks separately.
# shellcheck disable=SC2034

readonly VH_EXIT_OK=0
readonly VH_EXIT_FAIL=1
readonly VH_EXIT_USAGE=2
readonly VH_EXIT_INTERNAL=3

readonly VH_STATE_DIR=/var/lib/vps-hardening
readonly VH_SSHD_MAIN=/etc/ssh/sshd_config
readonly VH_SSHD_DROPIN_DIR=/etc/ssh/sshd_config.d
readonly VH_SSHD_DROPIN_NAME=00-vps-hardening.conf
readonly VH_PANEL_PORT_DEFAULT=2053
readonly VH_TIMEOUT_DEFAULT=10
readonly VH_TIMEOUT_MIN=3
readonly VH_TIMEOUT_MAX=60
# Packages apply installs (design 7.3 step 4).
readonly VH_PACKAGES=(ufw fail2ban nftables python3-systemd unattended-upgrades)
# sshd keywords the tool manages; nothing may set them before its drop-in.
readonly VH_SSHD_MANAGED='permitrootlogin passwordauthentication kbdinteractiveauthentication pubkeyauthentication denyusers'
# Placeholder connection used to evaluate Match blocks with sshd -T -C.
readonly VH_SSHD_PROBE_CONN='host=vps-hardening.invalid,addr=192.0.2.1,laddr=192.0.2.2,lport=22'

# Function the ERR trap calls before exiting, set while a failure must undo changes.
VH_ABORT_HOOK=''

VH_COUNT_PASS=0
VH_COUNT_FAIL=0
VH_COUNT_WARN=0
VH_COUNT_SKIP=0

# report LEVEL ID MESSAGE...
# LEVEL is PASS, FAIL, WARN, SKIP or INFO. IDs are stable; tests match on them.
report() {
  local level="$1" id="$2"
  shift 2
  case "$level" in
    PASS) VH_COUNT_PASS=$((VH_COUNT_PASS + 1)) ;;
    FAIL) VH_COUNT_FAIL=$((VH_COUNT_FAIL + 1)) ;;
    WARN) VH_COUNT_WARN=$((VH_COUNT_WARN + 1)) ;;
    SKIP) VH_COUNT_SKIP=$((VH_COUNT_SKIP + 1)) ;;
    INFO) ;;
    *) internal_error "未知的报告级别：$level" ;;
  esac
  printf '[%s] %-30s %s\n' "$level" "$id" "$*"
}

report_summary() {
  printf '\n结果：%d 项通过，%d 项不符合，%d 项警告，%d 项跳过。\n' \
    "$VH_COUNT_PASS" "$VH_COUNT_FAIL" "$VH_COUNT_WARN" "$VH_COUNT_SKIP"
}

# Print the summary and exit. Exiting here, rather than returning a status,
# keeps a FAIL result from being mistaken for an internal error by the ERR trap.
finish_checks() {
  report_summary
  if [ "$VH_COUNT_FAIL" -eq 0 ]; then
    exit "$VH_EXIT_OK"
  fi
  exit "$VH_EXIT_FAIL"
}

usage_error() {
  printf '[x] %s\n' "$*" >&2
  printf '    用法见 vps-hardening --help\n' >&2
  exit "$VH_EXIT_USAGE"
}

# A command refused before it changed anything.
refuse() {
  printf '[x] %s\n' "$*" >&2
  exit "$VH_EXIT_FAIL"
}

# safeguards_prompt UNTIL (FR-05): the administrator confirms both safeguards
# explicitly before apply, ports or rollback changes anything. UNTIL names the
# end of the operation that the current session must outlive.
safeguards_prompt() {
  local answer=''
  printf '\n开始之前请确认：\n'
  printf '  1. 当前 SSH 会话会一直保持，直到%s；\n' "$1"
  printf '  2. 服务商控制台或救援模式可用。\n'
  printf '两项都满足请输入 yes：'
  read -r answer || return 1
  [ "$answer" = yes ]
}

internal_error() {
  printf '[x] 内部错误：%s\n' "$*" >&2
  exit "$VH_EXIT_INTERNAL"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

# Read-only commands still get a bound so a hung service cannot stall a check.
bounded() {
  timeout --kill-after=5 30 "$@"
}

# Commands that change the system get a longer bound (a restart may wait for a
# slow stop). Bash runs signal traps only after the current command returns,
# so without a bound a hung command would also hold off the restore.
bounded_change() {
  timeout --kill-after=10 120 "$@"
}

# Private scratch directory, removed on exit. Call in the main shell, never
# inside $(...), or the trap would fire when the subshell exits.
VH_TMP=''
vh_tmp_init() {
  if [ -z "$VH_TMP" ]; then
    VH_TMP="$(mktemp -d /tmp/vps-hardening.XXXXXXXX)" || internal_error '无法创建临时目录'
    trap 'rm -rf -- "$VH_TMP"' EXIT
  fi
}

join_by() {
  local sep="$1" first=1 item
  shift
  for item in "$@"; do
    if [ "$first" -eq 1 ]; then
      printf '%s' "$item"
      first=0
    else
      printf '%s%s' "$sep" "$item"
    fi
  done
}
