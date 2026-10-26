#!/usr/bin/env bash
# Release-pinned installer for vps-hardening (requirements NFR-07, solution
# design 4.5). It installs /usr/local/bin/vps-hardening and the modules in
# /usr/local/lib/vps-hardening, after checking every file against SHA256SUMS
# and SHA256SUMS against the digest pinned below. It never runs apply.

set -Eeuo pipefail
umask 077
PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
LC_ALL=C
export PATH LC_ALL

# Set together at each release; tests/static.sh checks the version and the
# asset list against bin/vps-hardening. An empty digest means this copy is not
# bound to a release and installs nothing.
INSTALLER_VERSION='0.1.0'
RELEASE_TAG='v0.1.0'
REPOSITORY='alieismy/vps-hardening'
EXPECTED_MANIFEST_SHA256=''

readonly BIN_PATH=/usr/local/bin/vps-hardening
readonly LIB_PARENT=/usr/local/lib
readonly LIB_DIR="$LIB_PARENT/vps-hardening"
readonly LOCK_FILE=/run/vps-hardening.lock
readonly PENDING_FILE=/var/lib/vps-hardening/pending
readonly STATE_FILE=/var/lib/vps-hardening/state

# Release assets, flat. The first is the command; the rest are its modules.
assets=(
  vps-hardening
  common.sh
  platform.sh
  inputs.sh
  probe.sh
  preflight.sh
  verify.sh
  state.sh
  pending.sh
  apply.sh
  status.sh
  rollback.sh
  ports.sh
)

source_dir=''
temp_dir=''
stage_dir=''
old_dir=''
bin_tmp=''
old_bin=''
swapping=0

info() { printf '[vps-hardening-install] %s\n' "$*"; }
die() {
  printf '[vps-hardening-install][x] %s\n' "$*" >&2
  exit 1
}
usage_die() {
  printf '[vps-hardening-install][x] %s\n' "$*" >&2
  printf '    用法见 bash install.sh --help\n' >&2
  exit 2
}

# Put back the command and modules from before this run; 1 if a step fails.
# Whether a rename happened is read from the files, not from a variable, so a
# signal right after a rename is handled the same way.
restore_previous() {
  if [ ! -e "$bin_tmp" ]; then
    if [ -n "$old_bin" ]; then
      mv -f -- "$old_bin" "$BIN_PATH" || return 1
    else
      rm -f -- "$BIN_PATH" || return 1
    fi
  fi
  if [ ! -e "$stage_dir" ]; then
    rm -rf -- "$LIB_DIR" || return 1
  fi
  if [ -n "$old_dir" ] && [ -d "$old_dir" ]; then
    mv -T -- "$old_dir" "$LIB_DIR" || return 1
  fi
}

# Until the new files are in place and run, a failure or signal puts the
# previous ones back; the install either completes or changes nothing.
cleanup() {
  trap '' INT TERM HUP
  if [ "$swapping" -eq 1 ]; then
    if restore_previous; then
      info '安装未完成，已恢复为安装前的状态'
    else
      printf '[vps-hardening-install][x] %s\n' "安装未完成，恢复安装前的文件时出错；安装前的模块和入口保留在 ${old_dir:-（无）}、${old_bin:-（无）}" >&2
      old_dir=''
      old_bin=''
    fi
  fi
  [ -z "$stage_dir" ] || rm -rf -- "$stage_dir"
  [ -z "$bin_tmp" ] || rm -f -- "$bin_tmp"
  [ -z "$old_dir" ] || rm -rf -- "$old_dir"
  [ -z "$old_bin" ] || rm -f -- "$old_bin"
  [ -z "$temp_dir" ] || rm -rf -- "$temp_dir"
}

usage() {
  cat <<EOF
用法：
  bash install.sh
  bash install.sh --source-dir /绝对路径/发行版资产

远程方式只下载固定的 $RELEASE_TAG 发行版：先用本脚本内置的摘要校验 SHA256SUMS，
再用 SHA256SUMS 校验每个资产。本地方式用于发行前验证，目录中须有同样的资产和
SHA256SUMS，同样要通过内置摘要的校验。安装只放置文件，不执行 preflight 或 apply。
有待确认的变更，或另一个 vps-hardening 操作正在进行时，拒绝安装。
EOF
}

download_file() {
  curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 120 --max-redirs 5 --output "$2" "$1"
}

file_sha256() {
  sha256sum <"$1" | awk '{print $1}'
}

# The manifest lists exactly the assets, each once, as "DIGEST  NAME".
manifest_valid() {
  local name
  [ "$(awk 'NF' "$1" | wc -l)" -eq "${#assets[@]}" ] || return 1
  # No regex interval: mawk on Debian 12 (1.3.4 20200120) does not support {64}.
  for name in "${assets[@]}"; do
    [ "$(awk -v name="$name" '$2 == name && length($1) == 64 && $1 !~ /[^0-9a-f]/ && NF == 2 { n++ } END { print n + 0 }' "$1")" -eq 1 ] ||
      return 1
  done
}

manifest_digest() {
  awk -v name="$2" '$2 == name { print $1; exit }' "$1"
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --source-dir)
        [ "$#" -ge 2 ] || usage_die '--source-dir 缺少取值'
        source_dir="$2"
        shift 2
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *) usage_die "未知参数：$1" ;;
    esac
  done
}

# True when the installed files are exactly this release, with the owners and
# modes this script gives them.
already_installed() {
  local name
  [ -f "$BIN_PATH" ] && [ ! -L "$BIN_PATH" ] && [ -d "$LIB_DIR" ] && [ ! -L "$LIB_DIR" ] || return 1
  [ "$(stat -c '%u:%g:%a' -- "$BIN_PATH")" = '0:0:755' ] || return 1
  [ "$(stat -c '%u:%g:%a' -- "$LIB_DIR")" = '0:0:755' ] || return 1
  [ "$(file_sha256 "$BIN_PATH")" = "$(manifest_digest "$temp_dir/SHA256SUMS" vps-hardening)" ] || return 1
  [ "$(find "$LIB_DIR" -mindepth 1 | wc -l)" -eq $((${#assets[@]} - 1)) ] || return 1
  for name in "${assets[@]:1}"; do
    [ -f "$LIB_DIR/$name" ] && [ ! -L "$LIB_DIR/$name" ] || return 1
    [ "$(stat -c '%u:%g:%a' -- "$LIB_DIR/$name")" = '0:0:644' ] || return 1
    [ "$(file_sha256 "$LIB_DIR/$name")" = "$(manifest_digest "$temp_dir/SHA256SUMS" "$name")" ] || return 1
  done
}

main() {
  local command name base got
  parse_args "$@"
  [ "$(id -u)" -eq 0 ] || die '需要 root 权限：请在 root shell 中运行'
  for command in awk cp curl find flock grep install mktemp mv rm sha256sum stat sync wc; do
    [ -n "$source_dir" ] && [ "$command" = curl ] && continue
    command -v "$command" >/dev/null 2>&1 || die "缺少命令：$command"
  done
  [ "$RELEASE_TAG" = "v$INSTALLER_VERSION" ] || die '安装脚本的版本与发行版标签不一致'
  [[ "$EXPECTED_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
    die '这份安装脚本没有绑定发行版（内置摘要为空）；请使用发行版附带的 install.sh'
  if [ -n "$source_dir" ]; then
    [[ "$source_dir" = /* ]] || usage_die '--source-dir 必须是绝对路径'
    [ -d "$source_dir" ] && [ ! -L "$source_dir" ] || die '--source-dir 不存在，或是符号链接'
  fi

  # The tool's own lock: no apply, confirm, ports, rollback or restore runs
  # while the files change.
  exec 9>"$LOCK_FILE"
  flock -n 9 || die '另一个 vps-hardening 操作正在进行，请稍后再试'
  # While a change awaits confirmation, systemd calls the installed tool.
  [ ! -e "$PENDING_FILE" ] || die '有待确认的变更：请先确认，或等待自动恢复，然后再安装'

  temp_dir="$(mktemp -d)" || die '无法创建临时目录'
  trap cleanup EXIT
  trap 'exit 1' INT TERM HUP
  mkdir -m 0700 "$temp_dir/assets"
  if [ -n "$source_dir" ]; then
    [ -f "$source_dir/SHA256SUMS" ] && [ ! -L "$source_dir/SHA256SUMS" ] || die '资产目录中没有 SHA256SUMS'
    cp -- "$source_dir/SHA256SUMS" "$temp_dir/SHA256SUMS"
  else
    base="https://github.com/$REPOSITORY/releases/download/$RELEASE_TAG"
    info "下载 $RELEASE_TAG 的 SHA256SUMS"
    download_file "$base/SHA256SUMS" "$temp_dir/SHA256SUMS" || die '无法下载 SHA256SUMS；不会改用其他版本'
  fi
  got="$(file_sha256 "$temp_dir/SHA256SUMS")"
  [ "$got" = "$EXPECTED_MANIFEST_SHA256" ] || die "SHA256SUMS 的摘要 $got 与安装脚本内置的不一致"
  manifest_valid "$temp_dir/SHA256SUMS" || die 'SHA256SUMS 的内容与安装脚本的资产清单不一致'

  for name in "${assets[@]}"; do
    if [ -n "$source_dir" ]; then
      [ -f "$source_dir/$name" ] && [ ! -L "$source_dir/$name" ] || die "资产目录中没有 $name"
      cp -- "$source_dir/$name" "$temp_dir/assets/$name"
    else
      info "下载 $name"
      download_file "$base/$name" "$temp_dir/assets/$name" || die "无法下载 $name"
    fi
    [ "$(file_sha256 "$temp_dir/assets/$name")" = "$(manifest_digest "$temp_dir/SHA256SUMS" "$name")" ] ||
      die "$name 未通过 SHA-256 校验"
  done
  grep -Fqx "readonly VH_VERSION='$INSTALLER_VERSION'" "$temp_dir/assets/vps-hardening" ||
    die "vps-hardening 的版本不是 $INSTALLER_VERSION"

  if already_installed; then
    info "已安装 vps-hardening $INSTALLER_VERSION，文件与发行版一致，未做变更"
    exit 0
  fi
  if [ -L "$LIB_DIR" ] || { [ -e "$LIB_DIR" ] && [ ! -d "$LIB_DIR" ]; }; then
    die "$LIB_DIR 不是普通目录"
  fi
  [ ! -e "$BIN_PATH" ] || [ -f "$BIN_PATH" ] || die "$BIN_PATH 不是普通文件"

  install -d -o root -g root -m 0755 /usr/local/bin "$LIB_PARENT"
  stage_dir="$LIB_PARENT/.vps-hardening.stage.$$"
  install -d -o root -g root -m 0755 "$stage_dir"
  for name in "${assets[@]:1}"; do
    install -o root -g root -m 0644 "$temp_dir/assets/$name" "$stage_dir/$name"
  done
  bin_tmp="/usr/local/bin/.vps-hardening.new.$$"
  install -o root -g root -m 0755 "$temp_dir/assets/vps-hardening" "$bin_tmp"

  if [ -e "$BIN_PATH" ]; then
    old_bin="/usr/local/bin/.vps-hardening.old.$$"
    cp -a -- "$BIN_PATH" "$old_bin"
  fi
  swapping=1
  if [ -d "$LIB_DIR" ]; then
    old_dir="$LIB_PARENT/.vps-hardening.old.$$"
    mv -T -- "$LIB_DIR" "$old_dir"
  fi
  mv -T -- "$stage_dir" "$LIB_DIR"
  mv -f -- "$bin_tmp" "$BIN_PATH"
  got="$("$BIN_PATH" --version)" || die '安装后无法运行 vps-hardening --version'
  [ "$got" = "vps-hardening $INSTALLER_VERSION" ] || die "安装后的版本为 $got"
  sync
  swapping=0
  stage_dir=''
  bin_tmp=''
  [ -z "$old_dir" ] || rm -rf -- "$old_dir"
  [ -z "$old_bin" ] || rm -f -- "$old_bin"
  old_dir=''
  old_bin=''
  info "安装完成：$BIN_PATH（模块在 $LIB_DIR），版本 $INSTALLER_VERSION"
  # On a host the tool has applied, preflight would only refuse.
  if grep -qx 'status=applied' "$STATE_FILE" 2>/dev/null; then
    info '安装没有改变已应用的配置。下一步：vps-hardening verify 核对配置，vps-hardening status 查看记录'
  else
    info '安装没有执行 preflight 或 apply。下一步：vps-hardening preflight'
  fi
}

main "$@"
