# shellcheck shell=bash
# Platform detection (requirements A-1, D11).
# Globals defined here are read by the other modules, which ShellCheck checks separately.
# shellcheck disable=SC2034

VH_OS_ID=''
VH_OS_VERSION=''
VH_OS_CODENAME=''
VH_OS_PRETTY=''
VH_ARCH=''
VH_PLATFORM=''

# os-release is parsed, never sourced: it is data, not a script.
os_release_value() {
  local key="$1" file="${2:-/etc/os-release}" line value
  [ -r "$file" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      "$key="*)
        value="${line#*=}"
        value="${value#\"}"
        value="${value%\"}"
        value="${value#\'}"
        value="${value%\'}"
        printf '%s\n' "$value"
        return 0
        ;;
    esac
  done <"$file"
  return 1
}

detect_platform() {
  VH_OS_ID="$(os_release_value ID || true)"
  VH_OS_VERSION="$(os_release_value VERSION_ID || true)"
  VH_OS_CODENAME="$(os_release_value VERSION_CODENAME || true)"
  VH_OS_PRETTY="$(os_release_value PRETTY_NAME || true)"
  VH_ARCH="$(uname -m)"
  VH_PLATFORM=''
  case "$VH_OS_ID:$VH_OS_VERSION" in
    debian:12) VH_PLATFORM=debian12 ;;
    debian:13) VH_PLATFORM=debian13 ;;
    ubuntu:24.04) VH_PLATFORM=ubuntu2404 ;;
  esac
  case "$VH_ARCH" in
    x86_64 | aarch64) ;;
    *) VH_PLATFORM='' ;;
  esac
}

pid1_is_systemd() {
  [ "$(cat /proc/1/comm 2>/dev/null)" = systemd ]
}

# Containers share the host's firewall and are outside the supported scope.
in_container() {
  have systemd-detect-virt && systemd-detect-virt --container --quiet
}
