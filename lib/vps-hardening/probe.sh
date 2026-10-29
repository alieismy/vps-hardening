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
    bounded /usr/sbin/sshd -T -C "user=$user,$VH_SSHD_PROBE_CONN" >"$cache" 2>"$VH_TMP/sshd-T.err" ||
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
# there (requirements D61). sshd skips the shell test under ChrootDirectory,
# which the Match check and a new host rule out. Accounts sshd refuses for
# other reasons stay in: denying them as well changes nothing.
login_accounts() {
  local name _pw _uid _gid _gecos _home shell
  while IFS=: read -r name _pw _uid _gid _gecos _home shell; do
    [ "$name" != root ] || continue
    shell="${shell:-/bin/sh}"
    if [ -f "$shell" ] && [ -x "$shell" ]; then
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
