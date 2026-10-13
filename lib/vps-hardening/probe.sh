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

# All values of one keyword from sshd -T output on stdin, one per line.
# Array keywords (denyusers) may appear on several lines or space-separated.
sshd_values() {
  awk -v key="$1" '$1 == key { for (i = 2; i <= NF; i++) print $i }'
}

sshd_value() {
  awk -v key="$1" '$1 == key && !seen { print $2; seen = 1 }'
}

# Login accounts other than root: a shell listed in /etc/shells.
login_accounts() {
  local name _pw _uid _gid _gecos _home shell
  while IFS=: read -r name _pw _uid _gid _gecos _home shell; do
    [ "$name" != root ] || continue
    grep -qxF -- "$shell" /etc/shells 2>/dev/null || continue
    printf '%s\n' "$name"
  done < <(getent passwd)
}

# Expand AuthorizedKeysFile tokens (%h %u %U %%) for one user.
authorized_keys_files() {
  local user="$1" home uid token path
  home="$(getent passwd "$user" | cut -d: -f6)"
  uid="$(id -u "$user" 2>/dev/null)" || return 0
  sshd_effective "$user" | sshd_values authorizedkeysfile | while IFS= read -r token; do
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

# Lines of `ufw show added`, without the header.
ufw_added_rules() {
  bounded ufw show added 2>/dev/null | sed -n 's/^ufw //p'
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

fail2ban_has_custom_config() {
  local entry
  [ -d /etc/fail2ban ] || return 1
  if find /etc/fail2ban -name '*.local' -print -quit 2>/dev/null | grep -q .; then
    return 0
  fi
  for entry in /etc/fail2ban/jail.d/* /etc/fail2ban/fail2ban.d/*; do
    [ -e "$entry" ] || continue
    [ "$entry" = /etc/fail2ban/jail.d/defaults-debian.conf ] && continue
    return 0
  done
  pkg_installed fail2ban && [ -n "$(dpkg --verify fail2ban 2>/dev/null)" ]
}
