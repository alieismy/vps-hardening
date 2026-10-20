# shellcheck shell=bash
# Tool state (design 7.7): the state file, the operation log, the lock shared
# by apply, confirm and the automatic restore, and the file snapshot that every
# restore path uses (design 4.4).
# Globals defined here are read by the other modules, which ShellCheck checks separately.
# shellcheck disable=SC2034

readonly VH_STATE_FILE="$VH_STATE_DIR/state"
readonly VH_PENDING_FILE="$VH_STATE_DIR/pending"
readonly VH_LOG_FILE="$VH_STATE_DIR/log"
readonly VH_SNAPSHOT_DIR="$VH_STATE_DIR/snapshot"
readonly VH_UNITS_FILE="$VH_STATE_DIR/units"
readonly VH_UFW_RULES_FILE="$VH_STATE_DIR/ufw-rules"
readonly VH_LOCK_FILE=/run/vps-hardening.lock

# Files apply may change. The snapshot is taken after package installation, so
# files a package installed are restored to the package's version.
readonly VH_MANAGED_FILES=(
  "$VH_SSHD_DROPIN_DIR/$VH_SSHD_DROPIN_NAME"
  /etc/default/ufw
  /etc/ufw/ufw.conf
  /etc/ufw/user.rules
  /etc/ufw/user6.rules
  /etc/fail2ban/jail.d/99-vps-hardening.local
  /etc/fail2ban/fail2ban.local
  /etc/apt/apt.conf.d/52vps-hardening
)
# Units whose enablement and activity apply may change, recorded before
# package installation so that a package's own defaults are undone as well.
readonly VH_MANAGED_UNITS=(ufw.service fail2ban.service apt-daily.timer apt-daily-upgrade.timer)

# state_get KEY [FILE]: the value of KEY, or nothing.
state_get() {
  local file="${2:-$VH_STATE_FILE}"
  [ -r "$file" ] || return 0
  KEY="$1" awk 'index($0, ENVIRON["KEY"] "=") == 1 && !seen { print substr($0, length(ENVIRON["KEY"]) + 2); seen = 1 }' "$file"
}

# state_set KEY VALUE [FILE]: replace or add one line, atomically.
state_set() {
  local file="${3:-$VH_STATE_FILE}"
  case "$2" in
    *$'\n'*) internal_error "状态值含换行：$1" ;;
  esac
  [ -e "$file" ] || : >"$file"
  KEY="$1" VALUE="$2" awk '
    index($0, ENVIRON["KEY"] "=") == 1 { if (!done) print ENVIRON["KEY"] "=" ENVIRON["VALUE"]; done = 1; next }
    { print }
    END { if (!done) print ENVIRON["KEY"] "=" ENVIRON["VALUE"] }
  ' "$file" >"$file.new"
  mv -f -- "$file.new" "$file"
  sync -- "$file"
}

utc_now() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

vh_log() {
  printf '%s %s\n' "$(utc_now)" "$*" >>"$VH_LOG_FILE"
}

# vh_lock SECONDS: take the operation lock, waiting at most SECONDS. The lock
# lives in /run, so a reboot never leaves it held.
vh_lock() {
  exec 9>"$VH_LOCK_FILE"
  flock -w "$1" 9
}

state_dir_init() {
  install -d -m 0700 -o root -g root -- "$VH_STATE_DIR"
}

# Record each managed file: presence, digest, mode and owner, plus a private
# copy. Index lines: "N present DIGEST MODE:UID:GID PATH" or "N absent - - PATH".
snapshot_take() {
  local i=0 path
  rm -rf -- "$VH_SNAPSHOT_DIR"
  install -d -m 0700 -- "$VH_SNAPSHOT_DIR"
  for path in "${VH_MANAGED_FILES[@]}"; do
    if [ -L "$path" ] || { [ -e "$path" ] && [ ! -f "$path" ]; }; then
      printf '%s 不是普通文件，本工具不处理这种情况\n' "$path"
      return 1
    fi
    if [ -f "$path" ]; then
      install -m 0600 -- "$path" "$VH_SNAPSHOT_DIR/$i"
      printf '%s present %s %s %s\n' "$i" "$(file_digest "$path")" "$(stat -c '%a:%u:%g' -- "$path")" "$path"
    else
      printf '%s absent - - %s\n' "$i" "$path"
    fi >>"$VH_SNAPSHOT_DIR/index"
    i=$((i + 1))
  done
  sync -f -- "$VH_SNAPSHOT_DIR/index"
}

# Put every managed file back as recorded. Called in a condition, so errexit
# is off here: each failure is checked and counted instead.
snapshot_restore() {
  local index="$VH_SNAPSHOT_DIR/index" i kind digest meta path mode uid gid errors=0
  [ -f "$index" ] || return 0
  while read -r i kind digest meta path; do
    if [ "$kind" = present ]; then
      IFS=: read -r mode uid gid <<<"$meta"
      if ! install -m "$mode" -o "$uid" -g "$gid" -- "$VH_SNAPSHOT_DIR/$i" "$path.vh-restore" ||
        ! mv -f -- "$path.vh-restore" "$path"; then
        printf '无法恢复 %s\n' "$path"
        errors=$((errors + 1))
      elif [ "$(sha256sum <"$path" | awk '{print $1}')" != "$digest" ]; then
        printf '%s 恢复后摘要不符\n' "$path"
        errors=$((errors + 1))
      fi
    elif [ -e "$path" ] && ! rm -f -- "$path"; then
      printf '无法删除 %s\n' "$path"
      errors=$((errors + 1))
    fi
  done <"$index"
  sync
  [ "$errors" -eq 0 ]
}

# Digest of a managed file, or "absent".
file_digest() {
  if [ -f "$1" ]; then
    sha256sum <"$1" | awk '{print $1}'
  else
    printf 'absent\n'
  fi
}

# One line per managed unit: name, whether it exists, is-enabled, is-active.
units_record() {
  local unit exists enabled active
  : >"$VH_UNITS_FILE"
  for unit in "${VH_MANAGED_UNITS[@]}"; do
    if unit_exists "$unit"; then
      exists=yes
      enabled="$(systemctl is-enabled -- "$unit" 2>/dev/null)" || true
      active="$(systemctl is-active -- "$unit" 2>/dev/null)" || true
    else
      exists=no enabled=- active=-
    fi
    printf '%s %s %s %s\n' "$unit" "$exists" "${enabled:--}" "${active:--}" >>"$VH_UNITS_FILE"
  done
}
