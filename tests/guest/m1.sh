#!/usr/bin/env bash
# Guest side of the M1 VM tests (docs/verification-plan.md, VT-01 to VT-04 and
# the unhardened part of VT-50). Runs as root inside a disposable QEMU guest;
# tests/vm.py runs one phase per SSH session.

set -Eeuo pipefail
PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
LC_ALL=C
DEBIAN_FRONTEND=noninteractive
export PATH LC_ALL DEBIAN_FRONTEND

readonly BUNDLE=/opt/vh-bundle
readonly VH="$BUNDLE/bin/vps-hardening"
readonly KEYS=/opt/vh-keys
readonly EVIDENCE=/root/vh-evidence
# Never archived: the 3X-UI installer prints generated panel credentials here.
readonly PRIVATE=/root/vh-private
readonly XUI_INSTALL_SHA256=a7f4fedcea3abe8987508d00f29834b8872e4e4e5059159eb19460d474b37cdc
readonly XUI_SCRIPT_SHA256=cfabcd4af35a3646c374ea0ccba5178f4c0d3135f699277fc8d8b810158e85c0

GOOD_ARGS=(--open 443/tcp --open 2096/tcp)
phase_dir=''

log() { printf '[+] %s\n' "$*"; }
fail() {
  printf '[x] %s\n' "$*" >&2
  exit 1
}

os_id() {
  sed -n 's/^ID=//p' /etc/os-release | tr -d '"'
}

default_user() {
  case "$(os_id)" in
    debian) printf 'debian\n' ;;
    ubuntu) printf 'ubuntu\n' ;;
    *) fail "unexpected guest OS: $(os_id)" ;;
  esac
}

# capture NAME CMD...: run CMD with stdin from /dev/null; keep output and status.
capture() {
  local name="$1" rc=0
  shift
  "$@" </dev/null >"$phase_dir/$name.out" 2>&1 || rc=$?
  printf '%s\n' "$rc" >"$phase_dir/$name.rc"
  log "$name: exit $rc"
  sed 's/^/    /' "$phase_dir/$name.out"
}

expect_rc() {
  local got
  got="$(cat "$phase_dir/$1.rc")"
  [ "$got" = "$2" ] || fail "$1: exit status $got, expected $2"
}

# expect_report NAME LEVEL ID
expect_report() {
  grep -qE "^\[$2\] ${3//./\\.}( |$)" "$phase_dir/$1.out" || fail "$1: no [$2] $3 line"
}

expect_text() {
  grep -qF -- "$2" "$phase_dir/$1.out" || fail "$1: output lacks: $2"
}

expect_match() {
  grep -qE -- "$2" "$phase_dir/$1.out" || fail "$1: no line matches: $2"
}

expect_clean() {
  if grep -qF '内部错误' "$phase_dir/$1.out"; then
    fail "$1: internal error"
  fi
}

# Everything a read-only command must leave untouched (verification plan 4).
# Excluded, because other processes change them during a test: rule counters
# (the test's own SSH traffic) and the content of the 3X-UI database, which the
# running panel writes on its own.
snapshot() {
  local out="$phase_dir/snap-$1.txt" unit tool
  {
    echo '== /etc metadata'
    find /etc -xdev -printf '%M %u:%g %p -> %l\n' | sort || true
    echo '== /etc content'
    find /etc -xdev -type f -print0 | sort -z | xargs -0 -r sha256sum |
      grep -vE '  /etc/x-ui/x-ui\.db(-wal|-shm)?$' || true
    echo '== ssh keys'
    find /root/.ssh /home -xdev -path '*/.ssh/*' -type f -print0 | sort -z | xargs -0 -r sha256sum || true
    echo '== nft'
    if command -v nft >/dev/null; then nft -s list ruleset || echo "nft exit $?"; fi
    for tool in iptables-save ip6tables-save; do
      echo "== $tool"
      if command -v "$tool" >/dev/null; then
        "$tool" | sed -E '/^#/d; s/\[[0-9]+:[0-9]+\]//' || echo "$tool exit $?"
      fi
    done
    echo '== ufw'
    if command -v ufw >/dev/null; then ufw status verbose || echo "ufw exit $?"; fi
    echo '== unit files'
    systemctl list-unit-files --no-legend --no-pager | grep -vE '\.scope[[:space:]]' || true
    echo '== unit states'
    for unit in ssh.service ssh.socket ufw.service fail2ban.service nftables.service apt-daily.timer \
      apt-daily-upgrade.timer unattended-upgrades.service x-ui.service docker.service; do
      printf '%s %s %s\n' "$unit" "$(systemctl is-enabled "$unit" 2>/dev/null || true)" \
        "$(systemctl is-active "$unit" 2>/dev/null || true)"
    done
    echo '== packages'
    dpkg-query -W -f '${Package}:${Architecture} ${Version} ${db:Status-Abbrev}\n'
    echo '== tool state'
    ls -ld /var/lib/vps-hardening 2>&1 || true
  } >"$out" 2>&1
}

same_snapshot() {
  if ! diff -u "$phase_dir/snap-$1.txt" "$phase_dir/snap-$2.txt" >"$phase_dir/snap-$1-$2.diff"; then
    cat "$phase_dir/snap-$1-$2.diff"
    fail "state changed between $1 and $2"
  fi
  log "state unchanged between $1 and $2"
}

apt_busy() {
  local locks name
  # One name per call: pgrep -x rejects patterns longer than 15 characters.
  for name in apt apt-get aptitude dpkg apt.systemd.dai; do
    pgrep -x -- "$name" >/dev/null && return 0
  done
  pgrep -f '^/usr/bin/python3 /usr/bin/unattended-upgrade( |$)' >/dev/null && return 0
  locks="$(lslocks -n -o PATH 2>/dev/null)" || locks=''
  grep -qE '^/var/(lib/dpkg/lock(-frontend)?|lib/apt/lists/lock|cache/apt/archives/lock)$' <<<"$locks"
}

# Wait for first-boot work, then keep the APT timers from starting package
# runs during a test. Stopping a timer is runtime only; it stays enabled.
settle() {
  local rc=0 deadline
  cloud-init status --wait >/dev/null 2>&1 || rc=$?
  case "$rc" in
    0 | 2) ;;
    *) fail "cloud-init status $rc" ;;
  esac
  systemctl stop apt-daily.timer apt-daily-upgrade.timer
  deadline=$((SECONDS + 1200))
  while apt_busy; do
    [ "$SECONDS" -lt "$deadline" ] || fail 'package manager still busy after 20 minutes'
    sleep 5
  done
}

# Package indexes without translations, AppStream or command-not-found data,
# which make a full update far slower under TCG emulation.
reduced_update() {
  local opts=(-o Acquire::Languages=none) target dump
  dump="$(apt-config dump)"
  for target in DEP-11 DEP-11-icons-small DEP-11-icons DEP-11-icons-hidpi CNF; do
    if grep -q "^Acquire::IndexTargets::deb::$target::MetaKey " <<<"$dump"; then
      opts+=(-o "Acquire::IndexTargets::deb::$target::DefaultEnabled=false")
    fi
  done
  log "apt-get ${opts[*]} update"
  apt-get -q "${opts[@]}" update
}

install_packages() {
  apt-get -q install -y "$@"
}

record_platform() {
  local pkg
  {
    cat /etc/os-release
    uname -a
    for pkg in openssh-server sudo ufw fail2ban nftables unattended-upgrades cloud-init systemd util-linux; do
      dpkg-query -W -f '${Package} ${Version} ${db:Status-Abbrev}\n' "$pkg" 2>/dev/null || echo "$pkg not installed"
    done
    ls -l /etc/ssh/sshd_config.d/
  } >"$phase_dir/platform.txt"
  cat "$phase_dir/platform.txt"
}

make_keys() {
  rm -rf "$KEYS"
  install -d -m 0755 "$KEYS"
  ssh-keygen -q -t ed25519 -N '' -C vh-test-ed25519 -f "$PRIVATE/ed25519"
  ssh-keygen -q -t rsa -b 3072 -N '' -C vh-test-rsa -f "$PRIVATE/rsa"
  install -m 0644 "$PRIVATE/ed25519.pub" "$KEYS/ed25519.pub"
  install -m 0644 "$PRIVATE/rsa.pub" "$KEYS/rsa.pub"
  cat "$KEYS/ed25519.pub" "$KEYS/rsa.pub" >"$KEYS/both.pub"
  printf 'command="true" %s\n' "$(cat "$KEYS/ed25519.pub")" >"$KEYS/options.pub"
  printf 'ssh-ed25519 AAAAnotakey vh-test-invalid\n' >"$KEYS/invalid.pub"
  printf '# only a comment\n\n' >"$KEYS/comments.pub"
  chmod 0644 "$KEYS"/*.pub
}

# The "typical worst-case new host" of verification plan 3.2.
check_profile() {
  local user
  user="$(default_user)"
  [ -s /root/.ssh/authorized_keys ] || fail 'profile: root has no authorized key'
  if grep -q '^[^#]*command=' /root/.ssh/authorized_keys; then
    fail 'profile: root key is restricted'
  fi
  [ "$(passwd -S root | awk '{print $2}')" = P ] || fail 'profile: root has no password'
  [ -s "/home/$user/.ssh/authorized_keys" ] || fail "profile: $user has no authorized key"
  # Already root: sudo only lists the other account's rules.
  # shellcheck disable=SC2024
  sudo -n -l -U "$user" >"$phase_dir/profile-sudo.txt"
  grep -q NOPASSWD "$phase_dir/profile-sudo.txt" || fail "profile: $user lacks password-less sudo"
  grep -qx 'PasswordAuthentication yes' /etc/ssh/sshd_config.d/50-cloud-init.conf ||
    fail 'profile: 50-cloud-init.conf does not enable passwords'
  /usr/sbin/sshd -T -C user=root,host=profile.invalid,addr=192.0.2.1 >"$phase_dir/profile-sshd.txt"
  grep -qx 'passwordauthentication yes' "$phase_dir/profile-sshd.txt" ||
    fail 'profile: sshd does not accept passwords'
  log "profile: root key and password, $user key and password-less sudo, password logins enabled"
}

phase_prepare() {
  install -d -m 0700 "$PRIVATE"
  settle
  reduced_update
  record_platform
  make_keys
}

# VT-01 and the unhardened part of VT-50.
phase_matrix() {
  local id
  settle
  check_profile

  snapshot vt01-before
  capture vt01-preflight "$VH" preflight "${GOOD_ARGS[@]}"
  snapshot vt01-after
  same_snapshot vt01-before vt01-after
  expect_rc vt01-preflight 0
  expect_clean vt01-preflight
  expect_report vt01-preflight PASS root.keys

  snapshot vt50-before
  capture vt50-verify "$VH" verify
  snapshot vt50-after
  same_snapshot vt50-before vt50-after
  expect_rc vt50-verify 1
  expect_clean vt50-verify
  for id in state ssh.passwordauthentication accounts.nopasswd f2b.installed; do
    expect_report vt50-verify FAIL "$id"
  done
  # UFW is absent from the Debian images and inactive on the Ubuntu image.
  case "$(os_id)" in
    debian) expect_report vt50-verify FAIL ufw.installed ;;
    ubuntu) expect_report vt50-verify FAIL ufw.active ;;
  esac
  # The images already default to PermitRootLogin prohibit-password.
  for id in ssh.permitrootlogin root.keys ssh.pubkey ssh.port nft.service boundary.container boundary.xui-bbr; do
    expect_report vt50-verify PASS "$id"
  done
}

hold_dpkg_lock() {
  rm -f "$PRIVATE/locked"
  python3 -c '
import fcntl, os, sys, time
fd = os.open("/var/lib/dpkg/lock-frontend", os.O_RDWR)
fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
open(sys.argv[1], "w").close()
time.sleep(300)
' "$PRIVATE/locked" &
  lock_pid=$!
  for _ in $(seq 50); do
    [ -e "$PRIVATE/locked" ] && return 0
    sleep 0.2
  done
  fail 'could not take the dpkg frontend lock'
}

release_dpkg_lock() {
  kill "$lock_pid"
  wait "$lock_pid" 2>/dev/null || true
}

# input_case NAME STATUS TEXT ARGS...
input_case() {
  local name="vt04-$1" want="$2" text="$3"
  shift 3
  capture "$name" "$VH" "$@"
  expect_rc "$name" "$want"
  [ -z "$text" ] || expect_text "$name" "$text"
  expect_clean "$name"
}

# root_keys_case NAME FILE STATUS TEXT: preflight with FILE in place of root's
# authorized_keys, visible only in a private mount namespace.
root_keys_case() {
  local name="$1"
  # shellcheck disable=SC2016
  capture "$name" unshare --mount --propagation private -- \
    sh -c 'mount --bind "$1" /root/.ssh/authorized_keys && shift && exec "$@"' sh "$2" \
    "$VH" preflight "${GOOD_ARGS[@]}"
  expect_rc "$name" "$3"
  expect_text "$name" "$4"
  expect_clean "$name"
}

# VT-02 and VT-04.
phase_negative() {
  settle
  check_profile
  snapshot negative-before

  capture vt02-nonroot-preflight runuser -u nobody -- "$VH" preflight "${GOOD_ARGS[@]}"
  expect_rc vt02-nonroot-preflight 1
  expect_report vt02-nonroot-preflight FAIL root
  capture vt02-nonroot-verify runuser -u nobody -- "$VH" verify
  expect_rc vt02-nonroot-verify 1
  expect_report vt02-nonroot-verify FAIL root
  capture vt02-nonroot-apply runuser -u nobody -- "$VH" apply "${GOOD_ARGS[@]}"
  expect_rc vt02-nonroot-apply 2

  # The fake os-release is visible only in a private mount namespace.
  printf 'PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"\nID=debian\nVERSION_ID="11"\n' >"$PRIVATE/os-release"
  # shellcheck disable=SC2016
  capture vt02-release unshare --mount --propagation private -- \
    sh -c 'mount --bind "$1" /etc/os-release && shift && exec "$@"' sh "$PRIVATE/os-release" \
    "$VH" preflight "${GOOD_ARGS[@]}"
  expect_rc vt02-release 1
  expect_report vt02-release FAIL platform
  expect_text vt02-release 'Debian GNU/Linux 11'

  root_keys_case vt02-rootkey-none "$KEYS/comments.pub" 1 'root 的 authorized_keys 中没有公钥'
  expect_report vt02-rootkey-none FAIL root.keys
  root_keys_case vt02-rootkey-options "$KEYS/options.pub" 1 'root 没有可用的公钥：1 行带选项'
  expect_report vt02-rootkey-options FAIL root.keys
  root_keys_case vt02-rootkey-invalid "$KEYS/invalid.pub" 1 'root 没有可用的公钥：1 行'
  expect_report vt02-rootkey-invalid FAIL root.keys

  hold_dpkg_lock
  capture vt02-aptlock "$VH" preflight "${GOOD_ARGS[@]}"
  release_dpkg_lock
  expect_rc vt02-aptlock 1
  expect_report vt02-aptlock FAIL apt.idle

  # A dpkg process between lock acquisitions holds no lock; its name must count.
  install -m 0755 "$(command -v sleep)" "$PRIVATE/dpkg"
  "$PRIVATE/dpkg" 300 &
  dpkg_pid=$!
  capture vt02-dpkgproc "$VH" preflight "${GOOD_ARGS[@]}"
  kill "$dpkg_pid"
  wait "$dpkg_pid" 2>/dev/null || true
  expect_rc vt02-dpkgproc 1
  expect_report vt02-dpkgproc FAIL apt.idle

  input_case panel-22 2 '面板端口不能是 22' preflight --panel-port 22
  input_case panel-zero 2 '面板端口不合法' preflight --panel-port 0
  input_case panel-high 2 '面板端口不合法' preflight --panel-port 65536
  input_case open-panel 2 '与面板端口相同' preflight --open 2053/tcp
  input_case open-22 2 '公开端口不能是 22' preflight --open 22/tcp
  input_case open-zero 2 '公开端口格式不合法' preflight --open 0/tcp
  input_case open-high 2 '公开端口超出范围' preflight --open 65536/udp
  input_case open-noproto 2 '公开端口格式不合法' preflight --open 443
  input_case open-dup 2 '公开端口重复' preflight --open 443/tcp --open 443/tcp
  # Options removed by requirements D22 and D23 must not be silently ignored.
  input_case removed-option 2 '未知参数：--maxretry' preflight --maxretry 5
  input_case timeout-2 2 '--confirm-timeout 应为' preflight --confirm-timeout 2
  input_case timeout-61 2 '--confirm-timeout 应为' preflight --confirm-timeout 61
  input_case timeout-3 0 '确认时限：3 分钟' preflight --confirm-timeout 3
  input_case timeout-60 0 '确认时限：60 分钟' preflight --confirm-timeout 60
  root_keys_case vt04-rootkey-both "$KEYS/both.pub" 0 'root 有 2 把可用的公钥'
  expect_match vt04-rootkey-both '^\[INFO\] root\.key +ssh-ed25519 SHA256:'
  expect_match vt04-rootkey-both '^\[INFO\] root\.key +ssh-rsa SHA256:'
  input_case not-tty 2 '必须在交互终端中运行' apply "${GOOD_ARGS[@]}"

  snapshot negative-after
  same_snapshot negative-before negative-after
}

# VT-03: preflight on an existing host (S1 to S4) refuses without changes.
existing_host_case() {
  local name="vt03-$1"
  settle
  snapshot "$1-before"
  capture "$name" "$VH" preflight "${GOOD_ARGS[@]}"
  snapshot "$1-after"
  same_snapshot "$1-before" "$1-after"
  expect_rc "$name" 1
  expect_report "$name" FAIL "$2"
  expect_text "$name" '存量主机不在支持范围内'
  expect_clean "$name"
}

# S1: 3X-UI v3.7.0 installed the way vps-proxy-setup will (verification plan 3.5).
phase_s1() {
  local dir="$BUNDLE/fixtures/3x-ui" rc=0
  settle
  printf '%s  %s\n%s  %s\n' "$XUI_INSTALL_SHA256" "$dir/install.sh" "$XUI_SCRIPT_SHA256" "$dir/x-ui.sh" |
    sha256sum -c -
  XUI_NONINTERACTIVE=1 XUI_SSL_MODE=none XUI_ENABLE_FAIL2BAN=false XUI_PANEL_PORT=2053 \
    bash "$dir/install.sh" v3.7.0 </dev/null >"$PRIVATE/xui-install.log" 2>&1 || rc=$?
  # Lines that could carry the generated panel credentials stay private.
  grep -viE 'user|pass|token|path|url|http' "$PRIVATE/xui-install.log" | tail -n 40 >"$phase_dir/xui-install-tail.log" || true
  [ "$rc" -eq 0 ] || {
    cat "$phase_dir/xui-install-tail.log"
    fail "3X-UI install.sh exit $rc"
  }
  install -m 0755 "$dir/x-ui.sh" /usr/bin/x-ui
  /usr/local/x-ui/x-ui setting -listenIP 127.0.0.1 >/dev/null
  systemctl restart x-ui
  for _ in $(seq 30); do
    ss -H -ltn 'sport = :2053' | grep -q '127.0.0.1:2053' && break
    sleep 1
  done
  ss -H -ltn 'sport = :2053' | tee "$phase_dir/xui-listen.txt"
  grep -q '127.0.0.1:2053' "$phase_dir/xui-listen.txt" || fail '3X-UI panel is not on 127.0.0.1:2053'
  log "3X-UI fixture ready: $(systemctl is-active x-ui)"
  existing_host_case s1 new-host.xui
}

# Listeners for the UFW path check run by tests/vm.py around S2.
phase_s2_listen() {
  local port
  settle
  install -d -m 0755 /root/vh-www
  printf 'ok\n' >/root/vh-www/index.html
  for port in 8080 2096; do
    systemd-run --unit "vh-http-$port" python3 -m http.server --bind 0.0.0.0 --directory /root/vh-www "$port"
  done
  for _ in $(seq 30); do
    if ss -H -ltn 'sport = :8080' | grep -q . && ss -H -ltn 'sport = :2096' | grep -q .; then
      log 'listeners on 8080 and 2096'
      return 0
    fi
    sleep 1
  done
  fail 'test listeners did not start'
}

# S2: UFW enabled with a custom rule (8080) besides SSH.
phase_s2() {
  settle
  command -v ufw >/dev/null || install_packages --no-install-recommends ufw
  ufw allow 22/tcp
  ufw allow 8080/tcp
  ufw --force enable
  existing_host_case s2 new-host.ufw
}

# S3: a custom jail in jail.d.
phase_s3() {
  settle
  install_packages fail2ban
  printf '[recidive]\nenabled = true\n' >/etc/fail2ban/jail.d/custom.conf
  systemctl restart fail2ban || log "fail2ban restart failed: $(systemctl is-active fail2ban || true)"
  existing_host_case s3 new-host.fail2ban
}

# S4: the distribution's docker.io.
phase_s4() {
  settle
  install_packages --no-install-recommends docker.io
  existing_host_case s4 new-host.container
}

main() {
  local phase="${1-}"
  [ "$(id -u)" -eq 0 ] || fail 'run as root'
  phase_dir="$EVIDENCE/$phase"
  install -d -m 0700 "$EVIDENCE" "$PRIVATE"
  rm -rf "$phase_dir"
  install -d -m 0700 "$phase_dir"
  case "$phase" in
    prepare) phase_prepare ;;
    matrix) phase_matrix ;;
    negative) phase_negative ;;
    s1) phase_s1 ;;
    s2-listen) phase_s2_listen ;;
    s2) phase_s2 ;;
    s3) phase_s3 ;;
    s4) phase_s4 ;;
    *) fail "unknown phase: $phase" ;;
  esac
  log "phase $phase passed"
}

main "$@"
