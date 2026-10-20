#!/usr/bin/env bash
# Throwaway M2 research (DR-11, DR-4, ufw rule format). Not for merge.
set -uo pipefail
PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
export PATH LC_ALL=C

session() {
  local pid=$$ chain=''
  while [ "$pid" -gt 1 ]; do
    chain="$chain $(awk '/^Name:/{print $2}' /proc/$pid/status)[$pid]"
    pid=$(awk '/^PPid:/{print $2}' /proc/$pid/status)
  done
  printf 'uid=%s loginuid=%s sessionid=%s xdg=%s\n' "$(id -u)" "$(cat /proc/$$/loginuid)" "$(cat /proc/$$/sessionid)" "${XDG_SESSION_ID-unset}"
  printf 'chain=%s\n' "$chain"
  loginctl show-session "$(cat /proc/$$/sessionid)" -p Id -p Service -p Remote -p Class -p Type -p Leader -p Name 2>&1 | paste -sd' '
  grep -H loginuid /etc/pam.d/sshd /etc/pam.d/login 2>&1 || true
}

reload_study() {
  echo "== units"
  systemctl is-active ssh.service ssh.socket 2>&1 | paste -sd' '
  systemctl is-enabled ssh.service ssh.socket 2>&1 | paste -sd' '
  systemctl show ssh.service -p MainPID -p ExecReload -p KillMode 2>&1
  echo "== before"
  ssh -o BatchMode=yes -o PreferredAuthentications=none -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1 true 2>&1 | tail -1
  printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' >/etc/ssh/sshd_config.d/00-research.conf
  sshd -t && echo sshd-t-ok
  systemctl try-reload-or-restart ssh.service; echo "reload rc=$?"
  sleep 2
  systemctl show ssh.service -p MainPID 2>&1
  echo "== after"
  ssh -o BatchMode=yes -o PreferredAuthentications=none -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1 true 2>&1 | tail -1
  rm -f /etc/ssh/sshd_config.d/00-research.conf
  systemctl try-reload-or-restart ssh.service; echo "reload back rc=$?"
}

ufw_study() {
  command -v ufw >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get -q install -y --no-install-recommends ufw >/dev/null 2>&1
  ufw --version | head -1
  ufw allow 22/tcp comment 'vh ssh'
  ufw allow 443/tcp comment 'vh both'
  ufw allow proto udp to 0.0.0.0/0 port 8443 comment 'vh v4'
  ufw allow proto tcp to ::/0 port 2096 comment 'vh v6'
  echo "== show added"; ufw show added
  ufw default deny incoming; ufw default allow outgoing; ufw default deny routed
  echo "== status verbose (inactive)"; ufw status verbose
  systemctl is-enabled ufw.service; grep -E '^(ENABLED|IPV6)=' /etc/ufw/ufw.conf /etc/default/ufw
  ufw --force enable
  echo "== status verbose"; ufw status verbose
  systemctl is-enabled ufw.service; systemctl is-active ufw.service
  ufw --force disable; echo "disable rc=$?"
  grep -E '^ENABLED=' /etc/ufw/ufw.conf
}

timer_study() {
  systemd-run --unit vh-research-timeout --on-active=3 --timer-property=AccuracySec=1s -- /bin/sh -c 'echo fired >/run/vh-research-fired'
  systemctl list-timers --all --no-legend 'vh-research*' 2>&1
  sleep 6
  cat /run/vh-research-fired 2>&1
  systemctl show vh-research-timeout.timer -p LoadState -p ActiveState 2>&1 | paste -sd' '
  systemctl show vh-research-timeout.service -p LoadState -p ActiveState -p Result 2>&1 | paste -sd' '
  systemd-run --unit vh-research-timeout --on-active=3 -- /bin/true; echo "rerun same name rc=$?"
}

case "${1-}" in
  session) session ;;
  reload) reload_study ;;
  ufw) ufw_study ;;
  timer) timer_study ;;
esac
