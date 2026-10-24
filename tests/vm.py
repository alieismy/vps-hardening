#!/usr/bin/env python3
"""VM tests: run the tool in disposable QEMU guests.

Adapted from vps-tuning's tests/platform-vm.py. Suites:

  matrix    one guest: VT-01, the unhardened part of VT-50, the guest-side
            source address of forwarded connections and the sshd probe study
            for VO-2 (docs/verification-plan.md 3.3); then the M2 lifecycle:
            apply, refused and accepted confirmations, reboot (VT-10 to
            VT-15, VT-21, VT-24, VT-25, VT-62, VT-70, VT-71).
  recovery  overlays of one prepared guest: restore on timeout (VT-20,
            VT-21) and on reboot while pending (VT-22), with VT-25.
  negative  a prepared guest for VT-02 and VT-04, then one overlay disk per
            existing-host case S1-S4 (VT-03), plus the UFW path check in S2,
            and the failed apply of VT-23.
  hardened  one guest, hardened and confirmed: Fail2ban (VT-30 to VT-35),
            automatic updates (VT-40), then 3X-UI v3.10.2 (VT-55, VT-50,
            VT-71); then one overlay of it per drift (VT-51), and one each
            for rollback with 3X-UI (VT-61), port changes (VT-63) and apply
            on the applied host (VT-64).

The matrix flow ends with status and the rollback command (VT-60); the
negative suite also applies again after VT-23 (VT-64) and checks the release
installer on an overlay of its own (VT-72, local part).
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shlex
import socket
import subprocess
import tarfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / '.tmp/vm'
SSH_PORT = 2222
# Runner port -> guest port (verification plan 3.3).
FORWARDS = {SSH_PORT: 22, 12053: 2053, 10443: 443, 12096: 2096, 10080: 80, 18080: 8080}
XUI_COMMIT = '608ef4e4010bf83e2e78328e08f77efc051ad4d7'  # tag v3.10.2
# install.sh fetches x-ui.sh from the same tag; tests/guest/m1.sh checks it.
XUI_FILES = {
    'install.sh': '9684bae4f769b2127fcceceb4f200045657381311867529e6ba76c6b58e2825d',
}
VH = '/opt/vh-bundle/bin/vps-hardening'
# Ports opened in the lifecycle flow; tests/guest/m2.sh lists the UFW rules they give.
LIFECYCLE_OPEN = '--open 443/tcp --open 2096/tcp/ipv6 --open 8443/udp/ipv4'
# Ports of the hardened suite: the inbound and subscription ports of 3X-UI. They
# are added with ports once 3X-UI is installed (requirement D41); VT-64 applies
# again with them.
HARDENED_OPEN = '--open 443/tcp --open 2096/tcp'
# VT-51, one overlay each; tests/guest/m3.sh injects them.
DRIFTS = ('firewall-install', 'firewall-reinstall', 'iplimit', 'listen-all', 'bbr', 'ufw-rule', 'nftables',
          'sshd-dropin', 'sshd-match', 'ufw-framework', 'ufw-userrules', 'reboot-required')
APPLY_PROMPT = '两项都满足请输入 yes'.encode()
APPLIED = '加固已应用，等待确认'
PORTS_CHANGED = '端口变更已生效，等待确认'
# Key logins at least 2 s apart do not trigger Debian 13's penalties (VO-2).
PROBE_INTERVAL = 3
# Guest port -> runner port of the forwards above, for the reachability checks.
HTTP_PORTS = {443: 10443, 2096: 12096, 2053: 12053, 8080: 18080, 80: 10080}


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, **kwargs)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class Timings:
    def __init__(self, path):
        self.path = path
        self.items = {}

    def measure(self, name, func, *args):
        start = time.monotonic()
        try:
            return func(*args)
        finally:
            self.items[name] = round(time.monotonic() - start, 1)
            self.path.write_text(json.dumps(self.items, indent=2))
            print(f'TIME {name} {self.items[name]}s', flush=True)


class Guest:
    """One boot of a guest disk, with the seed attached and ports forwarded."""

    def __init__(self, ctx, label, disk):
        self.ctx = ctx
        self.label = label
        self.disk = disk
        self.evidence = ctx.evidence / label
        self.evidence.mkdir()
        self.vm = None
        self.serial = None

    def __enter__(self):
        ctx = self.ctx
        fwd = ','.join(f'hostfwd=tcp:127.0.0.1:{host}-:{guest}' for host, guest in FORWARDS.items())
        qemu = ['qemu-system-' + ('x86_64' if ctx.arch == 'amd64' else 'aarch64'),
                '-accel', 'kvm' if ctx.kvm else 'tcg', '-cpu', ctx.cpu]
        if ctx.arch == 'arm64':
            qemu += ['-machine', 'virt', '-bios', '/usr/share/qemu-efi-aarch64/QEMU_EFI.fd']
        qemu += ['-smp', str(ctx.vcpus), '-m', str(ctx.ram_mib), '-nographic',
                 '-drive', f'file={self.disk},if=virtio,format=qcow2',
                 '-drive', f'file={ctx.work / "seed.img"},if=virtio,format=raw',
                 '-nic', 'user,model=virtio-net-pci,' + fwd]
        self.serial = (self.evidence / 'serial.log').open('wb')
        self.vm = subprocess.Popen(qemu, stdout=self.serial, stderr=subprocess.STDOUT)
        return self

    def __exit__(self, *exc):
        try:
            if self.vm.poll() is None:
                self.collect()
        finally:
            if self.vm.poll() is None:
                self.vm.terminate()
                try:
                    self.vm.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    self.vm.kill()
                    self.vm.wait()
            self.serial.close()
        return False

    def ssh(self, command, **kwargs):
        return subprocess.run(self.ctx.ssh + [command], **kwargs)

    def login_ok(self, user='root'):
        return self.login_error(user) is None

    def login_error(self, user='root'):
        """None when a login as USER works, otherwise why it failed."""
        try:
            result = subprocess.run(self.ctx.ssh_as(user) + ['true'], stdout=subprocess.DEVNULL,
                                    stderr=subprocess.PIPE, timeout=60)
        except subprocess.TimeoutExpired:
            return 'no answer within 60 s'
        if result.returncode == 0:
            return None
        return result.stderr.decode(errors='replace').strip() or f'exit status {result.returncode}'

    def must_login(self, user, when):
        """VT-25: a real login with the identity that must work at this point."""
        if not self.login_ok(user):
            raise RuntimeError(f'{user} cannot log in {when}')
        print('PASS login as', user, when, flush=True)

    def wait(self, command='true', timeout=1800):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.vm.poll() is not None:
                raise RuntimeError(f'QEMU exited; see {self.label}/serial.log')
            try:
                result = self.ssh(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
            except subprocess.TimeoutExpired:
                continue
            if b'REMOTE HOST IDENTIFICATION HAS CHANGED' in result.stderr:
                raise RuntimeError('guest host key mismatch')
            if result.returncode == 0:
                return result.stdout.decode().strip()
            time.sleep(5)
        raise TimeoutError(f'guest {self.label} not ready; see serial.log')

    def ready(self):
        self.ctx.timings.measure(f'{self.label}.ready', self.wait, 'test -f /root/vh-cloud-ready')

    def boot_id(self):
        return self.wait('cat /proc/sys/kernel/random/boot_id')

    def wait_boot(self, old_boot_id):
        """Wait until the guest is back with a new boot ID."""
        deadline = time.monotonic() + 1800
        while self.boot_id() == old_boot_id:
            if time.monotonic() > deadline:
                raise TimeoutError(f'guest {self.label} did not reboot')
            time.sleep(5)

    def reboot(self):
        old = self.boot_id()
        self.ssh('systemctl reboot', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        self.ctx.timings.measure(f'{self.label}.reboot', self.wait_boot, old)

    def tool_status(self):
        return self.wait("awk -F= '$1 == \"status\" { print $2 }' /var/lib/vps-hardening/state")

    def wait_status(self, want, timeout):
        deadline = time.monotonic() + timeout
        while (status := self.tool_status()) != want:
            if time.monotonic() > deadline:
                raise TimeoutError(f'tool status is {status}, expected {want}')
            time.sleep(10)

    def upload(self, bundle):
        with bundle.open('rb') as f:
            run(self.ctx.ssh + ['rm -rf /opt/vh-bundle && install -d -m 0755 /opt/vh-bundle && '
                                'tar --no-same-owner -xf - -C /opt/vh-bundle'], stdin=f, timeout=120)

    def phase(self, name, *args, script='m1.sh', timeout=1800):
        words = (name,) + args
        title = ' '.join(words)
        print('START', self.label, title, flush=True)
        log_path = self.evidence / ('-'.join(words) + '.log')
        command = f'bash /opt/vh-bundle/tests/guest/{script} {title}'

        def body():
            with log_path.open('wb') as log:
                run(self.ctx.ssh + [command], stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        try:
            self.ctx.timings.measure(f'{self.label}.{title}', body)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            print(log_path.read_text(errors='replace'), flush=True)
            raise
        print('PASS', self.label, title, flush=True)

    def command(self, name, command, user='root', timeout=600):
        """Run one command in a new session; keep its output as evidence."""
        result = subprocess.run(self.ctx.ssh_as(user) + [command], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout)
        output = result.stdout.decode(errors='replace')
        (self.evidence / f'{name}.log').write_text(output)
        print(f'--- {self.label} {name}: exit {result.returncode}\n{output}', flush=True)
        return result.returncode, output

    def interactive(self, name, command, on_text=None, timeout=1800):
        """Run COMMAND on a pseudo-terminal in a new root session and type
        "yes" when apply asks for it, as the administrator would. ON_TEXT maps
        output text to a function called once when the text appears."""
        log_path = self.evidence / f'{name}.log'
        proc = subprocess.Popen(self.ctx.ssh_as('root', tty=True) + [command], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        watchdog = threading.Timer(timeout, proc.kill)
        watchdog.start()
        output = bytearray()
        waiting = dict(on_text or {})
        answered = False
        try:
            with log_path.open('wb') as log:
                while chunk := proc.stdout.read1(4096):
                    log.write(chunk)
                    log.flush()
                    output += chunk
                    if not answered and APPLY_PROMPT in output:
                        proc.stdin.write(b'yes\n')
                        proc.stdin.flush()
                        answered = True
                    for text in [t for t in waiting if t.encode() in output]:
                        waiting.pop(text)()
            proc.wait()
        finally:
            watchdog.cancel()
            try:
                proc.stdin.close()
            except OSError:
                pass
        text = output.decode(errors='replace')
        print(f'--- {self.label} {name}: exit {proc.returncode}\n{text}', flush=True)
        return proc.returncode, text

    def collect(self):
        try:
            with (self.evidence / 'guest-evidence.tar').open('wb') as f:
                subprocess.run(self.ctx.ssh + ['tar -cf - -C /root vh-evidence'], stdout=f,
                               stderr=subprocess.DEVNULL, timeout=60)
        except subprocess.TimeoutExpired:
            pass

    def poweroff(self):
        self.collect()
        self.ssh('systemctl poweroff', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        self.vm.wait(timeout=600)


class Context:
    def __init__(self, args):
        self.platform = args.platform
        self.arch = args.arch
        self.work = WORK
        self.work.mkdir(parents=True, exist_ok=False)
        os.chmod(self.work, 0o700)
        self.evidence = self.work / 'evidence'
        self.evidence.mkdir()
        self.timings = Timings(self.evidence / 'timings.json')
        self.kvm = os.access('/dev/kvm', os.R_OK | os.W_OK)
        self.cpu = 'host' if self.kvm else ('max' if self.arch == 'arm64' else 'qemu64')
        if not self.kvm and self.platform == 'ubuntu2404' and self.arch == 'arm64':
            # As in vps-tuning: Ubuntu's PAC instructions are too slow under the
            # default TCG QARMA5 implementation; use QEMU's faster one.
            self.cpu = 'max,pauth-impdef=on'
        self.vcpus, self.ram_mib = (2, 2048) if self.kvm else (2, 1536)
        (self.evidence / 'hypervisor.json').write_text(json.dumps({
            'platform': self.platform, 'arch': self.arch, 'acceleration': 'kvm' if self.kvm else 'tcg',
            'cpu': self.cpu, 'vcpus': self.vcpus, 'ram_mib': self.ram_mib}, indent=2))
        self.password = secrets.token_urlsafe(18)
        self.user = 'ubuntu' if self.platform.startswith('ubuntu') else 'debian'
        self.ssh_opts = []
        self.ssh = []
        # Other values that must not appear in the evidence (the panel's WebBasePath).
        self.private = []

    def image(self):
        spec = json.loads((ROOT / 'tests/platform-images.json').read_text())[self.platform][self.arch]
        (self.evidence / 'image.json').write_text(json.dumps(spec, indent=2))
        image = self.work / 'base.qcow2'
        urllib.request.urlretrieve(spec['url'], image)
        with image.open('rb') as f:
            digest = hashlib.file_digest(f, spec['algorithm']).hexdigest()
        if digest != spec['digest']:
            raise RuntimeError('official image checksum mismatch')
        return image

    def overlay(self, backing, name):
        disk = self.work / name
        run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', str(backing), str(disk), '12G'])
        return disk

    def seed(self):
        for name in ('client', 'host'):
            run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', f'vh-{name}', '-f', str(self.work / name)])
        # The "typical worst-case new host" of verification plan 3.2, written
        # explicitly instead of relying on image defaults.
        user_data = {
            'disable_root': False,
            'ssh_authorized_keys': [(self.work / 'client.pub').read_text().strip()],
            'ssh_keys': {'ed25519_private': (self.work / 'host').read_text(),
                         'ed25519_public': (self.work / 'host.pub').read_text().strip()},
            'write_files': [{'path': '/etc/ssh/sshd_config.d/50-cloud-init.conf', 'permissions': '0600',
                             'content': 'PasswordAuthentication yes\n'},
                            # For the guest side of the password logins (VT-13); never archived.
                            {'path': '/root/vh-private/password', 'permissions': '0600',
                             'content': self.password}],
            # The default user gets the same password, so that VT-13 shows its
            # password login working before apply and failing after.
            'runcmd': [['sh', '-c', 'u=$(id -nu 1000) && printf "root:%s\\n%s:%s\\n" "$1" "$u" "$1" | chpasswd',
                        'sh', self.password],
                       ['touch', '/root/vh-cloud-ready']],
        }
        (self.work / 'user-data').write_text('#cloud-config\n' + json.dumps(user_data))
        (self.work / 'meta-data').write_text('instance-id: vh-m1\nlocal-hostname: vh-ci\n')
        run(['cloud-localds', str(self.work / 'seed.img'), str(self.work / 'user-data'), str(self.work / 'meta-data')])
        (self.work / 'known-hosts').write_text(f'[127.0.0.1]:{SSH_PORT} ' + (self.work / 'host.pub').read_text())
        # Shared by the tool's own tunnel command in VT-15, which brings its key options.
        self.ssh_opts = ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                         '-o', 'UserKnownHostsFile=' + str(self.work / 'known-hosts'),
                         '-o', 'ConnectTimeout=5', '-o', 'LogLevel=ERROR', '-p', str(SSH_PORT)]
        self.ssh = self.ssh_as('root')

    def ssh_as(self, user, tty=False):
        return (['ssh', '-i', str(self.work / 'client'), '-o', 'IdentitiesOnly=yes'] + self.ssh_opts +
                (['-tt'] if tty else []) + [f'{user}@127.0.0.1'])

    def bundle(self, with_xui):
        """Tool, guest tests and (for S1) the verified 3X-UI fixture files."""
        path = self.work / 'bundle.tar'
        files = sorted([ROOT / 'install.sh'] + [
            p for d in ('bin', 'lib', 'tests/guest') for p in (ROOT / d).rglob('*') if p.is_file()])
        with tarfile.open(path, 'w') as tar:
            def add(name, data, mode):
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(data), mode, int(time.time())
                tar.addfile(info, io.BytesIO(data))
            dirs = set()
            for p in files:
                rel = p.relative_to(ROOT).as_posix()
                for parent in Path(rel).parents:
                    if str(parent) != '.':
                        dirs.add(parent.as_posix())
            for d in sorted(dirs) + (['fixtures', 'fixtures/3x-ui'] if with_xui else []):
                info = tarfile.TarInfo(d)
                info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, int(time.time())
                tar.addfile(info)
            for p in files:
                rel = p.relative_to(ROOT).as_posix()
                add(rel, p.read_bytes(), 0o755 if rel.startswith('bin/') or rel.endswith('.sh') else 0o644)
            if with_xui:
                for name, digest in XUI_FILES.items():
                    url = f'https://raw.githubusercontent.com/MHSanaei/3x-ui/{XUI_COMMIT}/{name}'
                    with urllib.request.urlopen(url, timeout=60) as response:
                        data = response.read()
                    if sha256(data) != digest:
                        raise RuntimeError(f'3X-UI {name} checksum mismatch')
                    add(f'fixtures/3x-ui/{name}', data, 0o644)
        return path

    def leak_scan(self):
        """No test password or client private key in any tool or guest output (VT-12, VT-50)."""
        needles = [self.password.encode()] + [
            line.encode() for line in (self.work / 'client').read_text().splitlines()
            if line and not line.startswith('-----')] + [value.encode() for value in self.private]
        for path in self.evidence.rglob('*'):
            if path.is_file() and path.name != 'serial.log':
                data = path.read_bytes()
                if any(needle in data for needle in needles):
                    raise RuntimeError(f'test secret found in {path.relative_to(self.evidence)}')


def ssh_banner(timeout=5):
    """Connect to the forwarded SSH port, read the banner, close without authenticating."""
    try:
        with socket.create_connection(('127.0.0.1', SSH_PORT), timeout=timeout) as s:
            s.settimeout(timeout)
            return s.recv(64).startswith(b'SSH-')
    except OSError:
        return False


def http_reachable(port, timeout=5):
    # QEMU accepts on the runner side first, so only a reply proves the guest answered.
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b'GET / HTTP/1.0\r\nHost: vh-test\r\n\r\n')
            return s.recv(64).startswith(b'HTTP/')
    except OSError:
        return False


def http_get(port, path, timeout=5):
    """Status code and body PATH returns from a server on the runner-side PORT,
    or (None, b''). A server that keeps the connection open is read until the timeout."""
    data = b''
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(f'GET {path} HTTP/1.0\r\nHost: vh-test\r\n\r\n'.encode())
            while len(data) < 1 << 20 and (chunk := s.recv(65536)):
                data += chunk
    except OSError:
        if not data:
            return None, b''
    head, _, body = data.partition(b'\r\n\r\n')
    words = head.split(b'\r\n')[0].split()
    try:
        return (int(words[1]) if len(words) > 1 and words[0].startswith(b'HTTP/') else None), body
    except ValueError:
        return None, b''


def forwarded_ports():
    """Which guest HTTP listeners answer through the QEMU forwards (VT-14)."""
    return {str(port): http_reachable(host) for port, host in HTTP_PORTS.items()}


def check(condition, message):
    if not condition:
        raise RuntimeError(message)
    print('PASS', message, flush=True)


class Probe:
    """VT-25: a root key login every PROBE_INTERVAL seconds for a whole flow.

    A probe that fails is retried once a second later: on Debian 12 a new
    connection is reset while sshd re-executes itself on reload, which is not
    an interruption of the login path. Retries are counted in the evidence,
    with the error of the first attempt. Failures are allowed only in declared
    outage windows (reboots).
    """

    def __init__(self, guest, name):
        self.guest = guest
        self.name = name
        self.records = []
        self.windows = []
        self.stopped = threading.Event()
        self.start = time.monotonic()
        # Offsets in the records count from here; the tool's log uses UTC.
        self.started_utc = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        self.thread = threading.Thread(target=self.run, daemon=True)

    def now(self):
        return round(time.monotonic() - self.start, 1)

    def run(self):
        while not self.stopped.is_set():
            began = self.now()
            error = self.guest.login_error()
            ok = error is None or (time.sleep(1) is None and self.guest.login_ok())
            self.records.append({'from': began, 'to': self.now(), 'ok': ok, 'retried': error is not None,
                                 'error': error})
            self.stopped.wait(PROBE_INTERVAL)

    def outage(self, reason):
        self.windows.append({'reason': reason, 'from': self.now(), 'to': None})

    def outage_over(self):
        self.windows[-1]['to'] = self.now()

    def expected(self, record):
        return any(w['from'] <= record['to'] and (w['to'] is None or record['from'] <= w['to'])
                   for w in self.windows)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, *exc):
        self.stopped.set()
        self.thread.join()
        failures = [r for r in self.records if not r['ok'] and not self.expected(r)]
        result = {'started_utc': self.started_utc, 'interval_s': PROBE_INTERVAL, 'probes': len(self.records),
                  'retried': sum(r['retried'] for r in self.records), 'outages': self.windows,
                  'unexpected_failures': failures, 'records': self.records}
        (self.guest.evidence / f'probe-{self.name}.json').write_text(json.dumps(result, indent=2))
        print(f'probe {self.name}: {result["probes"]} probes, {result["retried"]} retried, '
              f'{len(failures)} unexpected failures, outages {self.windows}', flush=True)
        if exc_type is None and failures:
            raise RuntimeError(f'VT-25: logins failed outside the outage windows: {failures}')
        return False


class UserSession:
    """VT-24: a session of the image's default user, opened before apply and
    kept open, that later tries confirm through sudo."""

    TRIGGER = '/run/vh-user-confirm'

    def __init__(self, ctx, guest):
        self.guest = guest
        self.log_path = guest.evidence / 'vt24-user-session.log'
        script = (f'cat /proc/self/sessionid >/tmp/vh-user-session && '
                  f'while [ ! -e {self.TRIGGER} ]; do sleep 1; done; '
                  f'sudo -n {VH} confirm; echo "confirm-rc=$?"')
        with self.log_path.open('wb') as log:
            self.proc = subprocess.Popen(ctx.ssh_as(ctx.user, tty=True) + [script], stdin=subprocess.PIPE,
                                         stdout=log, stderr=subprocess.STDOUT)
        guest.wait('test -s /tmp/vh-user-session', timeout=300)

    def confirm(self):
        self.guest.wait(f'touch {self.TRIGGER}')
        self.proc.wait(timeout=300)
        self.proc.stdin.close()
        output = self.log_path.read_text(errors='replace')
        print(f'--- {self.guest.label} vt24-user-session: exit {self.proc.returncode}\n{output}', flush=True)
        return output


def tunnel(ctx, template, path='/', name='tunnel'):
    """VT-15 and VT-55: the tunnel command the tool printed, with only its
    placeholders filled in, plus the test's host key and port options.
    Returns the status and body PATH gives through the tunnel; the evidence
    does not name the path."""
    command = (template.replace('<私钥>', str(ctx.work / 'client'))
               .replace('root@<VPS 地址>', 'root@127.0.0.1'))
    argv = shlex.split(command)
    check(argv[:2] == ['ssh', '-N'] and argv[-1] == 'root@127.0.0.1', f'tunnel template: {template}')
    argv = argv[:1] + ctx.ssh_opts + argv[1:]
    result = {'template': template, 'without_tunnel': http_get(8443, path)[0]}
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        status, body = None, b''
        for _ in range(60):
            if proc.poll() is not None:
                break
            status, body = http_get(8443, path)
            if status is not None:
                break
            time.sleep(1)
        result['with_tunnel'] = status
    finally:
        proc.terminate()
        _, err = proc.communicate(timeout=30)
        result['ssh_stderr'] = err.decode(errors='replace')
    (ctx.evidence / f'{name}.json').write_text(json.dumps(result, indent=2))
    check(result['without_tunnel'] is None, f'{name}: nothing on local port 8443 without the tunnel')
    return status, body


def lifecycle(ctx, guest):
    """The main flow (scenario A of design 7.5) on the matrix guest."""
    def m2(name, *args):
        guest.phase(name, *args, script='m2.sh')

    m2('m2-prepare')
    m2('m2-baseline')
    m2('m2-listen', '443', '2096', '2053', '8080', '80')
    m2('m2-before')
    result = {'ports_before': forwarded_ports()}
    check(all(result['ports_before'].values()), 'every test port answers before apply (control)')
    with Probe(guest, 'lifecycle') as probe:
        session = UserSession(ctx, guest)
        # VT-24 case 1: confirm in the session that ran apply.
        status, output = guest.interactive(
            'vt10-apply', f'{VH} apply {LIFECYCLE_OPEN}; echo "apply-rc=$?"; {VH} confirm; echo "confirm-rc=$?"')
        check('apply-rc=0' in output and APPLIED in output, 'VT-10: apply finished and awaits confirmation')
        check('confirm-rc=1' in output and '这是执行 apply 的会话' in output,
              'VT-24: confirm in the session that ran apply is refused')
        template = next(line.strip() for line in output.splitlines() if line.strip().startswith('ssh -N -L'))
        guest.must_login('root', 'while pending')
        # VT-24 case 2: the default user's session from before apply, through sudo.
        output = session.confirm()
        check('confirm-rc=1' in output and '确认必须在以 root 登录的会话中执行' in output,
              'VT-24: confirm through sudo from the default user is refused')
        guest.phase('m2-pending', script='m2.sh')
        status, output = guest.command('vt60-status-pending', f'{VH} status')
        check(status == 0 and '状态：待确认' in output and '确认截止' in output,
              'FR-13: status shows the pending change and its deadline')
        # VT-10 and VT-21: confirm from a new root session after the apply session closed.
        status, output = guest.command('vt10-confirm', f'{VH} confirm')
        check(status == 0 and '已确认' in output, 'VT-10: confirm from a new root session, then verify passes')
        guest.must_login('root', 'after confirm')
        # VT-24 case 3: nothing left to confirm.
        status, output = guest.command('vt24-confirm-again', f'{VH} confirm')
        check(status == 1 and '当前没有待确认的变更' in output, 'VT-24: confirm with nothing pending is refused')
        m2('m2-applied')
        status, output = guest.command('vt60-status-applied', f'{VH} status')
        check(status == 0 and '状态：已应用' in output and '受管文件' in output and 'ssh -N -L' in output,
              'FR-13: status shows the record, the managed files and the tunnel command')
        result['ports_after'] = forwarded_ports()
        check(result['ports_after'] == {'443': True, '2096': False, '2053': False, '8080': False, '80': False},
              f'VT-14: through the forwards only 443 answers: {result["ports_after"]}')
        m2('m2-panel-loopback')
        status, _ = tunnel(ctx, template)
        check(status == 200, 'VT-15: the panel answers 200 through the tunnel')
        probe.outage('reboot')
        guest.reboot()
        probe.outage_over()
        guest.must_login('root', 'after the reboot')
        m2('m2-rebooted')
        # VT-60: the rollback command after apply, confirm and a reboot.
        status, output = guest.command('vt60-rollback-no-tty', f'{VH} rollback')
        check(status == 2 and '必须在交互终端中运行' in output, 'VT-60: rollback without a terminal is refused')
        status, output = guest.interactive('vt60-rollback', f'{VH} rollback; echo "rollback-rc=$?"')
        check('rollback-rc=0' in output and '已恢复到应用前的配置' in output and '软件包保留' in output,
              'VT-60: rollback restored the configuration and lists the kept packages')
        check('[WARN] rollback.password' in output, 'VT-60: rollback warned that password logins come back')
        guest.must_login('root', 'after the rollback')
        guest.must_login(ctx.user, 'after the rollback')
        m2('m2-rolled-back', 'manual')
        status, output = guest.command('vt60-status-rolled-back', f'{VH} status')
        check(status == 0 and '状态：已回滚' in output and '手工回滚' in output, 'FR-13: status shows the rollback')
        status, output = guest.interactive('vt60-rollback-again', f'{VH} rollback; echo "rollback-rc=$?"')
        check('rollback-rc=1' in output and '已经回滚' in output, 'VT-60: a second rollback is refused')
    (ctx.evidence / 'lifecycle.json').write_text(json.dumps(result, indent=2))


def source_address(ctx, guest):
    """Address the guest sees for a forwarded connection (verification plan 3.3)."""
    line = guest.wait('printf "%s" "$SSH_CONNECTION"')
    source = line.split()[0]
    result = {'ssh_connection': line, 'source': source,
              'loopback': source in ('127.0.0.1', '::1') or source.startswith('127.')}
    (ctx.evidence / 'source-address.json').write_text(json.dumps(result, indent=2))
    if result['loopback']:
        raise RuntimeError(f'forwarded connections arrive from loopback ({source})')
    print('PASS source address of forwarded connections:', source, flush=True)


def probe_study(ctx, guest):
    """VO-2: which reachability probes trigger sshd's PerSourcePenalties."""
    since = guest.wait('date +%s')
    result = {}

    def raw(count, interval):
        seen = 0
        for _ in range(count):
            seen += ssh_banner()
            time.sleep(interval)
        return seen

    def recovery(limit=600):
        start = time.monotonic()
        while time.monotonic() - start < limit:
            if guest.login_ok():
                return round(time.monotonic() - start, 1)
            time.sleep(5)
        return None

    result['burst'] = {'connections': 30, 'interval_s': 0.1, 'banners': raw(30, 0.1)}
    result['burst']['login_right_after'] = guest.login_ok()
    result['burst']['recovery_s'] = recovery()
    time.sleep(20)
    result['slow'] = {'connections': 20, 'interval_s': 2, 'banners': raw(20, 2)}
    result['slow']['login_right_after'] = guest.login_ok()
    result['slow']['recovery_s'] = recovery()
    logins = 0
    for _ in range(10):
        logins += guest.login_ok()
        time.sleep(0.5)
    result['key_logins'] = {'logins': 10, 'interval_s': 0.5, 'succeeded': logins}
    guest.wait(timeout=900)
    result['sshd_version'] = guest.wait("dpkg-query -W -f '${Version}' openssh-server")
    result['sshd_penalty_settings'] = guest.wait(
        "/usr/sbin/sshd -T -C user=root,host=x.invalid,addr=192.0.2.1 | grep -i persourcepenalt || true")
    result['sshd_log'] = guest.wait(
        f"journalctl -u ssh.service --since @{since} --no-pager -o short-iso"
        " | grep -iE 'penalt|drop connection|MaxStartups' || true").splitlines()
    (ctx.evidence / 'probe-study.json').write_text(json.dumps(result, indent=2))
    print('probe study:', json.dumps({k: v for k, v in result.items() if k != 'sshd_log'}), flush=True)


def matrix(ctx, image):
    disk = ctx.overlay(image, 'disk.qcow2')
    with Guest(ctx, 'matrix', disk) as guest:
        guest.ready()
        guest.upload(ctx.bundle(with_xui=False))
        guest.phase('prepare')
        source_address(ctx, guest)
        guest.phase('matrix')
        ctx.timings.measure('matrix.probe-study', probe_study, ctx, guest)
        ctx.timings.measure('matrix.lifecycle', lifecycle, ctx, guest)


def recovery(ctx, image):
    """Scenarios B (timeout) and C (reboot while pending) of design 7.5."""
    prepared = ctx.overlay(image, 'prepared.qcow2')
    with Guest(ctx, 'base', prepared) as guest:
        guest.ready()
        guest.upload(ctx.bundle(with_xui=False))
        guest.phase('prepare')
        guest.phase('m2-prepare', script='m2.sh')
        guest.poweroff()

    # VT-20 and VT-21: the apply session ends right after apply; nobody confirms.
    with Guest(ctx, 'timeout', ctx.overlay(prepared, 'timeout.qcow2')) as guest:
        guest.ready()
        guest.phase('m2-baseline', script='m2.sh')
        guest.phase('m2-listen', '8080', script='m2.sh')
        check(http_reachable(18080), 'port 8080 answers before apply (control)')
        with Probe(guest, 'timeout'):
            status, output = guest.interactive('vt20-apply', f'{VH} apply --open 443/tcp --confirm-timeout 3')
            check(status == 0 and APPLIED in output, 'VT-20: apply finished with a 3-minute confirmation time')
            guest.must_login('root', 'while pending')
            check(not http_reachable(18080), 'VT-20: UFW drops port 8080 while pending')
            # The restore starts after 3 minutes; under emulation it can take several more.
            ctx.timings.measure('timeout.restore', guest.wait_status, 'rolled-back', 900)
            guest.must_login('root', 'after the timeout restore')
            guest.must_login(ctx.user, 'after the timeout restore')
            guest.phase('m2-rolled-back', 'timeout', script='m2.sh')
            check(http_reachable(18080), 'VT-20: port 8080 answers again after the restore')

    # VT-22: reboot from the session that ran apply, while the change is pending.
    with Guest(ctx, 'reboot', ctx.overlay(prepared, 'reboot.qcow2')) as guest:
        guest.ready()
        guest.phase('m2-baseline', script='m2.sh')
        with Probe(guest, 'reboot') as probe:
            boot_id = guest.boot_id()
            status, output = guest.interactive(
                'vt22-apply', f'{VH} apply --open 443/tcp && systemctl reboot',
                on_text={APPLIED: lambda: probe.outage('reboot')})
            check(APPLIED in output, 'VT-22: apply finished, then the same session rebooted')
            ctx.timings.measure('reboot.boot', guest.wait_boot, boot_id)
            probe.outage_over()
            guest.must_login('root', 'after the reboot')
            guest.must_login(ctx.user, 'after the reboot')
            guest.phase('m2-rolled-back', 'boot', script='m2.sh')


def negative(ctx, image):
    prepared = ctx.overlay(image, 'prepared.qcow2')
    with Guest(ctx, 'base', prepared) as guest:
        guest.ready()
        guest.upload(ctx.bundle(with_xui=True))
        guest.phase('prepare')
        guest.phase('negative')
        guest.poweroff()
    for case in ('s1', 's2', 's3', 's4'):
        with Guest(ctx, case, ctx.overlay(prepared, case + '.qcow2')) as guest:
            guest.ready()
            if case != 's2':
                guest.phase(case)
                continue
            # The guest sees forwarded traffic from the QEMU gateway, so UFW
            # must filter it: 2096 answers before UFW is enabled and not after.
            guest.phase('s2-listen')
            before = {port: http_reachable(host) for host, port in ((18080, 8080), (12096, 2096))}
            guest.phase('s2')
            after = {port: http_reachable(host) for host, port in ((18080, 8080), (12096, 2096))}
            result = {'before_ufw': before, 'after_ufw': after}
            (ctx.evidence / 'ufw-path.json').write_text(json.dumps(result, indent=2))
            if result != {'before_ufw': {8080: True, 2096: True}, 'after_ufw': {8080: True, 2096: False}}:
                raise RuntimeError(f'unexpected UFW path result: {result}')
            print('PASS UFW filters forwarded connections:', result, flush=True)

    # VT-23: apply fails after the restore is armed; everything it did is undone.
    with Guest(ctx, 'vt23', ctx.overlay(prepared, 'vt23.qcow2')) as guest:
        guest.ready()
        guest.phase('vt23-setup', script='m2.sh')
        guest.phase('m2-baseline', script='m2.sh')
        with Probe(guest, 'vt23'):
            status, output = guest.interactive('vt23-apply', f'{VH} apply --open 443/tcp')
            check(status == 1 and '正在恢复应用前的配置' in output and '已恢复到应用前的配置' in output,
                  'VT-23: apply failed, restored, exit status 1')
            guest.must_login('root', 'after the failed apply')
            guest.must_login(ctx.user, 'after the failed apply')
            guest.phase('m2-rolled-back', 'failure', script='m2.sh')
            # VT-64: once the cause is gone, apply runs the normal flow again.
            guest.phase('m4-unmask', script='m4.sh')
            status, output = guest.interactive('vt64-reapply', f'{VH} apply --open 443/tcp')
            check(status == 0 and APPLIED in output, 'VT-64: apply after the rolled-back failure awaits confirmation')
            status, output = guest.command('vt64-reapply-confirm', f'{VH} confirm')
            check(status == 0 and '已确认' in output, 'VT-64: confirm from a new root session, then verify passes')
            guest.phase('m4-reapplied', script='m4.sh')

    # VT-72, local part: the release installer on a host the tool never touched.
    with Guest(ctx, 'vt72', ctx.overlay(prepared, 'vt72.qcow2')) as guest:
        guest.ready()
        guest.phase('m4-installer', script='m4.sh')


def panel(ctx, guest, template):
    """VT-55: 3X-UI's login page at its WebBasePath, through the tunnel the
    tool printed. The path is read here and kept out of the evidence."""
    base = guest.wait("/usr/local/x-ui/x-ui setting -show true | sed -n 's/^webBasePath: //p'")
    check(base.startswith('/') and base.endswith('/') and len(base) > 2, 'VT-55: the panel has a WebBasePath')
    ctx.private.append(base)
    status, body = tunnel(ctx, template, base, 'panel-tunnel')
    title = body.split(b'<title>', 1)[-1].split(b'</title>', 1)[0][:80].decode(errors='replace')
    (ctx.evidence / 'panel-tunnel-page.json').write_text(json.dumps({'status': status, 'title': title}, indent=2))
    check(status == 200 and title == 'Sign in', f'VT-55: the WebBasePath returns the login page ({status}, {title!r})')


def hardened(ctx, image):
    """M3 on a guest hardened and confirmed as an administrator would, with
    only 22/tcp until 3X-UI is installed and its ports are added (requirement
    D41); then VT-51 on overlays of its disk after VT-55."""
    disk = ctx.overlay(image, 'disk.qcow2')
    with Guest(ctx, 'hardened', disk) as guest:
        def m3(name, *args):
            guest.phase(name, *args, script='m3.sh')
        guest.ready()
        guest.upload(ctx.bundle(with_xui=True))
        guest.phase('prepare')
        guest.phase('m2-prepare', script='m2.sh')
        guest.phase('m2-baseline', script='m2.sh')
        with Probe(guest, 'hardened') as probe:
            status, output = guest.interactive('apply', f'{VH} apply')
            check(status == 0 and APPLIED in output, 'apply finished and awaits confirmation')
            template = next(line.strip() for line in output.splitlines() if line.strip().startswith('ssh -N -L'))
            status, output = guest.command('confirm', f'{VH} confirm')
            check(status == 0 and '已确认' in output, 'confirm from a new root session, then verify passes')
            guest.phase('m4-flow-ssh-only', script='m4.sh')
            for name in ('m3-fail2ban', 'm3-regex', 'm3-ban', 'm3-manual-ban', 'm3-agent', 'm3-updates', 'm3-xui'):
                m3(name)
            status, output = guest.interactive(
                'xui-ports', f'{VH} ports --add 443/tcp --add 2096/tcp; echo "ports-rc=$?"')
            check('ports-rc=0' in output and PORTS_CHANGED in output, 'the 3X-UI ports await confirmation')
            status, output = guest.command('xui-ports-confirm', f'{VH} confirm')
            check(status == 0 and '已确认，端口变更生效' in output, 'confirm the 3X-UI ports from a new root session')
            guest.phase('m4-flow-ports-added', script='m4.sh')
            panel(ctx, guest, template)
            probe.outage('reboot')
            guest.reboot()
            probe.outage_over()
            guest.must_login('root', 'after the reboot')
            m3('m3-xui-rebooted')
        guest.poweroff()
    for drift in DRIFTS:
        with Guest(ctx, f'vt51-{drift}', ctx.overlay(disk, f'vt51-{drift}.qcow2')) as guest:
            guest.ready()
            guest.phase('m3-drift', drift, script='m3.sh')
    for name, case in (('vt61', vt61), ('vt63', vt63), ('vt64', vt64)):
        with Guest(ctx, name, ctx.overlay(disk, f'{name}.qcow2')) as guest:
            guest.ready()
            guest.phase('m4-setup', script='m4.sh')
            case(ctx, guest)


def vt61(ctx, guest):
    """VT-61: the rollback command with 3X-UI installed leaves 3X-UI as it is."""
    guest.phase('m4-xui-record', script='m4.sh')
    with Probe(guest, 'vt61'):
        status, output = guest.interactive('vt61-rollback', f'{VH} rollback; echo "rollback-rc=$?"')
        check('rollback-rc=0' in output and '已恢复到应用前的配置' in output, 'VT-61: rollback finished')
        guest.must_login('root', 'after the rollback')
        guest.must_login(ctx.user, 'after the rollback')
    guest.phase('m2-rolled-back', 'manual', script='m2.sh')
    guest.phase('m4-xui-kept', script='m4.sh')


def vt63(ctx, guest):
    """VT-63: refused port changes, one confirmed, one left to time out."""
    def m4(*args):
        guest.phase(*args, script='m4.sh')
    guest.phase('m2-listen', '443', '2096', '8443', '9443', script='m2.sh')
    m4('m4-ports-before')
    m4('m4-ports-refused')
    with Probe(guest, 'vt63'):
        status, output = guest.interactive(
            'vt63-ports', f'{VH} ports --add 8443/tcp --remove 2096/tcp; echo "ports-rc=$?"')
        check('ports-rc=0' in output and PORTS_CHANGED in output, 'VT-63: the port change awaits confirmation')
        guest.must_login('root', 'while the port change is pending')
        status, output = guest.command('vt63-confirm', f'{VH} confirm')
        check(status == 0 and '已确认，端口变更生效' in output, 'VT-63: confirm from a new root session, then verify passes')
        m4('m4-ports-changed')
        status, output = guest.interactive(
            'vt63-ports-unconfirmed', f'{VH} ports --add 9443/tcp --confirm-timeout 3; echo "ports-rc=$?"')
        check('ports-rc=0' in output and PORTS_CHANGED in output, 'VT-63: a second port change awaits confirmation')
        m4('m4-ports-pending')
        ctx.timings.measure('vt63.restore', guest.wait_status, 'applied', 900)
        guest.must_login('root', 'after the port restore')
        m4('m4-ports-restored')


def vt64(ctx, guest):
    """VT-64: apply on the applied host changes nothing; other inputs and drift are refused."""
    def m4(*args):
        guest.phase(*args, script='m4.sh')
    m4('m4-record')
    status, output = guest.interactive('vt64-apply-again', f'{VH} apply {HARDENED_OPEN}; echo "apply-rc=$?"')
    check('apply-rc=0' in output and '未做任何变更' in output and APPLY_PROMPT.decode() not in output,
          'VT-64: apply on the applied host exits 0 without asking or changing anything')
    m4('m4-unchanged', 'again', 'm4-record')
    status, output = guest.interactive('vt64-apply-other', f'{VH} apply --open 443/tcp; echo "apply-rc=$?"')
    check('apply-rc=1' in output and '[FAIL] apply.inputs' in output, 'VT-64: apply with other inputs is refused')
    m4('m4-unchanged', 'other', 'm4-record')
    m4('m4-ufw-drift')
    status, output = guest.interactive('vt64-apply-drift', f'{VH} apply {HARDENED_OPEN}; echo "apply-rc=$?"')
    check('apply-rc=1' in output and '[FAIL] ufw.rules' in output and '[FAIL] ufw.userrules' in output,
          'VT-64: apply on a drifted host is refused')
    m4('m4-unchanged', 'drift', 'm4-ufw-drift')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=['debian12', 'debian13', 'ubuntu2404'], required=True)
    parser.add_argument('--arch', choices=['amd64', 'arm64'], required=True)
    parser.add_argument('--suite', choices=['matrix', 'recovery', 'negative', 'hardened'], required=True)
    args = parser.parse_args()
    ctx = Context(args)
    image = ctx.timings.measure('image', ctx.image)
    ctx.seed()
    {'matrix': matrix, 'recovery': recovery, 'negative': negative, 'hardened': hardened}[args.suite](ctx, image)
    ctx.leak_scan()
    (ctx.evidence / 'COMPLETED').write_text(f'PASS {args.suite} {args.platform} {args.arch}\n')
    print('PASS', args.suite, args.platform, args.arch, flush=True)


if __name__ == '__main__':
    main()
