#!/usr/bin/env python3
"""M1 VM tests: run the read-only commands in disposable QEMU guests.

Adapted from vps-tuning's tests/platform-vm.py. Suites:

  matrix    one guest: VT-01, the unhardened part of VT-50, the guest-side
            source address of forwarded connections, and the sshd probe study
            for VO-2 (docs/verification-plan.md 3.3).
  negative  a prepared guest for VT-02 and VT-04, then one overlay disk per
            existing-host case S1-S4 (VT-03), plus the UFW path check in S2.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tarfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / '.tmp/vm'
SSH_PORT = 2222
# Runner port -> guest port (verification plan 3.3).
FORWARDS = {SSH_PORT: 22, 12053: 2053, 10443: 443, 12096: 2096, 10080: 80, 18080: 8080}
XUI_COMMIT = 'f727d04f6522bb94a8fb52e8352fdcafb51c11e1'  # tag v3.7.0
XUI_FILES = {
    'install.sh': 'a7f4fedcea3abe8987508d00f29834b8872e4e4e5059159eb19460d474b37cdc',
    'x-ui.sh': 'cfabcd4af35a3646c374ea0ccba5178f4c0d3135f699277fc8d8b810158e85c0',
}
GUEST_SCRIPT = 'bash /opt/vh-bundle/tests/guest/m1.sh '


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

    def login_ok(self):
        try:
            return self.ssh('true', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60).returncode == 0
        except subprocess.TimeoutExpired:
            return False

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

    def upload(self, bundle):
        with bundle.open('rb') as f:
            run(self.ctx.ssh + ['rm -rf /opt/vh-bundle && install -d -m 0755 /opt/vh-bundle && '
                                'tar --no-same-owner -xf - -C /opt/vh-bundle'], stdin=f, timeout=120)

    def phase(self, name, timeout=1800):
        print('START', self.label, name, flush=True)
        log_path = self.evidence / f'{name}.log'

        def body():
            with log_path.open('wb') as log:
                run(self.ctx.ssh + [GUEST_SCRIPT + name], stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        try:
            self.ctx.timings.measure(f'{self.label}.{name}', body)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            print(log_path.read_text(errors='replace'), flush=True)
            raise
        print('PASS', self.label, name, flush=True)

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
        self.ssh = []

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
                             'content': 'PasswordAuthentication yes\n'}],
            'runcmd': [['sh', '-c', 'printf "root:%s\\n" "$1" | chpasswd', 'sh', self.password],
                       ['touch', '/root/vh-cloud-ready']],
        }
        (self.work / 'user-data').write_text('#cloud-config\n' + json.dumps(user_data))
        (self.work / 'meta-data').write_text('instance-id: vh-m1\nlocal-hostname: vh-ci\n')
        run(['cloud-localds', str(self.work / 'seed.img'), str(self.work / 'user-data'), str(self.work / 'meta-data')])
        (self.work / 'known-hosts').write_text(f'[127.0.0.1]:{SSH_PORT} ' + (self.work / 'host.pub').read_text())
        self.ssh = ['ssh', '-i', str(self.work / 'client'), '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                    '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(self.work / 'known-hosts'),
                    '-o', 'ConnectTimeout=5', '-o', 'LogLevel=ERROR', '-p', str(SSH_PORT), 'root@127.0.0.1']

    def bundle(self, with_xui):
        """Tool, guest tests and (for S1) the verified 3X-UI fixture files."""
        path = self.work / 'bundle.tar'
        files = sorted(p for d in ('bin', 'lib', 'tests/guest') for p in (ROOT / d).rglob('*') if p.is_file())
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
        """No test password in any tool or guest output (VT-50)."""
        needle = self.password.encode()
        for path in self.evidence.rglob('*'):
            if path.is_file() and path.name != 'serial.log' and needle in path.read_bytes():
                raise RuntimeError(f'test password found in {path.relative_to(self.evidence)}')


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=['debian12', 'debian13', 'ubuntu2404'], required=True)
    parser.add_argument('--arch', choices=['amd64', 'arm64'], required=True)
    parser.add_argument('--suite', choices=['matrix', 'negative'], required=True)
    args = parser.parse_args()
    ctx = Context(args)
    image = ctx.timings.measure('image', ctx.image)
    ctx.seed()
    (matrix if args.suite == 'matrix' else negative)(ctx, image)
    ctx.leak_scan()
    (ctx.evidence / 'COMPLETED').write_text(f'PASS {args.suite} {args.platform} {args.arch}\n')
    print('PASS', args.suite, args.platform, args.arch, flush=True)


if __name__ == '__main__':
    main()
