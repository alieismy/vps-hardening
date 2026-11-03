#!/usr/bin/env python3
"""D64 parser/decision tests; these do not establish Linux or VM acceptance.

Execute the owning embedded Python functions rather than reimplementing their
parsers. Runtime input seams are mocked only where Linux/systemd is required.
"""
import ast
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
CURRENT_VERSION = re.search(r"^readonly VH_VERSION='([^']+)'$",
                            (ROOT / 'bin/vps-hardening').read_text(encoding='utf-8'), re.M)[1]


def load_probe():
    shell = (ROOT / 'lib/vps-hardening/probe.sh').read_text(encoding='utf-8')
    code = shell.split("<<'VH_SSH_PY'\n", 1)[1].split('\nVH_SSH_PY', 1)[0]
    module = ast.parse(code)
    # The final top-level try dispatches the CLI. Import its owning definitions
    # without executing that dispatch or any real host probe.
    module.body = [node for node in module.body if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef))]
    namespace = {'__name__': 'vh_ssh_probe_test'}
    exec(compile(module, 'probe.sh:VH_SSH_PY', 'exec'), namespace)
    return namespace


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.probe = load_probe()

    def test_reload_discovery_retries_transient_failure(self):
        calls = []
        def discover():
            calls.append('discover')
            if len(calls) < 3:
                raise ValueError('listener is reloading')
            print('stable endpoint')
        output = io.StringIO()
        with patch.dict(self.probe, discover=discover), \
                patch.object(self.probe['time'], 'sleep') as sleep, redirect_stdout(output):
            self.probe['discover_after_reload']()
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(output.getvalue(), 'stable endpoint\n')

    def test_reload_discovery_preserves_persistent_failure(self):
        calls = []
        def discover():
            calls.append('discover')
            raise ValueError('persistent endpoint mismatch')
        with patch.dict(self.probe, discover=discover), \
                patch.object(self.probe['time'], 'sleep') as sleep:
            with self.assertRaisesRegex(ValueError, 'persistent endpoint mismatch'):
                self.probe['discover_after_reload']()
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleep.call_count, 2)

    def test_explicit_listen_port_is_authority(self):
        values = self.probe['config_endpoints']('port 22\nlistenaddress 0.0.0.0:2222\n')
        self.assertEqual(values, {('ipv4', '0.0.0.0', '2222')})

    def test_dual_stack_one_number(self):
        values = self.probe['config_endpoints'](
            'port 2222\nlistenaddress 0.0.0.0:2222\nlistenaddress [::]:2222\n')
        self.assertEqual({entry[2] for entry in values}, {'2222'})
        self.assertEqual(len(values), 2)

    def test_multiple_effective_ports_remain_visible(self):
        values = self.probe['config_endpoints'](
            'port 22\nport 2222\nlistenaddress 0.0.0.0:22\nlistenaddress [::]:2222\n')
        self.assertEqual({entry[2] for entry in values}, {'22', '2222'})

    def test_missing_or_unresolved_addresses_fail(self):
        for text in ('port 2222\n', 'listenaddress example.invalid:2222\n', 'listenaddress ::%eth0:2222\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.probe['config_endpoints'](text)

    def test_mapped_address_does_not_invent_ipv6(self):
        self.assertEqual(self.probe['endpoint']('[::ffff:192.0.2.1]:2222'),
                         {('ipv4', '192.0.2.1', '2222')})

    def test_wildcard_needs_family(self):
        with self.assertRaises(ValueError):
            self.probe['endpoint']('*:2222')
        self.assertEqual(self.probe['endpoint']('*:2222', 6, True),
                         {('ipv4', '0.0.0.0', '2222'), ('ipv6', '::', '2222')})

    def test_port_bounds(self):
        for value in ('0', '65536', '022', '-1', '22/tcp', ''):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.probe['port'](value)
        self.assertEqual(self.probe['port']('65535'), '65535')

    def service(self, argv, environment=None, files=None, pid=0):
        argv = shlex.split(argv) if isinstance(argv, str) else argv
        values = {
            'ExecStart': ('a(sasbttttuii)', [[argv[0], argv, False, 0, 0, 0, 0, pid, 0, 0]]),
            'Environment': ('as', environment or []),
            'EnvironmentFiles': ('a(sb)', files or []),
        }
        def run(*args):
            self.assertEqual(args[:4], ('busctl', '--system', '--json=short', 'get-property'))
            signature, data = values[args[-1]]
            return json.dumps({'type': signature, 'data': data})
        with patch.dict(self.probe, run=run):
            return self.probe['service_arguments'](pid)

    def test_native_start_options_and_literal_environment(self):
        options, config = self.service('/usr/sbin/sshd -D $SSHD_OPTS',
                                       ['SSHD_OPTS=-p 2222 -f /etc/ssh/sshd_config'])
        self.assertEqual(options, ['-p', '2222', '-f', '/etc/ssh/sshd_config'])
        self.assertEqual(config, '/etc/ssh/sshd_config')

    def test_structured_argv_retains_spaces_and_literal_quotes(self):
        options, _ = self.service(['/usr/sbin/sshd', '-D', '-o', 'Port 2222',
                                   '-o', 'ListenAddress 0.0.0.0:2222'])
        self.assertEqual(options, ['-o', 'Port 2222', '-o', 'ListenAddress 0.0.0.0:2222'])

    def test_environment_file_retains_inner_quotes_until_expansion(self):
        with patch.object(Path, 'exists', return_value=True), patch.object(
                Path, 'read_text', return_value='SSHD_OPTS=-o "ListenAddress 0.0.0.0:2222"\n'):
            options, _ = self.service('/usr/sbin/sshd -D $SSHD_OPTS',
                                       files=[['/etc/default/ssh', True]])
        self.assertEqual(options, ['-o', 'ListenAddress 0.0.0.0:2222'])

    def test_environment_file_native_quoting_continuations_and_precedence(self):
        text = ('# ignored\nno assignment\n'
                'A=  one   "two words"  \n'
                'B="-o \\"Port 2222\\""\n'
                "C='one\ntwo'\n"
                'D=first\\\nsecond\n'
                'E="a\\qb\\$c"\n'
                'F=trailing\\ \n'
                'A=last\n')
        self.assertEqual(self.probe['environment_file'](text), {
            'A': 'last', 'B': '-o "Port 2222"', 'C': 'one\ntwo',
            'D': 'firstsecond', 'E': 'a\\qb$c', 'F': 'trailing ',
        })
        self.assertEqual(self.probe['environment_file']('A= one   "two words"  '),
                         {'A': 'one   "two words"'})
        with patch.object(Path, 'exists', return_value=True), patch.object(
                Path, 'read_text', side_effect=['SSHD_OPTS=-p 2223\n', 'SSHD_OPTS=-p 2222\n']):
            options, _ = self.service('/usr/sbin/sshd -D $SSHD_OPTS', ['SSHD_OPTS=-p 22'],
                                       [['/etc/first', False], ['/etc/second', False]])
        self.assertEqual(options, ['-p', '2222'])

    def test_unfinished_environment_file_is_rejected(self):
        for text in ('SSHD_OPTS="-p 2222', 'SSHD_OPTS=-p 2222\\', 'BAD-NAME=x', 'A=\x00'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.probe['environment_file'](text)

    def test_environment_missing_optional_file(self):
        with patch.object(Path, 'exists', return_value=False):
            self.assertEqual(self.service('/usr/sbin/sshd -D $SSHD_OPTS',
                                          files=[['/etc/default/ssh', True]])[0], [])

    def test_systemd_variable_expansion_escapes_inside_quotes(self):
        for quote in ('"', "'"):
            with self.subTest(quote=quote):
                options, _ = self.service('/usr/sbin/sshd -D $SSHD_OPTS',
                                           ['SSHD_OPTS=-o ' + quote + 'Port\\ 2222' + quote])
                self.assertEqual(options, ['-o', 'Port 2222'])
        words = self.probe['environment_words']
        self.assertEqual(words('one "" two\\ words'), ['one', '', 'two words'])
        for value in ('"unfinished', 'trailing\\', '"a\nb"', '\x00'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                words(value)

    def test_braced_variable_is_one_argument_without_second_unquoting(self):
        options, _ = self.service('/usr/sbin/sshd -D -o ${SSHD_OPTION}', ['SSHD_OPTION=Port 2222'])
        self.assertEqual(options, ['-o', 'Port 2222'])
        with self.assertRaisesRegex(ValueError, '控制字符'):
            self.service('/usr/sbin/sshd -D -o ${SSHD_OPTION}', ['SSHD_OPTION=Port\n2222'])

    def test_listener_title_confirms_options_after_environ_is_overwritten(self):
        def read_bytes(path):
            # Reading environ would reproduce the original false rejection.
            self.assertEqual(path.name, 'cmdline')
            return b'sshd: /usr/sbin/sshd -D -p 2222 [listener] 0 of 10-100 startups\x00'
        with patch.object(Path, 'read_bytes', read_bytes):
            self.assertEqual(self.service('/usr/sbin/sshd -D $SSHD_OPTS',
                                          ['SSHD_OPTS=-p 2222'], pid=100)[0], ['-p', '2222'])
            with self.assertRaisesRegex(ValueError, '运行中 sshd'):
                self.service('/usr/sbin/sshd -D $SSHD_OPTS', ['SSHD_OPTS=-p 2223'], pid=100)

    def test_runtime_argv_and_parameter_boundaries_are_checked(self):
        with patch.object(Path, 'read_bytes', return_value=b'/usr/sbin/sshd\x00-D\x00-o\x00Port 2222\x00'):
            self.assertEqual(self.service(['/usr/sbin/sshd', '-D', '-o', 'Port 2222'], pid=100)[0],
                             ['-o', 'Port 2222'])
            with self.assertRaisesRegex(ValueError, '运行中 sshd'):
                self.service(['/usr/sbin/sshd', '-D', '-o', 'Port', '2222'], pid=100)

    def test_structured_property_unknown_format_and_multiple_commands_rejected(self):
        cases = [{'type': 's', 'data': 'display text'},
                 {'type': 'a(sasbttttuii)', 'data': []},
                 {'type': 'a(sasbttttuii)', 'data': [['/usr/sbin/sshd']]},
                 {'type': 'a(sasbttttuii)', 'data': [['a'] * 10, ['b'] * 10]}]
        for value in cases:
            with self.subTest(value=value), patch.dict(self.probe, run=lambda *args: json.dumps(value)), \
                    self.assertRaises(ValueError):
                self.probe['service_arguments'](0)
        with patch.dict(self.probe, run=lambda *args: 'not JSON'), self.assertRaises(ValueError):
            self.probe['service_arguments'](0)
        for files in ([['/etc/default/ssh', 'yes']], ['/etc/default/ssh'], [['relative', False]]):
            with self.subTest(files=files), self.assertRaises(ValueError):
                self.service('/usr/sbin/sshd -D', files=files)

    def test_busctl_missing_failed_or_timed_out_is_not_a_default_port(self):
        for error in (FileNotFoundError('busctl'), subprocess.TimeoutExpired('busctl', 10)):
            with self.subTest(error=error), patch.object(subprocess, 'run', side_effect=error), \
                    self.assertRaisesRegex(ValueError, 'busctl'):
                self.probe['service_arguments'](0)
        with patch.object(subprocess, 'run', return_value=SimpleNamespace(returncode=1)), \
                self.assertRaisesRegex(ValueError, 'busctl 返回非零'):
            self.probe['service_arguments'](0)

    def test_readonly_probe_omits_daemon_log_file_option(self):
        options, config = self.service('/usr/sbin/sshd -D -E /var/log/sshd.log -p 2222')
        self.assertEqual(options, ['-p', '2222'])
        self.assertEqual(config, '/etc/ssh/sshd_config')

    def test_managed_authentication_or_include_override_rejected(self):
        for option in ('PermitRootLogin=yes', 'PasswordAuthentication yes',
                       'KbdInteractiveAuthentication=yes', 'PubkeyAuthentication=no',
                       'DenyUsers=root', 'Include=/tmp/untrusted', 'Match=User root',
                       '"PasswordAuthentication" yes', '"Include"=/tmp/untrusted',
                       'PaSsWoRdAuThEnTiCaTiOn=yes'):
            with self.subTest(option=option), self.assertRaises(ValueError):
                self.service('/usr/sbin/sshd -D -o ' + repr(option))

    def test_native_endpoint_options_remain_supported(self):
        options, _ = self.service('/usr/sbin/sshd -D -o Port=2222 -o ListenAddress=0.0.0.0:2222 -o AddressFamily=inet')
        self.assertEqual(options, ['-o', 'Port=2222', '-o', 'ListenAddress=0.0.0.0:2222', '-o', 'AddressFamily=inet'])

    def test_wrapper_and_unknown_option_rejected(self):
        for argv in ('/bin/sh -c /usr/sbin/sshd', '/usr/sbin/sshd -i',
                     '/usr/sbin/sshd -p', '/usr/sbin/sshd --unknown', '/usr/sbin/sshd -f relative'):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                self.service(argv)

    def test_socket_dropin_reset_is_applied(self):
        contents = '[Socket]\nListenStream=22\n[Socket]\nListenStream=\nListenStream=2222\n'
        props = {'Listen': '[::]:2222 (Stream)', 'BindIPv6Only': 'both'}
        with patch.dict(self.probe, run=lambda *args: contents):
            self.assertEqual(self.probe['socket_endpoints'](props),
                             {('ipv4', '0.0.0.0', '2222'), ('ipv6', '::', '2222')})

    def test_systemctl_repeated_listen_lines_preserve_both_address_families(self):
        # Actual systemctl show format observed in the Ubuntu CI artifact:
        # each address has its own Listen= line, rather than a joined value.
        shown = ('LoadState=loaded\nActiveState=active\nMainPID=123\n'
                 'Listen=0.0.0.0:2222 (Stream)\nListen=[::]:2222 (Stream)\n'
                 'BindIPv6Only=ipv6-only\n')
        persistent = ('[Socket]\nListenStream=0.0.0.0:22\nListenStream=[::]:22\n'
                      '[Socket]\nListenStream=\nListenStream=0.0.0.0:2222\nListenStream=[::]:2222\n')
        def run(*args):
            return shown if args[1] == 'show' else persistent
        with patch.dict(self.probe, run=run):
            props = self.probe['properties']('ssh.socket')
            self.assertEqual(props['MainPID'], '123')
            self.assertEqual(self.probe['socket_endpoints'](props),
                             {('ipv4', '0.0.0.0', '2222'), ('ipv6', '::', '2222')})

    def test_repeated_listen_must_not_hide_an_extra_loaded_endpoint(self):
        shown = ('Listen=0.0.0.0:22 (Stream)\nListen=[::]:2222 (Stream)\n'
                 'BindIPv6Only=ipv6-only\n')
        with patch.dict(self.probe, run=lambda *args: shown if args[1] == 'show' else
                        '[Socket]\nListenStream=[::]:2222\n'):
            props = self.probe['properties']('ssh.socket')
            with self.assertRaisesRegex(ValueError, '持久化与加载'):
                self.probe['socket_endpoints'](props)

    def test_socket_persistent_loaded_mismatch(self):
        props = {'Listen': '[::]:22 (Stream)', 'BindIPv6Only': 'both'}
        with patch.dict(self.probe, run=lambda *args: '[Socket]\nListenStream=2222\n'):
            with self.assertRaisesRegex(ValueError, '持久化与加载'):
                self.probe['socket_endpoints'](props)

    def test_socket_datagram_not_ssh(self):
        with self.assertRaises(ValueError):
            self.probe['socket_endpoints']({'Listen': '2222 (Datagram)'})

    def listener(self, ipv4, ipv6='', expected=None, main_pid=100, socket_mode=False):
        def run(*args):
            return ipv4 if args[-1] == '-4' else ipv6
        expected = expected or {('ipv4', '0.0.0.0', '2222')}
        with patch.object(Path, 'read_bytes', return_value=b'sshd: /usr/sbin/sshd -D [listener]\x00'), \
                patch.dict(self.probe, run=run,
                           process_exe=lambda pid: {1: 'systemd', 100: 'sshd', 200: 'sshd', 300: 'python3'}.get(pid)):
            return self.probe['listening'](expected, main_pid, socket_mode)

    def test_listener_must_belong_to_the_recorded_daemon(self):
        good = 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=100,fd=3))\n'
        self.assertEqual(self.listener(good), {('ipv4', '0.0.0.0', '2222')})
        with self.assertRaisesRegex(ValueError, '额外 SSH 实例'):
            self.listener(good.replace('pid=100', 'pid=200'))
        with self.assertRaisesRegex(ValueError, '监听不属于'):
            self.listener(good.replace('pid=100', 'pid=300'))

    def test_unrelated_scoped_ipv6_listener_does_not_reject_ssh(self):
        good = 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=100,fd=3))'
        other = 'LISTEN 0 128 [fe80::1%eth0]:8080 [::]:* users:(("other",pid=300,fd=3))'
        self.assertEqual(self.listener(good, other), {('ipv4', '0.0.0.0', '2222')})

    def test_ipv6_wildcard_requires_actual_v6only_attribute(self):
        raw = 'LISTEN 0 128 *:2222 *:* users:(("sshd",pid=100,fd=3))'
        expected = {('ipv4', '0.0.0.0', '2222'), ('ipv6', '::', '2222')}
        with self.assertRaisesRegex(ValueError, '缺少 v6only'):
            self.listener('', raw, expected)
        self.assertEqual(self.listener('', raw + ' v6only:0', expected), expected)
        self.assertEqual(self.listener('', raw + ' v6only:1', expected), {('ipv6', '::', '2222')})

    def test_socket_owner_systemd_is_only_accepted_in_socket_mode(self):
        raw = 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("systemd",pid=1,fd=3))'
        self.assertEqual(self.listener(raw, main_pid=0, socket_mode=True),
                         {('ipv4', '0.0.0.0', '2222')})
        with self.assertRaises(ValueError):
            self.listener(raw)

    def record(self, lines, actual=None, digest='a' * 64):
        actual = actual or ['2222', 'service', 'ipv4,0.0.0.0,2222 ipv6,::,2222']
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state'
            path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
            before = path.read_bytes()
            output = io.StringIO()
            with redirect_stdout(output):
                self.probe['read_record'](str(path), actual, digest, CURRENT_VERSION)
            self.assertEqual(path.read_bytes(), before, 'record compatibility must remain read-only')
            return output.getvalue()

    @staticmethod
    def modern():
        return ['version=' + CURRENT_VERSION, 'ssh_port=2222', 'ssh_activation=service',
                'ssh_listeners=ipv4,0.0.0.0,2222 ipv6,::,2222']

    def test_current_record(self):
        self.assertEqual(self.record(self.modern()), 'no\n')

    def test_recognizable_old_22_requires_original_jail_digest(self):
        lines = ['version=0.1.2', 'digest.5=' + 'a' * 64 + ' /etc/fail2ban/jail.d/99-vps-hardening.local']
        actual = ['22', 'service', 'ipv4,0.0.0.0,22 ipv6,::,22']
        self.assertEqual(self.record(lines, actual), 'yes\n')
        with self.assertRaises(ValueError):
            self.record(lines, actual, 'b' * 64)
        with self.assertRaises(ValueError):
            self.record(lines)

    def test_unknown_record_does_not_get_default_22(self):
        with self.assertRaises(ValueError):
            self.record(['version=unknown'])

    def test_unknown_version_with_new_fields_rejected(self):
        lines = self.modern()
        lines[0] = 'version=unknown'
        with self.assertRaises(ValueError):
            self.record(lines)

    def test_new_version_without_fields_is_not_legacy(self):
        with self.assertRaises(ValueError):
            self.record(['version=' + CURRENT_VERSION])

    def test_old_version_cannot_claim_new_fields(self):
        lines = self.modern()
        lines[0] = 'version=0.1.2'
        with self.assertRaises(ValueError):
            self.record(lines)

    def test_partial_and_duplicate_records_rejected(self):
        for lines in (self.modern()[:-1], self.modern() + ['ssh_port=2222']):
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                self.record(lines)

    def test_illegal_and_noncanonical_record_rejected(self):
        for line in ('ssh_port=65536', 'ssh_port=22', 'ssh_activation=wrapper',
                     'ssh_listeners=ipv6,::,2222 ipv4,0.0.0.0,2222',
                     'ssh_listeners=ipv4,0.0.0.0,2222 ipv6,::,22'):
            lines = [line if value.split('=', 1)[0] == line.split('=', 1)[0] else value
                     for value in self.modern()]
            with self.subTest(line=line), self.assertRaises(ValueError):
                self.record(lines)

    def test_listener_or_activation_drift_rejected(self):
        for actual in (['2222', 'socket', 'ipv4,0.0.0.0,2222 ipv6,::,2222'],
                       ['2222', 'service', 'ipv4,0.0.0.0,2222'],
                       ['22', 'service', 'ipv4,0.0.0.0,22 ipv6,::,22']):
            with self.subTest(actual=actual), self.assertRaisesRegex(ValueError, '漂移'):
                self.record(self.modern(), actual)


if __name__ == '__main__':
    unittest.main()
