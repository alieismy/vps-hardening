# VPS Hardening

English | [简体中文](README.zh-CN.md)

[![Latest release](https://img.shields.io/github/v/release/alieismy/vps-hardening)](https://github.com/alieismy/vps-hardening/releases/latest)
[![static](https://github.com/alieismy/vps-hardening/actions/workflows/static.yml/badge.svg?branch=master)](https://github.com/alieismy/vps-hardening/actions/workflows/static.yml)
[![vm](https://github.com/alieismy/vps-hardening/actions/workflows/vm.yml/badge.svg?branch=master)](https://github.com/alieismy/vps-hardening/actions/workflows/vm.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Baseline security hardening for Debian/Ubuntu VPS: key-only SSH login (root is the administrative account and may log in with a key only), UFW with only the necessary ports open, Fail2ban, and automatic security updates. The goal is to shrink the attack surface without noticeably adding to day-to-day administration, and without locking the administrator out of the server.

> This README is translated from the [Chinese README](README.zh-CN.md). The documents under `docs/` and the tool's own messages are in Chinese. Where the two READMEs differ, the Chinese README prevails.

**Current release: [`v0.2.1`](https://github.com/alieismy/vps-hardening/releases/tag/v0.2.1) (2026-11-22 UTC).** Hosts hardened by `v0.1.0` to `v0.2.0` must run `vps-hardening update-fail2ban` once after upgrading; see [Upgrading](#upgrading).

## Features

- **SSH**: key-only login; root may log in with a key only (`PermitRootLogin prohibit-password`). Apart from root, accounts with passwordless sudo (such as an image's default user) are denied SSH login, and their sudo rules are left unchanged. The provider's existing single SSH management port is kept, including non-22 ports; the port is never migrated.
- **UFW**: deny incoming, allow outgoing, deny routed; at hardening only the SSH port is allowed, and other public ports are opened as declared.
- **Fail2ban**: protects SSH only, `maxretry` is 5, and the ignore list contains only loopback addresses.
- **Automatic security updates**: unattended-upgrades is enabled without automatic reboots; `verify` reports when a reboot is required.
- **Lockout protection**: after `apply` and `ports`, the change must be confirmed from a new SSH session within a time limit (10 minutes by default). If it is not confirmed in time, or the host reboots before then, the previous configuration is restored from a snapshot.
- **Read-only checks and rollback**: `preflight` checks the host before any change, `verify` checks the hardening and any drift at any time, and `rollback` restores the configuration from before `apply`.

## Scope

| Item | Supported |
|---|---|
| Distributions | Debian 12, Debian 13, Ubuntu 24.04 LTS |
| Architecture | x86_64; arm64 is a reference only: the tool runs, and tests run on demand |
| Hosts | Fresh hosts from general VPS providers, hardened before 3X-UI is installed; not virtual machines from large cloud vendors such as Oracle Cloud or AWS |

Fresh hosts only: existing hosts already running 3X-UI are out of scope, and hosts with `nftables.service`, `netfilter-persistent` or `firewalld` enabled or running are refused as existing hosts. Hosts whose kernel was booted with `ipv6.disable=1` are refused by preflight.

The scope is baseline hardening: no full CIS compliance, intrusion detection, AppArmor/SELinux policies or audit system. This repository does not install proxy services or tune network performance. For each design decision, see [Confirmed scope](#confirmed-scope).

## Installation

Prerequisites: root has a usable public key (binding an SSH key in the provider's control panel is usually enough), you can log in as root with that key, and the provider's console is available.

1. Update the system, install basic tools and reboot. This tool does not do this step:

   ```bash
   apt update
   apt -s full-upgrade   # simulate only, to review the upgrade plan
   apt full-upgrade -y
   apt install -y curl wget ca-certificates gnupg lsb-release unzip vim nano htop ufw jq iproute2 procps kmod util-linux python3
   apt autoremove        # remove automatically installed packages that are no longer needed
   reboot
   ```

   Adjust the package list as needed, but keep `python3` from the official repositories (preflight parses the SSH endpoint with the standard library only) and systemd's `busctl`: without either, preflight refuses before any change. A host with `ufw` installed but neither enabled nor given rules still counts as fresh. Do not install Docker or 3X-UI in this step, and do not enable another firewall service.

2. Install `v0.2.1`:

   ```bash
   curl --disable --fail --location --proto '=https' --proto-redir '=https' \
     https://github.com/alieismy/vps-hardening/releases/download/v0.2.1/install.sh \
     -o install.sh &&
   echo '32110ed9ce8ef815a1e3cc5f3ebc3db1dd94eba3cd14e3e6fbde7ac392f3cc70  install.sh' | sha256sum -c - &&
   bash install.sh
   ```

   The installer runs only after the download and the digest check both succeed; the chain stops at the first failure. The installer first checks `SHA256SUMS` against its built-in digest, then checks each of the 13 files, and installs them to `/usr/local/bin/vps-hardening` and `/usr/local/lib/vps-hardening`. It only places files; it does not run preflight or apply ([detailed design §2.12](docs/detailed-design.md#212-安装脚本)).

**Release attestation.** Immutable releases were enabled for this repository on 2026-11-20. Releases published since then (from `v0.2.0-rc.2` on) cannot have their assets or tags changed, and their GitHub release attestation can be checked with `gh release verify <tag>`, for example `gh release verify v0.2.1`. `v0.2.0-rc.1` and earlier releases predate this protection; rely on the digests on their release pages (requirements D71).

**Other versions.** Each release page lists its own install command and digest ([Releases](https://github.com/alieismy/vps-hardening/releases)). The README inside the `v0.2.1` tag and its source archives is a pre-release snapshot whose install example still points to `v0.2.0`; to install `v0.2.1`, use the command above.

**Running from the repository (development version).** The repository's `install.sh` is not bound to a release and refuses to run. You can run `bin/vps-hardening` directly instead: while a change is pending, the automatic restore calls it by that path, so do not move or delete the repository directory before confirming.

## Usage

Below, **P** is the **local listening port** on the VPS as verified by preflight, and **E** is the **public SSH port** verified by the administrator; clients connect with `ssh -p <public SSH port> root@vps`. When the provider maps ports outside the VPS, E can differ from P; the local UFW and Fail2ban still use P, and the cloud security group and the mapping are the administrator's responsibility. DNAT, forwarding and container networking on the VPS itself are out of scope.

On a fresh VPS, after logging in as root with a key through the verified public endpoint:

1. **Preflight**: `vps-hardening preflight`. Check the reported P, the listen addresses and address families, and the activation mode (service or socket). Preflight verifies the SSH endpoint from sshd's effective configuration, its startup arguments and the actual listeners; it does not just read the first `Port` in the main configuration file, and it never treats an unknown value as 22. If the endpoint cannot be verified, has several effective ports or is inconsistent, preflight refuses before any change. This tool only checks public keys and never writes them; a key that cloud-init wrote for root with a `command=` prefix does not count as usable. If `/var/run/reboot-required` exists, preflight warns but does not block apply; rebooting first is recommended.
2. **Apply**: `vps-hardening apply`. Make sure the current session stays open and the provider's console is available, then type `yes`. UFW then allows only P/tcp. You can also declare public ports at hardening (`--open 443/tcp --open 2096/tcp`), provided they do not conflict with P or the panel port.
3. **Confirm**: keep the current session, open another terminal, log in as root with the key through the verified public port E, and run `vps-hardening confirm`. Confirm checks the identity of the new session, that the current full endpoint matches the recorded baseline, and that the session actually connected to local port P. If any endpoint check fails or cannot be verified, it exits with 1, keeps the pending state and the existing restore mechanisms, and does not extend the deadline. The time limit is 10 minutes by default (`--confirm-timeout` accepts 3 to 60 minutes); if it expires without confirmation, or the host reboots before then, the snapshot is restored.
4. **Verify**: run `vps-hardening verify` at any time for a read-only check. This still applies after 3X-UI is installed: drift such as a non-loopback listener on the panel port recorded at apply, the `3x-ipl` jail or Fail2ban configuration changes that appear when IP Limit is enabled, use of the BBR menu, or the firewall menu changing UFW is reported as non-compliant. The panel listener check covers only the recorded panel port: if the panel moves to another port, `verify` reports a warning because the recorded port has no listener, and it cannot check the new port's listen address. `verify` also does not read the IP limit settings of 3X-UI clients; IP Limit must stay off ([requirements §8](docs/requirements.md#8-范围外p3)).
5. **Open ports after installing 3X-UI**: open the inbound and subscription ports, which must not conflict with P: `vps-hardening ports --add 443/tcp --add 2096/tcp`. As with apply, run `confirm` from a new SSH session within the time limit, or the previous ports are restored; run `verify` after confirming. Do not open ports with the 3X-UI firewall menu.

The panel is reached only through an SSH tunnel. The output of `apply`, `confirm` and `status` contains a tunnel command with the placeholder `<公网SSH端口>` (public SSH port); replace it with the verified E before use. Local checks and restore results alone do not prove that the host is reachable from the internet.

### Commands

| Command | Purpose |
|---|---|
| `preflight` | Read-only preflight: checks the platform, the input and the fresh-host conditions without changing the system |
| `verify` | Read-only verification: checks the hardening item by item without changing the system |
| `apply` | Applies the hardening (interactive), then enters the pending state; on an applied host, running it again with the same arguments only checks and changes nothing |
| `confirm` | Confirms the result of `apply` or `ports` as root from a new SSH session |
| `status` | Shows the state, the change log, the confirmation deadline and the panel tunnel command (read-only) |
| `rollback` | Restores the configuration from before `apply` (interactive), including the previous password authentication (the pre-rollback check warns about it); packages this tool installed are kept |
| `ports` | Adds or removes public ports (interactive), for example `ports --add 8443/tcp --remove 2096/tcp`; removals are applied before additions, then the pending state starts |
| `update-fail2ban` | After a host hardened by `v0.2.0` or earlier is upgraded, changes Fail2ban's `journalmatch` to the current value (interactive); see [Upgrading](#upgrading) |

| Option | Commands | Description |
|---|---|---|
| `--panel-port PORT` | `preflight`, `apply` | 3X-UI panel port, reached only through an SSH tunnel (default 2053) |
| `--open PORT/PROTO[/FAM]` | `preflight`, `apply` | Public port; PROTO is `tcp` or `udp`, FAM is `both`, `ipv4` or `ipv6`; repeatable |
| `--add PORT/PROTO[/FAM]`, `--remove PORT/PROTO[/FAM]` | `ports` | Adds or removes a public port; repeatable; at least one is required |
| `--confirm-timeout MIN` | `preflight`, `apply`, `ports` | Confirmation time limit, 3 to 60 minutes (default 10) |

Exit codes: `0` all checks pass; `1` non-compliant items found; `2` usage or input error; `3` internal error. `vps-hardening --help` shows the help and `--version` the version. The full command contract is in [detailed design §2](docs/detailed-design.md#2-命令契约).

### Port conflicts and drift

P must not share a number with the panel port or a service port, and TCP versus UDP cannot be used to get around a conflict of purpose; P=80 is refused. SSH itself may use 443 or 2096, but the same number cannot then be assigned to the proxy or the subscription. `ports --add/--remove` must not include P; when P≠22, service port 22 can be added or removed on its own. `verify`, a repeated `apply`, `ports` and `confirm` compare against the recorded baseline; drift they detect is neither adopted as a new port nor fixed automatically. Keep the console available while investigating.

### Restore

A restore first makes a best effort to restore the managed files and services, then checks the local endpoint. If the runtime endpoint is inconsistent or cannot be verified, it reports a failed restore, `rollback` returns 1, and the snapshot, the markers and any remaining boot-time fallback are kept; a timer that was already stopped when the restore began is not restarted automatically. The boot-time restore runs before SSH starts and records the endpoint as unverified; after the service starts, still run `verify` and log in from a new external session.

## Upgrading

Reinstall with the install command from the new release's page. The installer only replaces the program files; it does not run preflight or apply.

- **While a change is pending**: the installer refuses to upgrade. Confirm the change with the old tool first, or wait for the restore.
- **From `v0.1.0`–`v0.2.0` to `v0.2.1`**: `verify` warns about Fail2ban's old `journalmatch`. Run `vps-hardening update-fail2ban`; it rewrites only this tool's jail file and its recorded digest, then restarts Fail2ban. Until then, Fail2ban keeps the old value and occasionally needs one more failed attempt before it bans (requirements D84, [detailed design §8.36](docs/detailed-design.md#836-vt-33-偶发少计的原因需求-d79)).
- **From `v0.1.1` or earlier**: if an account whose shell is not listed in `/etc/shells` has a public key and passwordless sudo, `verify` reports `accounts.nopasswd` as non-compliant after the upgrade; roll back and apply again.
- **State record format**: since `v0.2.0-rc.2` the state record carries a format number, `record_format`. If the host's record format is newer than the version being installed can read, the installer refuses (requirements D70). Records written by `v0.2.0-rc.1` lack this field and are read as format 2. When a record from an earlier published version lacks fields such as P, it is read for compatibility, read-only, only if the old format, the source version, the original jail's port-22 baseline and the current SSH endpoint can all be verified; missing fields are never written back or guessed. A complete new record is produced by a full rollback followed by a new apply.
- **Downgrading**: downgrading a host hardened by `v0.2.1`, or one where `update-fail2ban` has run, to `v0.2.0` or earlier is not supported ([detailed design §9](docs/detailed-design.md#9-已知限制与后续)).

## Companion repositories and order

The three repositories are used in the order of the table below: harden first, then tune, then set up the proxy (requirements D27; rationale in [requirements §7.3](docs/requirements.md#73-与-vps-tuning-的约定)).

| Order | Repository | Purpose | Status |
|---|---|---|---|
| 1 | vps-hardening (this repository) | Baseline security hardening | Release v0.2.1 |
| 2 | [vps-tuning](https://github.com/alieismy/vps-tuning) | Network tuning, diagnostics and measurement | Pre-release |
| 3 | [vps-proxy-setup](https://github.com/alieismy/vps-proxy-setup) | Proxy service setup (3X-UI as the example) | Requirements stage (created 2026-10-25) |

Full flow (requirements D27, D41, D42):

1. **Preparation**: update the system, install basic tools and reboot; done by the administrator (see step 1 of [Installation](#installation));
2. **vps-hardening**: harden and confirm; UFW allows only the verified P/tcp;
3. **vps-tuning**: tune (apply → reboot → verify);
4. **vps-proxy-setup**: install and configure 3X-UI, then open its ports with `vps-hardening ports` and confirm;
5. **Final checks**: vps-tuning's strict verification (requires the proxy service to be running); after a reboot, check again with `vps-hardening verify`, the strict tuning verification and a proxy client connection.

Apply and reboot for tuning only after the hardening is confirmed: a reboot before confirmation automatically undoes the hardening.

## Confirmed scope

Confirmed on 2026-10-10 and revised up to 2026-11-20; the [requirements specification](docs/requirements.md) uses this as its upstream basis, and the Chinese table in [README.zh-CN.md](README.zh-CN.md#已确认的范围) is the authoritative version. The D numbers are decisions recorded in section 2.2 of the requirements specification.

| Item | Decision |
|---|---|
| SSH port | Keep the single local SSH management port P on the VPS, verified read-only, open to all sources; 22 is the reference default. Keep the existing listen addresses, address families and service/socket activation; the port is never migrated automatically. Listening on all IPv4 addresses is required; with no IPv6 listener there is only a warning. If the endpoint cannot be verified, has several effective ports or is inconsistent, the tool refuses before any change (D64) |
| SSH authentication | Key-only login; root is the administrative account and may log in with a key only (`PermitRootLogin prohibit-password`); no separate administrative user is created. The administrator configures root's public key in advance, and preflight requires at least one usable key (since 2026-10-20, replacing the earlier "deny root login, use a regular sudo user") |
| Firewall | Enable UFW: deny incoming, allow outgoing, deny routed. At hardening only P/tcp is opened; the proxy inbound port (such as 443/tcp) and the subscription port (such as 2096/tcp) are opened with `vps-hardening ports` when 3X-UI is installed (D41, D64). When P≠22, 22 is not opened automatically; if 22 is explicitly declared as a service port, it is managed as an ordinary rule. 80/tcp is not opened; certificates are issued by the proxy repository through DNS-01 with a Cloudflare API token |
| 3X-UI panel | Reached only through an SSH tunnel: `ssh -p <public SSH port> -L 8443:127.0.0.1:<panel port> root@vps`; the panel port defaults to 2053. UFW does not open the panel port, the panel listens only on 127.0.0.1 (set by the proxy repository), and no `ADMIN_CIDRS` allowlist is used (since 2026-10-13, replacing the earlier allowlist approach) |
| Fail2ban | Included; protects only SSH on the recorded P, and the jail and the actual ban action use the same P. The configuration follows the sample in section 16.1 of the user's production 3X-UI plan, and the ignore list contains only loopback addresses; filter mode `normal`, `maxretry` fixed at 5 (changed 2026-10-20; see requirements FR-08) |
| Automatic security updates | Included; on Debian, stable point-release updates are also installed automatically (as in Debian's default); no automatic reboot; the verify command reports when a reboot is required |
| Target platforms | The same distributions as vps-tuning: Debian 12/13, Ubuntu 24.04 LTS. Architecture x86_64; ARM64 as a reference: the tool runs, and tests run on demand (changed 2026-10-20). Since `v0.2.0-rc.2` the kernel must have an IPv6 stack; hosts booted with `ipv6.disable=1` are refused by preflight (requirements D69) |
| Image default user | If it has passwordless sudo, the account is denied SSH login |
| Eligible hosts | Hosts from general VPS providers, not virtual machines from large cloud vendors such as Oracle Cloud or AWS (requirements D67). Fresh hosts only, hardened before 3X-UI is installed; existing hosts already running 3X-UI are out of scope. Since `v0.2.0-rc.2`, hosts with `nftables.service`, `netfilter-persistent` or `firewalld` enabled or running are also refused as existing hosts (requirements D68) |
| Delivery | A single-command tool, `vps-hardening`, run on the VPS itself, providing preflight, apply, verify and rollback, with no control machine; after apply, the change must be confirmed from a new SSH session within 10 minutes (configurable from 3 to 60), or it is restored automatically |
| 3X-UI coexistence baseline | v3.10.2 (since 2026-10-21, replacing v3.7.0, requirements D32): install with the version argument `v3.10.2`; the upstream install script fetches the menu script from the same tag, so `/usr/bin/x-ui` no longer needs replacing. Set `XUI_ENABLE_FAIL2BAN=false` and preset the panel port with `XUI_PANEL_PORT`; do not use 3X-UI's firewall or BBR menus. Existing hosts with v3.7.0 installed are not bound by this; for what v3.10.2's bundled Xray requires of REALITY clients, see section 7.2 of the requirements specification |

## Project status

- **Release**: `v0.2.1` was published on 2026-11-22 (UTC) and set as Latest; its code is that of pre-release `v0.2.1-rc.1` with only the version changed.
- **CI**: before release, both the pull request and master passed the 30-job test matrix in amd64 virtual machines on Debian 12, Debian 13 and Ubuntu 24.04, as well as the static checks. The 15 public assets, downloaded anonymously, matched the build, and the GitHub release attestation verifies.
- **Real VPS**: `v0.2.x` has been accepted on a single real host, an already-hardened Debian 13 host on the provider's preset non-22 port, through in-place incremental acceptance and upgrades; after the upgrade to `v0.2.1`, `verify` passed all 44 checks. First-time preflight, apply and confirm on a fresh host have not been done with `v0.2.x` on a real VPS; they rely on VM evidence. Real-host acceptance of `v0.1.x` (M5) was done on a freshly installed Debian 13 test VPS.
- **Not covered**: Debian 12 and Ubuntu 24.04 have VM evidence only; arm64 is a reference only and was not run for `v0.2.1`; the external IPv6 path and real provider NAT have not been accepted.

Changes in each version are listed under [Releases](https://github.com/alieismy/vps-hardening/releases). The full records of releases, CI and acceptance are in [detailed design §8](docs/detailed-design.md#8-运行证据), and the known limitations in [§9](docs/detailed-design.md#9-已知限制与后续).

## Documentation

The documents are in Chinese.

| Document | Contents |
|---|---|
| [Requirements specification](docs/requirements.md) | Functional requirements (FR), non-functional requirements, cross-repository agreements, and the record of user statements (U) and confirmed decisions (D) |
| [Solution design](docs/solution-design.md) | Components, boundaries, flows and key mechanisms |
| [Detailed design](docs/detailed-design.md) | Command contract, check items, module layout, test framework, run evidence and known limitations |
| [Verification plan](docs/verification-plan.md) | What is verified, where, and how a pass is judged (test items are numbered VT) |

Each document's version and review status are in the table at its top.

## Feedback

Report bugs and suggestions in [GitHub Issues](https://github.com/alieismy/vps-hardening/issues). Do not report security vulnerabilities in Issues; report them privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT License](LICENSE)
