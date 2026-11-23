# 安全策略 / Security Policy

[中文](#中文) | [English](#english)

## 中文

### 支持的版本

只有最新的正式版（[Releases](https://github.com/alieismy/vps-hardening/releases) 中标为 Latest 的版本）接收安全修复。修复随新版本发布，不回移到更早的版本或预发行版。

| 版本 | 接收安全修复 |
|---|---|
| 最新正式版 | 是 |
| 更早的正式版、所有预发行版 | 否，请升级到最新正式版 |

### 报告漏洞

请不要在公开的 Issue 或拉取请求中报告漏洞。请使用 GitHub 的私密漏洞报告：打开 [Report a vulnerability](https://github.com/alieismy/vps-hardening/security/advisories/new) 填写，报告只有维护者能看到。中文或英文均可。

报告请尽量包含：

- 受影响的版本（`vps-hardening --version`）和发行版；
- 问题和影响，例如绕过只允许密钥登录、UFW 放行了未声明的端口、自动恢复失效导致管理员被锁在外面、安装器的摘要校验被绕过；
- 复现步骤或概念验证；
- 已知的缓解办法。

请不要在报告中附上私钥、令牌、主机地址等敏感信息，必要的日志请先脱敏。

维护者会在私密报告中确认问题、沟通进展；确认的漏洞在修复版本发布后，通过 GitHub 安全公告公开。

### 范围

范围内：本仓库的代码（`bin/`、`lib/`、`install.sh`）和发行版资产。

范围外：

- OpenSSH、UFW、Fail2ban、unattended-upgrades、3X-UI 等上游组件自身的漏洞，请报告给相应的项目；
- 需要事先取得目标主机 root 权限才能利用的问题：`confirm` 等检查防的是误操作，不防有意绕过的 root（[方案设计第 7.5 节](docs/solution-design.md#75-防锁死与确认fr-05)）；
- [适用范围](README.md#适用范围)中明确不做的事项，以及[详细设计第 9 节](docs/detailed-design.md#9-已知限制与后续)已记录的已知限制，除非你发现了新的利用方式。

## English

### Supported versions

Only the latest release (the one marked Latest under [Releases](https://github.com/alieismy/vps-hardening/releases)) receives security fixes. Fixes ship in a new release and are not backported to earlier versions or pre-releases.

| Version | Security fixes |
|---|---|
| Latest release | Yes |
| Earlier releases, all pre-releases | No; upgrade to the latest release |

### Reporting a vulnerability

Do not report vulnerabilities in public issues or pull requests. Use GitHub private vulnerability reporting: open [Report a vulnerability](https://github.com/alieismy/vps-hardening/security/advisories/new) and fill in the form; only the maintainers can see the report. Reports in English or Chinese are welcome.

Please include, where possible:

- the affected version (`vps-hardening --version`) and distribution;
- the problem and its impact, for example bypassing key-only login, UFW allowing an undeclared port, the automatic restore failing so that the administrator is locked out, or bypassing the installer's digest check;
- steps to reproduce or a proof of concept;
- any known mitigation.

Do not attach private keys, tokens, host addresses or other sensitive data; redact logs before sharing them.

The maintainers will confirm the issue and share progress in the private report. Confirmed vulnerabilities are disclosed through a GitHub security advisory after the fixed release is published.

### Scope

In scope: the code in this repository (`bin/`, `lib/`, `install.sh`) and the release assets.

Out of scope:

- vulnerabilities in upstream components such as OpenSSH, UFW, Fail2ban, unattended-upgrades or 3X-UI; report them to those projects;
- issues that require root on the target host beforehand: checks such as `confirm` guard against mistakes, not against a root user deliberately bypassing them ([solution design §7.5](docs/solution-design.md#75-防锁死与确认fr-05));
- what the [Scope](README.en.md#scope) section explicitly excludes, and the known limitations recorded in [detailed design §9](docs/detailed-design.md#9-已知限制与后续), unless you have found a new way to exploit them.
