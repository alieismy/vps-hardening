# VPS Hardening

简体中文 | [English](README.en.md)

[![Latest release](https://img.shields.io/github/v/release/alieismy/vps-hardening)](https://github.com/alieismy/vps-hardening/releases/latest)
[![static](https://github.com/alieismy/vps-hardening/actions/workflows/static.yml/badge.svg?branch=master)](https://github.com/alieismy/vps-hardening/actions/workflows/static.yml)
[![vm](https://github.com/alieismy/vps-hardening/actions/workflows/vm.yml/badge.svg?branch=master)](https://github.com/alieismy/vps-hardening/actions/workflows/vm.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

为 Debian/Ubuntu VPS 提供基础安全加固，包括：SSH 只允许密钥登录（root 作为管理账户，只能用密钥登录）、UFW 只开放必要端口、Fail2ban，以及自动安全更新。目标是在不明显增加日常管理负担的前提下缩小暴露面，同时避免把管理员锁在服务器外。

**当前正式版：[`v0.2.1`](https://github.com/alieismy/vps-hardening/releases/tag/v0.2.1)（2026-11-22 UTC）。** 由 `v0.1.0`～`v0.2.0` 加固的主机，升级后须执行一次 `vps-hardening update-fail2ban`，见[升级](#升级)。

## 功能

- **SSH**：只允许密钥登录，root 只能用密钥登录（`PermitRootLogin prohibit-password`）；除 root 外，有免密 sudo 的账户（例如镜像默认用户）禁止经 SSH 登录，它的 sudo 规则不改动。保留服务商预设的单一 SSH 管理端口，包括非 22 端口，不迁移端口。
- **UFW**：默认拒绝入站、允许出站、拒绝转发；加固时只放行 SSH 端口，其他公开端口按声明开放。
- **Fail2ban**：只保护 SSH，`maxretry` 为 5，白名单只含回环地址。
- **自动安全更新**：启用 unattended-upgrades，不自动重启；需要重启时由 `verify` 报告。
- **防锁死**：`apply` 和 `ports` 之后须在时限内（默认 10 分钟）从新的 SSH 会话确认；到期未确认，或在此之前重启，都会按快照自动恢复。
- **只读核对与回滚**：`preflight` 在变更前检查主机，`verify` 随时核对加固结果和漂移，`rollback` 恢复到应用前的配置。

## 适用范围

| 项目 | 支持 |
|---|---|
| 发行版 | Debian 12、Debian 13、Ubuntu 24.04 LTS |
| 架构 | x86_64；arm64 只作参考，工具可以运行，测试按需执行 |
| 主机 | 一般 VPS 服务商的新机，在安装 3X-UI 之前加固；不含 Oracle Cloud、AWS 等大型云厂商的虚拟机 |

只支持新机：已运行 3X-UI 的存量主机不在范围内，启用或运行 `nftables.service`、`netfilter-persistent` 或 `firewalld` 的主机也按存量主机拒绝。内核以 `ipv6.disable=1` 启动的主机在预检中拒绝。

范围限定为基础加固，不做 CIS 全量合规、入侵检测、AppArmor/SELinux 策略或审计系统。本仓库不安装代理服务，也不做网络性能调优。各项设计决定见[已确认的范围](#已确认的范围)。

## 安装

前提：root 已配置可用的公钥（一般在服务商管理页面绑定 SSH 密钥即可），能以 root 用密钥登录，服务商控制台可用。

1. 更新系统、安装基础工具并重启。本工具不执行这一步：

   ```bash
   apt update
   apt -s full-upgrade   # 只模拟，查看升级计划
   apt full-upgrade -y
   apt install -y curl wget ca-certificates gnupg lsb-release unzip vim nano htop ufw jq iproute2 procps kmod util-linux python3
   apt autoremove        # 清理自动安装且不再需要的软件包
   reboot
   ```

   软件包按需增减，但须保留官方仓库的 `python3`（预检只用标准库解析 SSH 入口）和 systemd 配套的 `busctl`：缺少任一个时，预检在变更前拒绝。只安装 `ufw`、不启用也不添加规则时，主机仍是新机；这一步不要安装 Docker 或 3X-UI，也不要启用其他防火墙服务。

2. 安装 `v0.2.1`：

   ```bash
   curl --disable --fail --location --proto '=https' --proto-redir '=https' \
     https://github.com/alieismy/vps-hardening/releases/download/v0.2.1/install.sh \
     -o install.sh &&
   echo '32110ed9ce8ef815a1e3cc5f3ebc3db1dd94eba3cd14e3e6fbde7ac392f3cc70  install.sh' | sha256sum -c - &&
   bash install.sh
   ```

   下载和摘要校验都成功后才执行安装器，任一步失败即停止。安装器先用内置的摘要校验 `SHA256SUMS`，再逐个校验 13 个文件，然后安装到 `/usr/local/bin/vps-hardening` 和 `/usr/local/lib/vps-hardening`；它只放置文件，不执行预检或应用（[详细设计第 2.12 节](docs/detailed-design.md#212-安装脚本)）。

**发行版证明。** 仓库于 2026-11-20 启用不可变发行版，此后发布的发行版（自 `v0.2.0-rc.2` 起）资产和标签不能再修改，可以用 `gh release verify <标签>` 核对 GitHub 的发行版证明，例如 `gh release verify v0.2.1`。`v0.2.0-rc.1` 及更早的发行版不受这项保护，以各自发布页上的摘要校验为准（需求 D71）。

**其他版本。** 各版本的安装命令和摘要见各自的[发布页](https://github.com/alieismy/vps-hardening/releases)。`v0.2.1` 标签及其源码归档中的 README 是发布前的快照，其中的安装示例仍指向 `v0.2.0`；安装 `v0.2.1` 请使用上面的命令。

**从仓库运行（开发版）。** 仓库中的 `install.sh` 没有绑定发行版，执行时拒绝。也可以直接运行 `bin/vps-hardening`：待确认期间，自动恢复按这个路径调用它，所以确认之前不要移动或删除仓库目录。

## 使用方法

下文的 **P** 指预检核实的 VPS **本机监听端口**；**E** 指管理员核实的**公网 SSH 端口**，客户端使用 `ssh -p <公网SSH端口> root@vps`。服务商在 VPS 外做端口映射时，E 可以不同于 P，本机 UFW 和 Fail2ban 仍使用 P；云端安全组及映射由管理员维护。VPS 本机 DNAT、转发及容器网络不在范围内。

在新的 VPS 上，以 root 用密钥经已经核实的公网入口登录后：

1. **预检**：`vps-hardening preflight`。核对报告的 P、监听地址和地址族、启动方式（service 或 socket）。预检综合 sshd 的有效配置、启动参数和实际监听核实 SSH 入口，不只读主配置中的首个 `Port`，也不会把未知值当作 22；无法核实、有效多端口或入口不一致时在变更前拒绝。本工具只检查、不写入公钥；cloud-init 写给 root、带 `command=` 前缀的公钥不算可用。存在 `/var/run/reboot-required` 时给出警告，不阻止应用，建议先重启。
2. **应用**：`vps-hardening apply`。确认已保留当前会话、服务商控制台可用后输入 `yes`。这时 UFW 只放行 P/tcp；也可以在加固时就声明公开端口（`--open 443/tcp --open 2096/tcp`），前提是这些端口与 P、面板端口不冲突。
3. **确认**：保持当前会话，另开一个终端，经核实的公网 E 用 root 的密钥登录后执行 `vps-hardening confirm`。确认会检查新会话身份、当前完整入口与记录基线一致，以及该会话实际连接的本机端口为 P；任一入口检查不符或无法核实时，退出码为 1，保留待确认状态和已有恢复机制，不延长截止时间。确认时限默认 10 分钟（`--confirm-timeout` 可设 3～60 分钟）；到期未确认，或在此之前重启，都会按快照恢复。
4. **验证**：之后可随时用 `vps-hardening verify` 只读核对。安装 3X-UI 之后同样适用：应用时记录的面板端口上有非回环地址的监听、启用 IP Limit 后出现的 `3x-ipl` jail 或 Fail2ban 配置改动、用过 BBR 菜单、防火墙菜单改动了 UFW 等漂移都会报告为不符合。面板监听只核对记录中的面板端口：面板改用其他端口后，原端口上没有监听时报告警告，新端口的监听地址无法核对。`verify` 也不读取 3X-UI 客户端的 IP 数限制设置，IP Limit 须保持关闭（[需求规格说明第 8 节](docs/requirements.md#8-范围外p3)）。
5. **安装 3X-UI 之后开放端口**：开放与 P 不冲突的入站端口和订阅端口，`vps-hardening ports --add 443/tcp --add 2096/tcp`。与应用一样，须在时限内从新的 SSH 会话执行 `confirm`，否则恢复原端口；确认后执行 `verify`。不要用 3X-UI 的防火墙菜单开放端口。

面板只经 SSH 隧道访问，`apply`、`confirm` 和 `status` 的输出中有带 `<公网SSH端口>` 占位符的隧道命令，使用前替换为管理员核实的 E。本机检查和恢复结果不能单独证明公网可达。

### 命令

| 命令 | 作用 |
|---|---|
| `preflight` | 只读预检：检查平台、输入和新机条件，不改变系统 |
| `verify` | 只读验证：逐项核对加固结果，不改变系统 |
| `apply` | 应用加固（交互执行），结束后进入待确认；已应用的主机上用相同参数再次执行只做核对，不做变更 |
| `confirm` | 在新的 SSH 会话中以 root 确认 `apply` 或 `ports` 的结果 |
| `status` | 显示状态、变更记录、确认截止时间和面板隧道命令（只读） |
| `rollback` | 恢复到应用前的配置（交互执行），包括应用前的密码认证（回滚前检查会警告）；本工具安装的软件包保留 |
| `ports` | 增减公开端口（交互执行），例如 `ports --add 8443/tcp --remove 2096/tcp`；先撤销后增加，结束后进入待确认 |
| `update-fail2ban` | 由 `v0.2.0` 及以前的版本加固的主机升级后，把 Fail2ban 的 `journalmatch` 改为当前值（交互执行），见[升级](#升级) |

| 参数 | 适用命令 | 说明 |
|---|---|---|
| `--panel-port PORT` | `preflight`、`apply` | 3X-UI 面板端口，只经 SSH 隧道访问（默认 2053） |
| `--open PORT/PROTO[/FAM]` | `preflight`、`apply` | 公开端口，PROTO 为 `tcp` 或 `udp`，FAM 为 `both`、`ipv4` 或 `ipv6`，可重复 |
| `--add PORT/PROTO[/FAM]`、`--remove PORT/PROTO[/FAM]` | `ports` | 增加或撤销公开端口，可重复，至少给出一个 |
| `--confirm-timeout MIN` | `preflight`、`apply`、`ports` | 确认时限，3～60 分钟（默认 10） |

退出码：`0` 全部通过；`1` 有不符合项；`2` 用法或输入错误；`3` 内部错误。`vps-hardening --help` 显示帮助，`--version` 显示版本；完整的命令契约见[详细设计第 2 节](docs/detailed-design.md#2-命令契约)。

### 端口冲突与漂移

P 不能与面板或业务端口同号，TCP/UDP 不用于绕过用途冲突；P=80 拒绝。SSH 使用 443 或 2096 本身可用，但不能再把同号端口分配给代理或订阅。`ports --add/--remove` 不得包含 P；P≠22 时，业务端口 22 可单独增减。`verify`、再次 `apply`、`ports` 和 `confirm` 比对记录基线，发现漂移不会重新采用新端口或自动修复；排查时保留控制台入口。

### 恢复

恢复先尽力完成受管文件和服务恢复，再核对本机入口。运行期入口不一致或无法核实时报告“恢复失败”，`rollback` 返回 1，保留快照、标记及尚存的开机兜底；恢复开始时已停止的定时器不会自动重计时。开机恢复在 SSH 启动前执行，入口记为未验证，服务启动后仍须 `verify` 及外部新会话登录验收。

## 升级

用新版本发布页上的安装命令重新安装。安装器只替换程序文件，不执行预检或应用。

- **待确认期间**：安装器拒绝升级，须先用旧工具完成确认或等待恢复。
- **从 `v0.1.0`～`v0.2.0` 升级到 `v0.2.1`**：`verify` 对 Fail2ban 旧的 `journalmatch` 报告警告。执行 `vps-hardening update-fail2ban`，它只改写本工具的 jail 文件和它的记录摘要，然后重启 Fail2ban；执行之前，Fail2ban 仍按旧值工作，偶尔要多失败一次才封禁（需求 D84，[详细设计第 8.36 节](docs/detailed-design.md#836-vt-33-偶发少计的原因需求-d79)）。
- **从 `v0.1.1` 及更早的版本升级**：shell 没有登记在 `/etc/shells` 中、有公钥和免密 sudo 的账户，升级后 `verify` 报告 `accounts.nopasswd` 不符合，回滚后重新应用即可。
- **状态记录格式**：自 `v0.2.0-rc.2` 起，状态记录带格式编号 `record_format`；主机的记录格式高于要安装的版本能读取的格式时，安装器拒绝安装（需求 D70）。`v0.2.0-rc.1` 写的记录没有这个字段，按格式 2 读取。已发布旧版的记录缺少 P 等字段时，仅在旧格式、来源版本、原 jail 的 22 基线以及当前 SSH 入口均能核实的条件下只读兼容，不回写或猜测缺失字段；完整的新记录由完整回滚后重新应用生成。
- **降级**：由 `v0.2.1` 加固或已执行 `update-fail2ban` 的主机，降级到 `v0.2.0` 及更早的版本不受支持（[详细设计第 9 节](docs/detailed-design.md#9-已知限制与后续)）。

## 配套仓库与执行顺序

三个仓库按下表的顺序使用：先加固，再调优，最后搭建代理（需求 D27；理由见[需求规格说明第 7.3 节](docs/requirements.md#73-与-vps-tuning-的约定)）。

| 顺序 | 仓库 | 用途 | 状态 |
|---|---|---|---|
| 1 | vps-hardening（本仓库） | 基础安全加固 | 正式版 v0.2.1 |
| 2 | [vps-tuning](https://github.com/alieismy/vps-tuning) | 网络调优、诊断与测量 | Pre-release |
| 3 | [vps-proxy-setup](https://github.com/alieismy/vps-proxy-setup) | 代理服务搭建（以 3X-UI 为例） | 需求阶段（2026-10-25 创建） |

完整流程（需求 D27、D41、D42）：

1. **准备**：更新系统、安装基础工具并重启，由管理员执行（见[安装](#安装)第 1 步）；
2. **vps-hardening**：加固并确认，UFW 只放行已核实的 P/tcp；
3. **vps-tuning**：调优（应用 → 重启 → 验证）；
4. **vps-proxy-setup**：安装并配置 3X-UI，然后用 `vps-hardening ports` 开放它的端口并确认；
5. **收尾验证**：vps-tuning 的严格验证（要求代理服务已运行）；重启后再用 `vps-hardening verify`、调优的严格验证和代理客户端连接复核。

调优的应用和重启要在加固确认之后进行，确认前重启会自动撤销加固。

## 已确认的范围

2026-10-10 确认，后续修订至 2026-11-20；[需求规格说明](docs/requirements.md)以此为上游依据。表中的 D 编号是需求规格说明第 2.2 节记录的决定。

| 项目 | 决定 |
|---|---|
| SSH 端口 | 保留只读核实的 VPS 本机单一 SSH 管理端口 P，对所有来源开放；22 是默认端口对照。保留既有监听地址、地址族和 service/socket 启动方式，不自动迁移端口。IPv4 全地址监听必需，无 IPv6 监听时只警告；无法核实、有效多端口或入口不一致时在变更前拒绝（D64） |
| SSH 认证 | 只允许密钥登录；root 是管理账户，只能用密钥登录（`PermitRootLogin prohibit-password`），不另建管理用户。root 的公钥由管理员事先配置，预检要求至少有一把可用的公钥（2026-10-20 起替代原先的"禁止 root 登录、使用普通 sudo 用户"） |
| 防火墙 | 启用 UFW：默认拒绝入站、允许出站、拒绝转发。加固时只开放 P/tcp，代理入站（如 443/tcp）和订阅端口（如 2096/tcp）在安装 3X-UI 时用 `vps-hardening ports` 开放（D41、D64）。P≠22 时不自动放行 22；显式声明 22 为业务端口时按普通规则管理。80/tcp 不开放，证书由代理仓库用 Cloudflare API Token 走 DNS-01 签发 |
| 3X-UI 面板 | 只经 SSH 隧道访问：`ssh -p <公网SSH端口> -L 8443:127.0.0.1:<面板端口> root@vps`，面板端口默认 2053。UFW 不放行面板端口，面板只监听 127.0.0.1（由代理仓库设置），不使用 `ADMIN_CIDRS` 白名单（2026-10-13 起替代原先的白名单方案） |
| Fail2ban | 纳入，只保护记录 P 上的 SSH，jail 与实际封禁动作使用同一 P；配置采用用户现网 3X-UI 方案第 16.1 节的样例，白名单只含回环地址；过滤模式为 `normal`，`maxretry` 固定为 5（2026-10-20 修改，见需求说明 FR-08） |
| 自动安全更新 | 纳入；Debian 同时自动安装稳定版小版本更新（与 Debian 默认一致）；不自动重启，需要重启时由验证命令报告 |
| 目标平台 | 发行版与 vps-tuning 一致：Debian 12/13、Ubuntu 24.04 LTS。架构为 x86_64；ARM64 作为参考，工具可以运行，测试按需执行（2026-10-20 修改）。自 `v0.2.0-rc.2` 起要求内核有 IPv6 协议栈，以 `ipv6.disable=1` 启动的主机在预检中拒绝（需求 D69） |
| 镜像默认用户 | 如果有免密 sudo，禁止该账户经 SSH 登录 |
| 适用主机 | 一般 VPS 服务商的主机，不含 Oracle Cloud、AWS 等大型云厂商的虚拟机（需求 D67）。只支持新机，在安装 3X-UI 之前执行；已运行 3X-UI 的存量主机不在范围内。自 `v0.2.0-rc.2` 起，启用或运行 `nftables.service`、`netfilter-persistent` 或 `firewalld` 的主机也按存量主机拒绝（需求 D68） |
| 交付形态 | 在 VPS 本机运行的单命令工具 `vps-hardening`，提供预检、应用、验证和回滚，不依赖控制端；应用后须在 10 分钟内（可设 3～60 分钟）从新的 SSH 会话确认，否则自动恢复 |
| 3X-UI 共存基线 | v3.10.2（2026-10-21 起替代 v3.7.0，需求 D32）：安装时带版本参数 `v3.10.2`，上游安装脚本从同一 tag 取得菜单脚本，不再需要替换 `/usr/bin/x-ui`；设 `XUI_ENABLE_FAIL2BAN=false`，用 `XUI_PANEL_PORT` 预先指定面板端口；不使用 3X-UI 的防火墙菜单和 BBR 菜单。已安装 v3.7.0 的现有主机不受此约束；v3.10.2 自带的 Xray 对 REALITY 客户端的要求见需求规格说明第 7.2 节 |

## 项目状态

- **发布**：正式版 `v0.2.1` 于 2026-11-22（UTC）发布并设为 Latest，代码与预发行版 `v0.2.1-rc.1` 相同，只改版本号。
- **CI**：发布前，拉取请求和 master 都在 Debian 12、Debian 13、Ubuntu 24.04 的 amd64 虚拟机中通过了 30 个作业的测试矩阵和静态检查；15 项公开资产匿名下载后与构建一致，GitHub 的发行版证明核对通过。
- **真实 VPS**：`v0.2.x` 只在一台已加固的 Debian 13 主机（服务商预设的非 22 端口）上做过原地增量验收和升级，升级到 `v0.2.1` 后 `verify` 44 项通过。新机上的首次预检、应用和确认没有用 `v0.2.x` 在真实 VPS 上做过，以虚拟机证据为准。`v0.1.x` 的真实主机验收（M5）在一台全新安装的 Debian 13 测试 VPS 上完成。
- **未覆盖**：Debian 12 和 Ubuntu 24.04 只有虚拟机证据；arm64 只作参考，`v0.2.1` 没有运行；外部 IPv6 路径和服务商真实 NAT 未验收。

各版本的变化见 [Releases](https://github.com/alieismy/vps-hardening/releases)；发布、CI 和验收的完整记录见[详细设计第 8 节](docs/detailed-design.md#8-运行证据)，已知限制见[第 9 节](docs/detailed-design.md#9-已知限制与后续)。

## 文档

| 文档 | 内容 |
|---|---|
| [需求规格说明](docs/requirements.md) | 功能需求（FR）、非功能需求、跨仓库约定，以及用户原话（U）和已确认决定（D）的记录 |
| [方案设计](docs/solution-design.md) | 组件、边界、流程和关键机制 |
| [详细设计](docs/detailed-design.md) | 命令契约、检查项、模块划分、测试框架、运行证据和已知限制 |
| [验证计划](docs/verification-plan.md) | 验证什么、在哪里验证、怎样判定通过（测试项编号为 VT） |

各文档的版本和评审状态见文档开头的表格。

## 反馈

问题和建议请提交到 [GitHub Issues](https://github.com/alieismy/vps-hardening/issues)。安全漏洞请不要提交到 Issues，按 [SECURITY.md](SECURITY.md) 私密报告。

## 许可证

[MIT License](LICENSE)
