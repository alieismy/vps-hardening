# VPS Hardening

Baseline security hardening for Debian/Ubuntu VPS. **Status: pre-release [v0.1.0-rc.4](https://github.com/alieismy/vps-hardening/releases/tag/v0.1.0-rc.4) (milestones M1–M4: read-only checks, apply with automatic restore, Fail2ban values, coexistence with 3X-UI, status, rollback, port changes and the release installer; fixes for gaps found in the requirements review are included, v0.1.0-rc.2 fixes four issues found after v0.1.0-rc.1 was released, v0.1.0-rc.3 makes the recommended flow open only 22/tcp at hardening, and v0.1.0-rc.4 makes Fail2ban use this tool's values from its first start and fixes the installer's next-step hint). Tested in CI VMs; real-host acceptance (M5) passed on one freshly installed Debian 13 test VPS only, and the v0.1.0-rc.4 fixes were rechecked on the same host after a rollback — still a pre-release, do not use on production VPS.**

为 Debian/Ubuntu VPS 提供基础安全加固，包括：SSH 只允许密钥登录（root 作为管理账户，只能用密钥登录）、UFW 只开放必要端口、Fail2ban，以及自动安全更新。目标是在不明显增加日常管理负担的前提下缩小暴露面，同时避免把管理员锁在服务器外。

**当前状态：预发行版 [`v0.1.0-rc.4`](https://github.com/alieismy/vps-hardening/releases/tag/v0.1.0-rc.4)（2026-10-25），真实主机验收（M5）已在一台全新安装的 Debian 13 测试 VPS 上完成，`v0.1.0-rc.4` 的修复已在同一台主机上复核。** 已完成里程碑 M1～M3：只读的 `preflight`（预检）和 `verify`（验证），`apply`（应用）、`confirm`（确认）和自动恢复，以及 Fail2ban 生效值、自动更新和与 3X-UI 共存的验证。M4 已实现并经评审批准（需求 D38）：`status`（状态）、`rollback`（手工回滚）、`ports`（端口变更）、已应用的主机上再次 `apply` 只做核对，以及发行版安装脚本；3X-UI 共存基线改为 v3.10.2。评审需求时发现的三处缺口已修复并随预发行版发布，相应的文档（需求 v1.7、方案设计 v1.4、验证计划 v1.5、详细设计 v0.6）已批准（需求 D39）：sshd 配置中的 `Match` 块、`ufw status` 不显示的规则、规则的基线（需求 D34～D37）。`v0.1.0-rc.1` 发布后核实的四个问题列在它的发布说明中，已在 `v0.1.0-rc.2` 中修复（需求 D40）：带引号或含空格的 sshd 配置写法会让 `Match` 块漏查；重复安装不检查权限；安装中途失败或被中断时不恢复原来的文件。以上都在三个平台的 amd64 虚拟机测试中通过（arm64 作为参考，按需测试）。`v0.1.0-rc.3` 按需求 v1.9 调整推荐流程：加固时 UFW 只放行 22/tcp，安装 3X-UI 后再用 `ports` 开放它的端口；预检发现待重启时警告（需求 D41～D43）。真实主机验收（M5）在一台重装的 Debian 13 测试 VPS 上从公开地址安装 `v0.1.0-rc.3`，按验证计划第 5 节完成（[详细设计第 8.19 节](docs/detailed-design.md#819-真实主机验收m5)）。它没有覆盖 Fail2ban 的受控触发和外部 IPv6 路径；Debian 12 和 Ubuntu 24.04 只有虚拟机证据。`v0.1.0-rc.4` 修复了 M5 之后列出的两个问题（需求 D47）：由本工具安装 fail2ban 时，第一次启动就使用 FR-08 的值；安装脚本在新机上提示不带 `--open` 的 `preflight`。在这台测试 VPS 上回滚、卸载 3X-UI 之后，从公开地址安装 `v0.1.0-rc.4` 复核了这两项（[详细设计第 8.22 节](docs/detailed-design.md#822-测试-vps-上复核需求-d47-的修复)，需求 D50）。此前在这台测试 VPS 上的试运行和核对见[详细设计第 8.6 节](docs/detailed-design.md#86-测试-vps-上的试运行)、[第 8.8 节](docs/detailed-design.md#88-测试-vps-上的-m3-核对)、[第 8.9 节](docs/detailed-design.md#89-测试-vps-上的-d27-顺序演练)、[第 8.11 节](docs/detailed-design.md#811-测试-vps-上的-m4-核对)；发布和公开下载的回验见[第 8.14 节](docs/detailed-design.md#814-预发行版和-vt-72-的公开部分)、[第 8.16 节](docs/detailed-design.md#816-预发行版-v010-rc2-和-vt-72-的公开部分)、[第 8.18 节](docs/detailed-design.md#818-预发行版-v010-rc3-和-vt-72-的公开部分)、[第 8.21 节](docs/detailed-design.md#821-预发行版-v010-rc4-和-vt-72-的公开部分)）。仍是预发行版，不要用于生产 VPS。文档：[需求规格说明](docs/requirements.md)（v1.10）、[方案设计](docs/solution-design.md)（v1.6）、[验证计划](docs/verification-plan.md)（v1.8）、[详细设计](docs/detailed-design.md)（v0.10），已批准（2026-10-25，需求 D48）；详细设计 v0.11 草案待评审。

## 已确认的范围（2026-10-10，2026-10-13 补充，2026-10-20、2026-10-21、2026-10-24 修改）

| 项目 | 决定 |
|---|---|
| SSH 端口 | 保持 22，对所有来源开放 |
| SSH 认证 | 只允许密钥登录；root 是管理账户，只能用密钥登录（`PermitRootLogin prohibit-password`），不另建管理用户。root 的公钥由管理员事先配置，预检要求至少有一把可用的公钥（2026-10-20 起替代原先的"禁止 root 登录、使用普通 sudo 用户"） |
| 防火墙 | 启用 UFW：默认拒绝入站、允许出站、拒绝转发。对所有来源开放 22/tcp、代理入站（如 443/tcp）和订阅端口（如 2096/tcp）。加固时只开放 22/tcp，代理入站和订阅端口在安装 3X-UI 时用 `vps-hardening ports` 开放（2026-10-24 修改，需求 D41）；80/tcp 不开放，证书由代理仓库用 Cloudflare API Token 走 DNS-01 签发 |
| 3X-UI 面板 | 只经 SSH 隧道访问：`ssh -L 8443:127.0.0.1:<面板端口> root@vps`，面板端口默认 2053。UFW 不放行面板端口，面板只监听 127.0.0.1（由代理仓库设置），不使用 `ADMIN_CIDRS` 白名单（2026-10-13 起替代原先的白名单方案） |
| Fail2ban | 纳入，只保护 SSH；配置采用用户现网 3X-UI 方案第 16.1 节的样例，白名单只含回环地址；过滤模式为 `normal`，`maxretry` 固定为 5（2026-10-20 修改，见需求说明 FR-08） |
| 自动安全更新 | 纳入；Debian 同时自动安装稳定版小版本更新（与 Debian 默认一致）；不自动重启，需要重启时由验证命令报告 |
| 目标平台 | 发行版与 vps-tuning 一致：Debian 12/13、Ubuntu 24.04 LTS。架构为 x86_64；ARM64 作为参考，工具可以运行，测试按需执行（2026-10-20 修改） |
| 镜像默认用户 | 如果有免密 sudo，禁止该账户经 SSH 登录 |
| 适用主机 | 只支持新机，在安装 3X-UI 之前执行；已运行 3X-UI 的存量主机不在范围内 |
| 交付形态 | 在 VPS 本机运行的单命令工具 `vps-hardening`，提供预检、应用、验证和回滚，不依赖控制端；应用后须在 10 分钟内（可设 3～60 分钟）从新的 SSH 会话确认，否则自动恢复 |
| 3X-UI 共存基线 | v3.10.2（2026-10-21 起替代 v3.7.0，需求 D32）：安装时带版本参数 `v3.10.2`，上游安装脚本从同一 tag 取得菜单脚本，不再需要替换 `/usr/bin/x-ui`；设 `XUI_ENABLE_FAIL2BAN=false`，用 `XUI_PANEL_PORT` 预先指定面板端口；不使用 3X-UI 的防火墙菜单和 BBR 菜单。已安装 v3.7.0 的现有主机不受此约束；v3.10.2 自带的 Xray 对 REALITY 客户端的要求见需求规格说明第 7.2 节 |

范围限定为基础加固，不做 CIS 全量合规、入侵检测、AppArmor/SELinux 策略或审计系统。本仓库不安装代理服务，也不做网络性能调优。

## 使用方法

在新的 VPS 上，以 root 用密钥登录后：

1. 更新系统、安装基础工具并重启（需求 D24、D42）。本工具不执行这一步：

   ```bash
   apt update
   apt -s full-upgrade   # 只模拟，查看升级计划
   apt full-upgrade -y
   apt install -y curl wget ca-certificates gnupg lsb-release unzip vim nano htop ufw jq iproute2 procps kmod util-linux
   apt autoremove        # 清理自动安装且不再需要的软件包
   reboot
   ```

   软件包按需增减。只安装 `ufw`、不启用也不添加规则时，主机仍是新机；这一步不要安装 Docker 或 3X-UI。
2. 安装预发行版。安装脚本先用内置的摘要校验 `SHA256SUMS`，再逐个校验 13 个资产，然后安装到 `/usr/local/bin/vps-hardening` 和 `/usr/local/lib/vps-hardening`；它只放置文件，不执行预检或应用（[详细设计第 2.12 节](docs/detailed-design.md#212-安装脚本)）：

   ```bash
   curl -fsSLO https://github.com/alieismy/vps-hardening/releases/download/v0.1.0-rc.4/install.sh
   echo '502a981a589d50cbfce6ca8d8c81813851d2c26491b572d743ff848b4739b3fe  install.sh' | sha256sum -c -
   bash install.sh
   ```

   仓库中的 `install.sh` 没有绑定发行版，执行时拒绝。也可以直接从仓库运行 `bin/vps-hardening`（开发版）：待确认期间，自动恢复按这个路径调用它，所以确认之前不要移动或删除仓库目录。
3. 预检：`vps-hardening preflight`。root 必须已有可用的公钥，一般在服务商管理页面绑定 SSH 密钥即可；本工具只检查、不写入公钥，cloud-init 写给 root、带 `command=` 前缀的公钥不算可用。存在 `/var/run/reboot-required` 时预检给出警告，不阻止应用，建议先重启（需求 D43，自 `v0.1.0-rc.3` 起）。自 `v0.1.0-rc.4` 起，安装脚本结尾提示的就是这一步；`v0.1.0-rc.3` 提示的 `preflight --open <公开端口>` 是旧的推荐做法（详细设计第 9 节）。
4. 应用：`vps-hardening apply`，确认已保留当前会话、服务商控制台可用后输入 `yes`。这时 UFW 只放行 22/tcp，3X-UI 的端口在第 7 步开放（需求 D41）；也可以在加固时就声明公开端口（`--open 443/tcp --open 2096/tcp`）。
5. 保持当前会话，另开一个终端，用 root 的密钥登录后执行 `vps-hardening confirm`。确认时限默认 10 分钟（`--confirm-timeout` 可设 3～60 分钟）；到期未确认，或在此之前重启，都会自动恢复到应用前的配置。
6. 之后可随时用 `vps-hardening verify` 只读核对。安装 3X-UI 之后同样适用：面板监听了非回环地址、启用了 IP Limit、用过 BBR 菜单、防火墙菜单改动了 UFW 等漂移都会报告为不符合。
7. 安装 3X-UI 之后，开放它的入站端口和订阅端口：`vps-hardening ports --add 443/tcp --add 2096/tcp`。与应用一样，须在时限内从新的 SSH 会话执行 `confirm`，否则恢复原端口；确认后执行 `verify`。不要用 3X-UI 的防火墙菜单开放端口。
8. 其他命令：`vps-hardening status` 显示状态、变更记录和面板隧道命令。`vps-hardening ports --add 8443/tcp --remove 2096/tcp` 增减公开端口，与应用一样须在时限内从新的 SSH 会话执行 `confirm`，否则恢复原端口。`vps-hardening rollback` 恢复到应用前的配置，包括应用前的密码认证（回滚前检查会警告），本工具安装的软件包保留。已应用的主机上用相同参数再次 `apply` 只做核对，不做变更。

面板只经 SSH 隧道访问，`apply`、`confirm` 和 `status` 的输出中有隧道命令。命令细节见[详细设计第 2 节](docs/detailed-design.md#2-命令契约)。

## 待定事项

详细设计 v0.11 草案待评审：记录 `v0.1.0-rc.4` 的发布（[第 8.21 节](docs/detailed-design.md#821-预发行版-v010-rc4-和-vt-72-的公开部分)）和在测试 VPS 上对需求 D47 修复的复核（[第 8.22 节](docs/detailed-design.md#822-测试-vps-上复核需求-d47-的修复)，需求 D50），附录 A 增加一次 arm64 参考运行，第 9 节随之修改。之后待用户决定是否发布正式版（[方案设计第 10 节](docs/solution-design.md#10-里程碑)：M5 之后由用户确认）。

需求 v1.10、方案设计 v1.6、验证计划 v1.8 和详细设计 v0.10 已批准（2026-10-25，需求 D48）：修复需求 D46 列出的两个问题（需求 D47，#20）。由本工具安装 fail2ban 时，安装期间临时阻止服务启动，第一次启动就使用 FR-08 的值；安装脚本在没有应用过的主机上提示执行不带 `--open` 的 `preflight`。修复已合并，随预发行版 `v0.1.0-rc.4` 发布（需求 D49）。

详细设计 v0.9 已批准（2026-10-24，需求 D46）：记录 `v0.1.0-rc.3` 的发布和真实主机验收（M5）（第 8.18、8.19 节），第 9 节增加 M5 发现的一个问题，并记录 M5 再次观察到的一个已知问题。

需求 v1.8、v1.9，方案设计 v1.5，验证计划 v1.6、v1.7 和详细设计 v0.7、v0.8 已批准（2026-10-24，需求 D44）。这两轮批准的内容：

- VPS 流程的澄清（需求 D41～D43，用户于 2026-10-24 决定）：加固时不声明公开端口，UFW 只放行 22/tcp；安装 3X-UI 时用 `ports --add` 开放它的端口并从新会话确认，`ports` 因此改为 P0；加固前的系统更新、基础工具安装和清理写入需求第 7.3 节；预检发现待重启时只警告。3X-UI 的 IP Limit 暂不考虑（需求第 8 节）。

- 发布后的修复（需求 D40，用户于 2026-10-22 决定）：`v0.1.0-rc.1` 发布后核实了四个问题。修复后，检查 sshd 配置时按 sshd 自己的规则读取每一行，带引号的关键字、带引号或转义空格的 `Include` 路径不再漏查；安装脚本只在已安装文件的内容、属主和权限都与发行版相同时不做变更；替换文件的过程中失败或被中断时，恢复为安装前的文件（[详细设计第 1 节](docs/detailed-design.md#1-范围)、[第 2.12 节](docs/detailed-design.md#212-安装脚本)）。

需求 v1.7、方案设计 v1.4、验证计划 v1.5 和详细设计 v0.6 已批准（2026-10-22，需求 D39）。这一轮批准的内容：

- 修复（需求 D34～D37，用户于 2026-10-22 决定）：评审需求 v1.6 草案时发现三处自 M2 起就有的缺口。修复后，预检和 `verify` 拒绝 sshd 配置中的 `Match` 块；UFW 未启用时，预检也拒绝已添加的规则和被改动的 before/after 框架文件，`verify` 另外比较框架文件；规则改为与声明比较；`verify` 核对 `user.rules`、`user6.rules` 与记录的摘要，两者不一致时 `ports` 拒绝变更；80/tcp 在输入阶段就拒绝（[详细设计第 1 节](docs/detailed-design.md#1-范围)、[第 8.13 节](docs/detailed-design.md#813-修复的运行结果)）。

需求 v1.6、方案设计 v1.3、验证计划 v1.4、详细设计 v0.5 和 M4 的拉取请求 #10 已批准（2026-10-22，需求 D38）。这一轮批准的内容：3X-UI 共存基线由 v3.7.0 改为 v3.10.2（需求 D32，用户于 2026-10-21 选定；测试 VPS 上先卸载 3.7.0 再安装，需求 D33）；M4 的命令契约、测试和运行证据（[详细设计第 8.10～8.12 节](docs/detailed-design.md#810-m4-运行结果)）。评审时要求安装脚本在已应用的主机上的结尾提示在发布前修复，这一项已在修复中完成（[详细设计第 2.12 节](docs/detailed-design.md#212-安装脚本)）。

需求 v1.5、验证计划 v1.3 和详细设计 v0.4 已确认（2026-10-20，需求 D31）。这一轮确认的内容：3X-UI 的"安装防火墙"在 UFW 已启用时不做任何改动，据此更正需求第 7.2 节和 FR-10 的验收（需求 D29）；增加 `f2b.config`、`f2b.files`、`uu.dropin` 三个检查项；Fail2ban 对封禁过的来源加重计数（需求第 10.1 节、R-3）。这三项由需求 D30 确认。

需求 v1.4、方案设计 v1.2、验证计划 v1.2 和详细设计 v0.3 已确认（2026-10-20，需求 D28）。这一轮确认的内容：ARM64 改为按需运行的参考（需求 D26）；加固、调优和 3X-UI 的执行顺序（需求 D27）；Fail2ban 和自动更新的配置写入提前到 M2（[详细设计第 1 节](docs/detailed-design.md#1-范围)）；连续探测失败后重试一次，两次都失败才算中断（VT-25）。此前确认的 root 只用密钥登录、Fail2ban 参数等见上方的范围表。另有一项留到 M4 之后：真实主机验收的时间和主机（[验证计划第 9 节](docs/verification-plan.md#9-待决事项)）。

预发行版 `v0.1.0-rc.1` 已于 2026-10-22 在 #10、#11 合并之后发布，VT-72 的公开部分已完成（需求 D38，[详细设计第 8.14 节](docs/detailed-design.md#814-预发行版和-vt-72-的公开部分)）；发布后核实的四个问题已补进它的发布说明（需求 D39）。预发行版 `v0.1.0-rc.2` 已于 2026-10-22 在 #14、#15 合并之后发布，修复了这四个问题，VT-72 的公开部分已完成（需求 D39，[详细设计第 8.16 节](docs/detailed-design.md#816-预发行版-v010-rc2-和-vt-72-的公开部分)）。预发行版 `v0.1.0-rc.3` 已于 2026-10-24 在 #18 合并之后发布，包含这两轮批准的修改，VT-72 的公开部分已完成（需求 D44，[详细设计第 8.18 节](docs/detailed-design.md#818-预发行版-v010-rc3-和-vt-72-的公开部分)）。真实主机验收（M5）已在一台重装的 Debian 13 测试 VPS 上完成（[详细设计第 8.19 节](docs/detailed-design.md#819-真实主机验收m5)）。验收中发现一个问题，并再次观察到一个已知问题，都在详细设计第 9 节。按用户的决定（需求 D46），`v0.1.0-rc.3` 的发布说明补充"已知问题"，这两个问题在一个修复拉取请求中修复，随下一个预发行版与其他修改一起发布：
- 安装脚本结尾的提示仍是 `preflight --open <公开端口>`，与推荐流程不一致（M5 发现）；
- 应用时 fail2ban 先按软件包自带的配置运行几秒，这期间产生的封禁只有 600 秒（详细设计第 8.8 节已记录，当时判断影响小、不修改）。

预发行版 `v0.1.0-rc.4` 已于 2026-10-25 在 #20～#22 合并之后发布，修复了这两个问题，VT-72 的公开部分已完成（需求 D49，[详细设计第 8.21 节](docs/detailed-design.md#821-预发行版-v010-rc4-和-vt-72-的公开部分)）。之后在这台测试 VPS 上回滚 `v0.1.0-rc.3`、卸载 3X-UI，从公开地址安装 `v0.1.0-rc.4` 复核了这两项：按应用前已有失败产生的封禁为 1 天（需求 D50，[详细设计第 8.22 节](docs/detailed-design.md#822-测试-vps-上复核需求-d47-的修复)）。

## 配套仓库

| 仓库 | 用途 | 状态 |
|---|---|---|
| [vps-tuning](https://github.com/alieismy/vps-tuning) | 网络调优、诊断与测量 | Pre-release |
| vps-hardening（本仓库） | 基础安全加固 | Pre-release（v0.1.0-rc.4） |
| [vps-proxy-setup](https://github.com/alieismy/vps-proxy-setup) | 代理服务搭建（以 3X-UI 为例） | 需求阶段（2026-10-25 创建） |

建议的执行顺序（需求 D27、D41、D42；理由见[需求规格说明第 7.3 节](docs/requirements.md#73-与-vps-tuning-的约定)）：更新系统、安装基础工具并重启 → 加固并确认（UFW 只放行 22/tcp）→ 调优（应用 → 重启 → 验证）→ 安装并配置 3X-UI，用 `vps-hardening ports` 开放它的端口并确认 → 调优仓库的严格验证 → 重启后复核。系统更新和重启由管理员执行，本工具不执行。调优的应用和重启要在加固确认之后进行，确认前重启会自动撤销加固。

## 许可证

[MIT License](LICENSE)
