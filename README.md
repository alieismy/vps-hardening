# VPS Hardening

Baseline security hardening for Debian/Ubuntu VPS. **Status: in development (milestones M1–M3 done: read-only checks, apply with automatic restore, Fail2ban values and coexistence with 3X-UI; tested in CI VMs and on one test VPS) — no usable release yet.**

为 Debian/Ubuntu VPS 提供基础安全加固，包括：SSH 只允许密钥登录（root 作为管理账户，只能用密钥登录）、UFW 只开放必要端口、Fail2ban，以及自动安全更新。目标是在不明显增加日常管理负担的前提下缩小暴露面，同时避免把管理员锁在服务器外。

**当前状态：开发中，尚无可用版本。** 已完成里程碑 M1～M3：只读的 `preflight`（预检）和 `verify`（验证），`apply`（应用）、`confirm`（确认）和自动恢复，以及 Fail2ban 生效值、自动更新和与 3X-UI v3.7.0 共存的验证，都在三个平台的 amd64 虚拟机测试中通过（arm64 作为参考，按需测试）。尚未完成：手工回滚、端口变更和发布包（M4），真实主机验收（M5）。目前只在 CI 虚拟机和一台测试 VPS 上验证过（[详细设计第 8.6 节](docs/detailed-design.md#86-测试-vps-上的试运行)、[第 8.8 节](docs/detailed-design.md#88-测试-vps-上的-m3-核对)），不要用于生产 VPS。文档：[需求规格说明](docs/requirements.md)（v1.5 草案）、[方案设计](docs/solution-design.md)（v1.2）、[验证计划](docs/verification-plan.md)（v1.3 草案）、[详细设计](docs/detailed-design.md)（v0.4 草案，覆盖 M1～M3）；草案待评审，此前的版本已确认。

## 已确认的范围（2026-10-10，2026-10-13 补充，2026-10-20 修改）

| 项目 | 决定 |
|---|---|
| SSH 端口 | 保持 22，对所有来源开放 |
| SSH 认证 | 只允许密钥登录；root 是管理账户，只能用密钥登录（`PermitRootLogin prohibit-password`），不另建管理用户。root 的公钥由管理员事先配置，预检要求至少有一把可用的公钥（2026-10-20 起替代原先的"禁止 root 登录、使用普通 sudo 用户"） |
| 防火墙 | 启用 UFW：默认拒绝入站、允许出站、拒绝转发。对所有来源开放 22/tcp、代理入站（如 443/tcp）和订阅端口（如 2096/tcp）；80/tcp 不开放，证书由代理仓库用 Cloudflare API Token 走 DNS-01 签发 |
| 3X-UI 面板 | 只经 SSH 隧道访问：`ssh -L 8443:127.0.0.1:<面板端口> root@vps`，面板端口默认 2053。UFW 不放行面板端口，面板只监听 127.0.0.1（由代理仓库设置），不使用 `ADMIN_CIDRS` 白名单（2026-10-13 起替代原先的白名单方案） |
| Fail2ban | 纳入，只保护 SSH；配置采用用户现网 3X-UI 方案第 16.1 节的样例，白名单只含回环地址；过滤模式为 `normal`，`maxretry` 固定为 5（2026-10-20 修改，见需求说明 FR-08） |
| 自动安全更新 | 纳入；Debian 同时自动安装稳定版小版本更新（与 Debian 默认一致）；不自动重启，需要重启时由验证命令报告 |
| 目标平台 | 发行版与 vps-tuning 一致：Debian 12/13、Ubuntu 24.04 LTS。架构为 x86_64；ARM64 作为参考，工具可以运行，测试按需执行（2026-10-20 修改） |
| 镜像默认用户 | 如果有免密 sudo，禁止该账户经 SSH 登录 |
| 适用主机 | 只支持新机，在安装 3X-UI 之前执行；已运行 3X-UI 的存量主机不在范围内 |
| 交付形态 | 在 VPS 本机运行的单命令工具 `vps-hardening`，提供预检、应用、验证和回滚，不依赖控制端；应用后须在 10 分钟内（可设 3～60 分钟）从新的 SSH 会话确认，否则自动恢复 |
| 3X-UI 共存基线 | v3.7.0：安装时带版本参数 `v3.7.0`，并用该 tag 中已校验的 `x-ui.sh` 替换 `/usr/bin/x-ui`（上游安装脚本总是从 main 分支下载它）；设 `XUI_ENABLE_FAIL2BAN=false`，用 `XUI_PANEL_PORT` 预先指定面板端口；不使用 3X-UI 的防火墙菜单和 BBR 菜单 |

范围限定为基础加固，不做 CIS 全量合规、入侵检测、AppArmor/SELinux 策略或审计系统。本仓库不安装代理服务，也不做网络性能调优。

## 使用方法（开发版）

尚无发布包和安装脚本（M4），开发版从仓库运行 `bin/vps-hardening`，下文写作 `vps-hardening`。待确认期间，自动恢复按这个路径调用它，所以确认之前不要移动或删除仓库目录。在新的 VPS 上，以 root 用密钥登录后：

1. 全量升级并重启：`apt update && apt full-upgrade`，然后 `reboot`。本工具不执行这一步（需求 D24）。
2. 预检：`vps-hardening preflight --open 443/tcp --open 2096/tcp`。root 必须已有可用的公钥，一般在服务商管理页面绑定 SSH 密钥即可；本工具只检查、不写入公钥，cloud-init 写给 root、带 `command=` 前缀的公钥不算可用。
3. 应用：`vps-hardening apply --open 443/tcp --open 2096/tcp`，确认已保留当前会话、服务商控制台可用后输入 `yes`。
4. 保持当前会话，另开一个终端，用 root 的密钥登录后执行 `vps-hardening confirm`。确认时限默认 10 分钟（`--confirm-timeout` 可设 3～60 分钟）；到期未确认，或在此之前重启，都会自动恢复到应用前的配置。
5. 之后可随时用 `vps-hardening verify` 只读核对。安装 3X-UI 之后同样适用：面板监听了非回环地址、启用了 IP Limit、用过 BBR 菜单、防火墙菜单改动了 UFW 等漂移都会报告为不符合。

面板只经 SSH 隧道访问，`apply` 和 `confirm` 的输出中有隧道命令。命令细节见[详细设计第 2 节](docs/detailed-design.md#2-命令契约)。

## 待定事项

M3 的文档待评审：需求 v1.5 草案、验证计划 v1.3 草案（VT-51 的漂移清单、VO-1 的摘要）、详细设计 v0.4 草案（M3 的检查项、测试和运行证据）。其中三项已经确认（需求 D30）：3X-UI 的"安装防火墙"在 UFW 已启用时不做任何改动，据此更正需求第 7.2 节和 FR-10 的验收（D29）；增加 `f2b.config`、`f2b.files`、`uu.dropin` 三个检查项；Fail2ban 对封禁过的来源加重计数（需求第 10.1 节、R-3）。

需求 v1.4、方案设计 v1.2、验证计划 v1.2 和详细设计 v0.3 已确认（2026-10-20，需求 D28）。这一轮确认的内容：ARM64 改为按需运行的参考（需求 D26）；加固、调优和 3X-UI 的执行顺序（需求 D27）；Fail2ban 和自动更新的配置写入提前到 M2（[详细设计第 1 节](docs/detailed-design.md#1-范围)）；连续探测失败后重试一次，两次都失败才算中断（VT-25）。此前确认的 root 只用密钥登录、Fail2ban 参数等见上方的范围表。另有一项留到 M4 之后：真实主机验收的时间和主机（[验证计划第 9 节](docs/verification-plan.md#9-待决事项)）。

下一步：里程碑 M4（手工回滚、状态记录、端口变更，发布预发行版）。

## 配套仓库

| 仓库 | 用途 | 状态 |
|---|---|---|
| [vps-tuning](https://github.com/alieismy/vps-tuning) | 网络调优、诊断与测量 | Pre-release |
| vps-hardening（本仓库） | 基础安全加固 | 开发中（M3 已完成） |
| vps-proxy-setup | 代理服务搭建（以 3X-UI 为例） | 规划中，尚未创建 |

建议的执行顺序（需求 D27；理由见[需求规格说明第 7.3 节](docs/requirements.md#73-与-vps-tuning-的约定)）：`apt update && apt full-upgrade` → 重启 → 加固并确认 → 调优（应用 → 重启 → 验证）→ 安装并配置 3X-UI → 调优仓库的严格验证 → 重启后复核。全量升级和重启由管理员执行，本工具不执行。调优的应用和重启要在加固确认之后进行，确认前重启会自动撤销加固。

## 许可证

[MIT License](LICENSE)
