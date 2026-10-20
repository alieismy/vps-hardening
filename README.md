# VPS Hardening

Baseline security hardening for Debian/Ubuntu VPS. **Status: in development (milestone M1 done: read-only checks) — no usable release yet.**

为 Debian/Ubuntu VPS 提供基础安全加固，包括：SSH 只允许密钥登录（root 作为管理账户，只能用密钥登录）、UFW 只开放必要端口、Fail2ban，以及自动安全更新。目标是在不明显增加日常管理负担的前提下缩小暴露面，同时避免把管理员锁在服务器外。

**当前状态：开发中，尚无可用版本。** 已完成里程碑 M1：只读的 `preflight`（预检）和 `verify`（验证），以及在 6 组平台上运行的虚拟机测试（VT-02、VT-03 中涉及 `apply` 的部分随 M2 补测）；加固本身（`apply` 等）尚未实现，不要在任何 VPS 上运行。文档：[需求规格说明](docs/requirements.md)（v1.3，已确认）、[方案设计](docs/solution-design.md)（v1.1，已确认）、[验证计划](docs/verification-plan.md)（v1.1，已确认）、[详细设计](docs/detailed-design.md)（M1 部分，v0.2，已确认）。

## 已确认的范围（2026-10-10，2026-10-13 补充，2026-10-20 修改）

| 项目 | 决定 |
|---|---|
| SSH 端口 | 保持 22，对所有来源开放 |
| SSH 认证 | 只允许密钥登录；root 是管理账户，只能用密钥登录（`PermitRootLogin prohibit-password`），不另建管理用户。root 的公钥由管理员事先配置，预检要求至少有一把可用的公钥（2026-10-20 起替代原先的"禁止 root 登录、使用普通 sudo 用户"） |
| 防火墙 | 启用 UFW：默认拒绝入站、允许出站、拒绝转发。对所有来源开放 22/tcp、代理入站（如 443/tcp）和订阅端口（如 2096/tcp）；80/tcp 不开放，证书由代理仓库用 Cloudflare API Token 走 DNS-01 签发 |
| 3X-UI 面板 | 只经 SSH 隧道访问：`ssh -L 8443:127.0.0.1:<面板端口> root@vps`，面板端口默认 2053。UFW 不放行面板端口，面板只监听 127.0.0.1（由代理仓库设置），不使用 `ADMIN_CIDRS` 白名单（2026-10-13 起替代原先的白名单方案） |
| Fail2ban | 纳入，只保护 SSH；配置采用用户现网 3X-UI 方案第 16.1 节的样例，白名单只含回环地址；过滤模式为 `normal`，`maxretry` 固定为 5（2026-10-20 修改，见需求说明 FR-08） |
| 自动安全更新 | 纳入；Debian 同时自动安装稳定版小版本更新（与 Debian 默认一致）；不自动重启，需要重启时由验证命令报告 |
| 目标平台 | 与 vps-tuning 一致：Debian 12/13、Ubuntu 24.04 LTS，x86_64/ARM64 |
| 镜像默认用户 | 如果有免密 sudo，禁止该账户经 SSH 登录 |
| 适用主机 | 只支持新机，在安装 3X-UI 之前执行；已运行 3X-UI 的存量主机不在范围内 |
| 交付形态 | 在 VPS 本机运行的单命令工具 `vps-hardening`，提供预检、应用、验证和回滚，不依赖控制端；应用后须在 10 分钟内（可设 3～60 分钟）从新的 SSH 会话确认，否则自动恢复 |
| 3X-UI 共存基线 | v3.7.0：安装时带版本参数 `v3.7.0`，并用该 tag 中已校验的 `x-ui.sh` 替换 `/usr/bin/x-ui`（上游安装脚本总是从 main 分支下载它）；设 `XUI_ENABLE_FAIL2BAN=false`，用 `XUI_PANEL_PORT` 预先指定面板端口；不使用 3X-UI 的防火墙菜单和 BBR 菜单 |

范围限定为基础加固，不做 CIS 全量合规、入侵检测、AppArmor/SELinux 策略或审计系统。本仓库不安装代理服务，也不做网络性能调优。

## 待定事项

需求 v1.3、方案设计 v1.1、验证计划 v1.1 和详细设计 v0.2 已确认（2026-10-20：root 只用密钥登录、不建管理用户，Fail2ban 用 `normal` 模式、`maxretry` 取 5，加固前先全量升级并重启）。另有一项留到 M4 之后：真实主机验收的时间和主机（[验证计划第 9 节](docs/verification-plan.md#9-待决事项)）。

下一步：里程碑 M2（核心应用：SSH、UFW、待确认与自动恢复、`confirm`）。

## 配套仓库

| 仓库 | 用途 | 状态 |
|---|---|---|
| [vps-tuning](https://github.com/alieismy/vps-tuning) | 网络调优、诊断与测量 | Pre-release |
| vps-hardening（本仓库） | 基础安全加固 | 开发中（M1 已完成） |
| vps-proxy-setup | 代理服务搭建（以 3X-UI 为例） | 规划中，尚未创建 |

建议的执行顺序（见[需求规格说明第 7.3 节](docs/requirements.md#73-与-vps-tuning-的约定)）：`apt update && apt full-upgrade` → 重启 → 加固 → 调优 → 搭建代理 → 调优仓库的严格验证。全量升级和重启由管理员执行，本工具不执行。

## 许可证

[MIT License](LICENSE)
