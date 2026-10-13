# VPS Hardening

Baseline security hardening for Debian/Ubuntu VPS. **Status: planning — no usable release yet.**

为 Debian/Ubuntu VPS 提供基础安全加固，包括：SSH 只允许密钥登录、禁止 root 登录、UFW 只开放必要端口、Fail2ban，以及自动安全更新。目标是在不明显增加日常管理负担的前提下缩小暴露面，同时避免把管理员锁在服务器外。

**当前状态：规划中，尚无可用版本。** 本仓库目前只有范围记录和[需求规格说明](docs/requirements.md)（已于 2026-10-13 评审确认），不要在任何 VPS 上运行。

## 已确认的范围（2026-10-10，2026-10-13 补充）

| 项目 | 决定 |
|---|---|
| SSH 端口 | 保持 22，对所有来源开放 |
| SSH 认证 | 只允许密钥登录；禁止 root 通过 SSH 登录；日常使用普通 sudo 用户，sudo 需要输入密码 |
| 防火墙 | 启用 UFW：默认拒绝入站、允许出站、拒绝转发。对所有来源开放 22/tcp、代理入站（如 443/tcp）和订阅端口（如 2096/tcp）；80/tcp 不开放，证书由代理仓库用 Cloudflare API Token 走 DNS-01 签发 |
| 3X-UI 面板 | 只经 SSH 隧道访问：`ssh -L 8443:127.0.0.1:<面板端口> user@vps`。UFW 不放行面板端口，面板只监听 127.0.0.1（由代理仓库设置），不使用 `ADMIN_CIDRS` 白名单（2026-10-13 起替代原先的白名单方案） |
| Fail2ban | 纳入，只保护 SSH；配置采用用户现网 3X-UI 方案第 16.1 节的样例，白名单只含回环地址，`maxretry` 默认 6（参数见需求说明 FR-08） |
| 自动安全更新 | 纳入；不自动重启，需要重启时由验证命令报告 |
| 目标平台 | 与 vps-tuning 一致：Debian 12/13、Ubuntu 24.04 LTS，x86_64/ARM64 |
| 镜像默认用户 | 如果有免密 sudo，禁止该账户经 SSH 登录 |
| 适用主机 | 只支持新机，在安装 3X-UI 之前执行；已运行 3X-UI 的存量主机不在范围内 |
| 交付形态 | 在 VPS 本机运行的单命令工具，提供预检、应用、验证和回滚，不依赖控制端 |
| 3X-UI 共存基线 | v3.7.0：安装时设 `XUI_ENABLE_FAIL2BAN=false`，用 `XUI_PANEL_PORT` 预先指定面板端口，不使用 3X-UI 的防火墙菜单和 BBR 菜单 |

范围限定为基础加固，不做 CIS 全量合规、入侵检测、AppArmor/SELinux 策略或审计系统。本仓库不安装代理服务，也不做网络性能调优。

## 待定事项

详见[需求规格说明第 11 节](docs/requirements.md#11-待决事项)：

- 防锁死确认时限的默认值，设计阶段给出。

下一步：方案设计和验证计划。

## 配套仓库

| 仓库 | 用途 | 状态 |
|---|---|---|
| [vps-tuning](https://github.com/alieismy/vps-tuning) | 网络调优、诊断与测量 | Pre-release |
| vps-hardening（本仓库） | 基础安全加固 | 规划中 |
| vps-proxy-setup | 代理服务搭建（以 3X-UI 为例） | 规划中，尚未创建 |

建议的执行顺序（见[需求规格说明第 7.3 节](docs/requirements.md#73-与-vps-tuning-的约定)）：加固 → 调优 → 搭建代理 → 调优仓库的严格验证。

## 许可证

[MIT License](LICENSE)
