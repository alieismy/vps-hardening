# VPS Hardening

Baseline security hardening for Debian/Ubuntu VPS. **Status: planning — no usable release yet.**

为 Debian/Ubuntu VPS 提供基础安全加固，包括：SSH 只允许密钥登录、禁止 root 登录、UFW 只开放必要端口、Fail2ban，以及自动安全更新。目标是在不明显增加日常管理负担的前提下缩小暴露面，同时避免把管理员锁在服务器外。

**当前状态：规划中，尚无可用版本。** 本仓库目前只有范围记录，不要在任何 VPS 上运行。

## 已确认的范围（2026-10-10）

| 项目 | 决定 |
|---|---|
| SSH 端口 | 保持 22，对所有来源开放 |
| SSH 认证 | 只允许密钥登录；禁止 root 通过 SSH 登录；日常使用普通 sudo 用户，sudo 需要输入密码 |
| 防火墙 | 启用 UFW：默认拒绝入站、允许出站；只开放 SSH、代理入站等必要端口 |
| 3X-UI 面板 | 面板端口只允许 `ADMIN_CIDRS` 中的地址访问；管理员 IP 变化时改用 SSH 隧道：`ssh -L 8443:127.0.0.1:<面板端口> user@vps` |
| Fail2ban | 纳入；具体配置待提供样例后再分析确定 |
| 自动安全更新 | 纳入 |

范围限定为基础加固，不做 CIS 全量合规、入侵检测、AppArmor/SELinux 策略或审计系统。本仓库不安装代理服务，也不做网络性能调优。

## 待定事项

- 目标平台：建议与 vps-tuning 一致（Debian 12/13、Ubuntu 24.04 LTS，x86_64/ARM64），待需求确认。
- 实现方式和验证方法。
- Fail2ban 配置，等待样例。
- 与 vps-proxy-setup 的端口约定：
  - 面板端口建议安装 3X-UI 前用 `XUI_PANEL_PORT` 预先指定；
  - 代理入站端口清单。
- 与 3X-UI 自带防火墙菜单、Fail2ban IP 限制功能的共存方式。

## 配套仓库

| 仓库 | 用途 | 状态 |
|---|---|---|
| [vps-tuning](https://github.com/alieismy/vps-tuning) | 网络调优、诊断与测量 | Pre-release |
| vps-hardening（本仓库） | 基础安全加固 | 规划中 |
| vps-proxy-setup | 代理服务搭建（以 3X-UI 为例） | 规划中，尚未创建 |

建议的执行顺序（待需求确认）：加固 → 调优 → 搭建代理 → 调优仓库的严格验证。

## 许可证

[MIT License](LICENSE)
