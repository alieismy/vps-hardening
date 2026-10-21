# VPS Hardening 详细设计

| 项目 | 内容 |
|---|---|
| 状态 | v0.4 草案：增补里程碑 M3 的检查项（第 4 节）、测试（第 7 节）和运行证据（第 8.7～8.9 节），涉及第 1、4、7～9 节。超出 v0.3 第 1 节所列 M3 范围的三个检查项（`f2b.config`、`f2b.files`、`uu.dropin`）已经用户确认（需求 U18、D30）；全文待评审。v0.3 已批准：增补里程碑 M2（`apply`、`confirm`、自动恢复）的契约、状态记录、测试和运行证据，涉及第 1～9 节；M3、M4 实现时继续增补。第 1 节的范围调整（Fail2ban 和自动更新的写入提前到 M2）偏离方案设计 v1.1 第 10 节，已经评审通过，方案设计 v1.2 第 10 节随之修改。按需求 v1.4（D26），arm64 改为按需运行的参考，M2 的 arm64 结果放在附录 A。增补第 8.6 节：在用户提供的一台测试 VPS 上试运行 M2 开发版，不是 M5 的验收。用户于 2026-10-20 评审通过（需求 U16、D28），包括第 1 节的范围调整和 VT-25 的判定方式。此前的版本：v0.1 于 2026-10-20 经用户评审，除第 2.4 节的 `--maxretry` 和第 4 节 `ssh.permitrootlogin` 的期望值两处外通过；v0.2 按需求 v1.3（D22、D23）修改第 2.2、2.4、3～7、9 节，删除管理用户和公钥文件参数、sudo 条件检查，新增 root 公钥检查 `root.keys`，于同日经用户评审通过（需求 U13、D25） |
| 日期 | 2026-10-20（v0.1 为 2026-10-13） |
| 上游 | [需求规格说明 v1.5 草案](requirements.md)（v1.4 已批准）、[方案设计 v1.2](solution-design.md)（已批准）、[验证计划 v1.3 草案](verification-plan.md)（v1.2 已批准） |
| 下游 | 实现、测试 |
| 深度 | 命令契约、检查项目录、模块划分、实现约束和测试框架；不重复上游已有的决策理由 |

**证据状态。** 第 2～6 节描述的是仓库中的实现，第 7 节描述的是测试框架。运行证据见第 8 节：第 8.1～8.5、8.7 节来自 CI 虚拟机；第 8.6、8.8 节来自一台测试 VPS，只有一台主机，不能代替真实主机验收（M5）。

## 1. 范围

M1 实现只读部分（方案设计第 10 节）：

- `preflight`：只读预检，包括存量主机判定（FR-01、FR-02）；
- `verify`：只读验证（FR-10）。

M2 实现应用和确认（第 2.5～2.8 节）：

- `apply`：预检、交互确认、安装软件包、快照、布置自动恢复，然后写入 SSH、UFW、Fail2ban 和自动更新的配置，进入待确认；
- `confirm`：从新的 root SSH 会话确认，撤除自动恢复，然后运行 `verify`；
- 自动恢复：确认超时、待确认期间重启、应用失败三种情况共用同一套恢复逻辑；
- `verify` 中依赖应用记录的 SSH 和 UFW 检查项（第 4 节）；
- `status`、`rollback`、`ports` 仍报告"尚未实现"（M4）。

**范围调整（已经评审通过，需求 D28）。** 方案设计 v1.1 第 10 节把 Fail2ban 和自动安全更新放在 M3。M2 已经写入这两部分的配置，原因有两个：

- VT-10 要求确认后 `verify` 通过，而 M1 已实现的 `f2b.*`、`uu.*` 检查项要求两者都已配置；
- VT-23 用屏蔽 `fail2ban.service` 的方式注入失败，需要 `apply` 在布置自动恢复后操作这个服务。

M3 仍负责：`f2b.values` 和 `boundary.panel-listen` 两个检查项（M2 中报告"跳过"）、FR-08 的 11 步验证（VT-30～VT-35）、VT-40、VT-51、VT-55，以及与 3X-UI 共存的验证。

M3 实现（v0.4）：

- `verify` 实现 `f2b.values` 和 `boundary.panel-listen`，另增加 `f2b.config`、`f2b.files`、`uu.dropin` 三项（第 4 节）；
- 修复 M1 遗留的 `f2b.mainconf` 漏报（第 8.7 节）；
- 新的 hardened 测试套件覆盖 VT-30～VT-35、VT-40、VT-50（加固后、重启后、安装 3X-UI 后）、VT-51、VT-55 和 VT-71 的其余部分（第 7 节）；
- `apply`、`confirm` 和自动恢复没有改动。

**范围补充（已确认，需求 D30）。** `f2b.config`、`f2b.files`、`uu.dropin` 不在上面列给 M3 的范围内。增加的依据：`f2b.config` 对应方案设计第 7.6 节 Fail2ban 区域的"配置检查通过"，此前没有实现；另两项兑现受管文件首行注释中"verify reports any change"的说明，并覆盖 `f2b.values` 读不回的过滤模式（第 4 节）。三项都是只读检查，不改变 `apply` 的行为。

## 2. 命令契约

### 2.1 调用与环境

- 入口为 `bin/vps-hardening`，模块在 `lib/vps-hardening/`。入口用 `readlink -f` 定位自身，按"上两级目录下的 `lib/vps-hardening`"找模块，所以安装后（`/usr/local/bin` 和 `/usr/local/lib`，方案设计第 7.2 节）和在仓库中运行使用同一套相对布局。
- 入口固定 `PATH`、`LC_ALL=C`（被解析的工具输出保持英文格式）和 `umask 077`，并启用 `set -Eeuo pipefail`。
- 输出中的说明文字为中文；检查项编号为英文，保持稳定，测试按编号判定。
- `apply` 把入口的绝对路径写进 systemd 单元（第 2.7 节）。路径中只允许字母、数字和 `._/-`，含其他字符时 `apply` 在做任何变更之前拒绝执行。

### 2.2 退出码

| 退出码 | 含义 |
|---|---|
| 0 | 检查全部通过（允许有警告和跳过） |
| 1 | 至少一项不符合 |
| 2 | 用法或输入错误：未知命令或参数、参数取值不合法、`apply` 不在交互终端中运行、命令尚未实现 |
| 3 | 内部错误：命令意外失败。由 ERR 陷阱统一转换，避免被误读为"不符合"（退出码 1） |

M2 新增命令的退出码 0、1、3 的具体含义（2 的含义同上表）：

| 命令 | 0 | 1 | 3 |
|---|---|---|---|
| `apply` | 应用完成，进入待确认 | 不是 root；预检有不符合项；管理员没有输入 `yes`；另一个操作正在进行；应用失败（已恢复，或恢复未全部完成） | 内部错误。应用已经开始时，先恢复再退出 |
| `confirm` | 确认成功，随后的 `verify` 全部通过 | 确认被拒绝（第 2.6 节），状态不变；或者确认成功，但 `verify` 有不符合项 | 撤除自动恢复失败（第 2.6 节）；或者确认成功，但 `verify` 出现内部错误 |
| `_restore` | 已恢复，或无需恢复 | 恢复未全部完成 | 等待操作锁超过 15 分钟 |

`confirm` 成功后用 `exec` 运行 `verify`，退出码就是 `verify` 的退出码；输出中有"已确认"的就是第二种 1。`_restore` 只由 systemd 单元调用，不在帮助中列出。

### 2.3 输出格式

每个检查项一行：`[级别] 编号 说明`，编号左对齐占 30 列。级别：

| 级别 | 含义 | 是否影响退出码 |
|---|---|---|
| `PASS` | 符合 | 否 |
| `FAIL` | 不符合 | 是，退出码 1 |
| `WARN` | 需要注意，但不构成不符合 | 否 |
| `SKIP` | 缺少判定依据（如没有应用记录） | 否 |
| `INFO` | 说明性信息，如公钥指纹 | 否，也不计数 |

最后一行汇总通过、不符合、警告和跳过的数量。用法错误和内部错误以 `[x]` 开头写到标准错误。输出中不包含密码或私钥内容，公钥只输出类型和 SHA256 指纹。

`apply` 先按上述格式输出预检结果，然后输出变更计划和 6 个步骤的标题（`== 1/6` 等）。软件包安装、UFW、Fail2ban 命令的输出写入工具日志（第 2.8 节），终端只显示每步的结论。

### 2.4 输入参数

`preflight` 和 `apply` 共用同一个解析器（`lib/vps-hardening/inputs.sh`），支持 `--选项 值` 和 `--选项=值` 两种写法。任何一项不合法都以退出码 2 结束，不做主机检查。

| 参数 | 规则 |
|---|---|
| `--panel-port` | 默认 2053（需求 D20）；1～65535，不能是 22 |
| `--open` | 可重复，最多 16 个；`端口/tcp|udp[/both|ipv4|ipv6]`，地址族默认 `both`；端口不能是 22 或面板端口，同一端口和协议不能重复 |
| `--confirm-timeout` | 3～60 的整数分钟，默认 10（需求 D18） |

`apply` 先检查标准输入是否为终端（方案设计第 7.1 节），再解析参数。

v0.1 中的 `--user`、`--pubkey-file` 和 `--maxretry` 已删除：root 是管理账户，它的公钥由管理员事先配置，本工具只读检查（`root.keys`，需求 D22）；`maxretry` 固定为 5（D23）。传入这些参数按未知参数处理，退出码 2，不会被静默忽略。

### 2.5 `apply`

流程对应方案设计第 7.3 节的 10 步：

| 步骤 | 实现 | 失败时 |
|---|---|---|
| 1 预检 | 不是 root 时立即结束；取操作锁，不等待；执行与 `preflight` 相同的检查 | 退出码 1，未做任何变更 |
| 2 交互确认 | 输出变更计划，其中列出将被禁止 SSH 登录的免密 sudo 账户；管理员输入 `yes`，表示当前会话会一直保持、服务商控制台可用 | 输入其他内容或读到文件结束：退出码 1，未做任何变更 |
| 3 记录初始状态 | 创建状态目录；删除上次已回滚的应用留下的记录；状态记为"应用中"，写入输入参数；记录 4 个受管单元的启用和运行状态 | 属于"准备"阶段：只恢复单元状态（见下文） |
| 4 安装软件包 | 只安装缺少的：`apt-get install --no-install-recommends`，加 `--force-confold`；标准输入为 `/dev/null`；超时 30 分钟；输出写入日志 | 同上；已安装的软件包保留 |
| 5 快照 | 8 个受管文件的副本和元数据（第 2.8 节） | 同上 |
| 6 布置自动恢复 | 依次写待确认标记、启用开机兜底单元、启动临时定时器，每一项都核实（第 2.7 节） | 从这一步起属于"变更"阶段：任何失败都按快照恢复 |
| 7 SSH | 见下文 | 按快照恢复 |
| 8 UFW、Fail2ban | 见下文 | 按快照恢复 |
| 9 自动更新 | 见下文 | 按快照恢复 |
| 10 进入待确认 | 记录 8 个受管文件的摘要；用完整时限重新计时（第 2.7 节）；状态改为"待确认"；输出截止时间、确认命令和面板隧道命令，然后退出 | 按快照恢复 |

**SSH。**

1. 写入 `/etc/ssh/sshd_config.d/00-vps-hardening.conf`：`PermitRootLogin prohibit-password`、`PasswordAuthentication no`、`KbdInteractiveAuthentication no`、`PubkeyAuthentication yes`；有免密 sudo 账户时再加 `DenyUsers`（需求 D13）。
2. 执行 `sshd -t`。
3. 用 `sshd -T -C`（连接参数见第 6 节）分别以 root 和每个被禁账户求值，核对 FR-04 的各项、端口 22 和 `allowtcpforwarding`。
4. 全部符合后才执行 `systemctl try-reload-or-restart ssh.service`。服务在运行时，这个命令执行单元的 `ExecReload`（先 `sshd -t`，再发 SIGHUP），主进程不变；服务没有运行时什么也不做，下次由 socket 启动时读取新配置。Ubuntu 的 socket 激活下同样生效（第 8.4 节，DR-4）。

**UFW。**

1. 确保 `/etc/default/ufw` 中为 `IPV6=yes`。
2. 默认策略设为拒绝入站、允许出站、拒绝转发。
3. 放行 22/tcp 和每个 `--open` 端口。地址族为 `both` 时用 `ufw allow 端口/协议`；`ipv4`、`ipv6` 分别加 `to 0.0.0.0/0`、`to ::/0`。规则都带注释 `vps-hardening`。
4. 核实已有放行 22/tcp 的规则，然后才 `systemctl enable ufw.service` 并 `ufw --force enable`。
5. 核实状态为 active，把 `ufw status` 的规则行记入 `ufw-rules`。`verify` 的 `ufw.rules` 以这份记录为准。

**Fail2ban。**

1. 写入 `/etc/fail2ban/jail.d/99-vps-hardening.local`（FR-08 表中的 jail 值）和 `/etc/fail2ban/fail2ban.local`（`dbpurgeage = 30d`）。
2. 执行 `fail2ban-client -t`。
3. 启用并重启服务。最多等 120 秒，直到 `fail2ban-client ping` 有响应、sshd jail 在运行。
4. 核实 jail 只有 `sshd`，并且 `maxretry`、`findtime`、`bantime` 的生效值为 5、600、86400。其余生效值的核对在 M3 实现（`f2b.values`）。

**自动更新。**

1. 写入 `/etc/apt/apt.conf.d/52vps-hardening`：两个 `APT::Periodic` 值为 1，`Automatic-Reboot` 为 `false`；先用 `#clear` 清空两个来源列表，再按发行版写入 FR-09 的来源。文件名排在发行版的 `50unattended-upgrades` 之后，所以覆盖它的设置。
2. 核实 `apt-config dump` 中的生效值和来源集合，判定方法与 `uu.origins` 相同。
3. `systemctl enable --now` 两个 APT 定时器。

**失败处理。**

- 应用分两个阶段：
  - "准备"阶段（第 3～5 步）只可能装了软件包。失败时把 4 个受管单元恢复到记录的状态，状态记为"已回滚"，原因注明"尚未修改配置"。
  - "变更"阶段（第 6 步起）失败时执行完整的恢复（第 2.7 节），并在终端报告结果。
- 三种失败都走同一个入口：
  - 步骤中的显式检查失败；
  - ERR 陷阱捕获的意外失败：经恢复钩子先恢复，再以退出码 3 结束；
  - SIGINT、SIGTERM、SIGHUP。收到 SIGHUP 时终端已经断开，其后的输出改写到工具日志。
- 恢复期间忽略这三个信号。
- 恢复后保留已安装的软件包（方案设计第 4.4 节），终端列出这些软件包。

**再次执行。** 状态为"已回滚"时，预检的 `new-host.state` 通过，可以按正常流程再次应用；其他状态都被拒绝（第 3 节）。NFR-03 要求已应用且没有漂移时退出码为 0，这在 M4 实现；M2 中，已应用的主机上再次执行 `apply` 退出码为 1。

### 2.6 `confirm`

`confirm` 不接受参数。它依次检查以下各项，任一项不满足就拒绝（退出码 1），状态不变：

1. 以 root 运行。
2. 取得操作锁，不等待。
3. 状态为"待确认"，且待确认标记存在。
4. 本进程的登录 UID（`/proc/$$/loginuid`）为 0，即会话是以 root 登录的，不是经 sudo 或 su 切换的。
5. 本进程的审计会话编号（`/proc/$$/sessionid`）有效（不是表示"未设置"的 4294967295），且与标记中记录的 `apply` 会话编号不同。
6. 祖先进程中有 `sshd` 或 `sshd-session`，即会话来自 SSH，不是控制台。OpenSSH 9.8 起每个会话由 `sshd-session` 进程处理（Debian 13）。

第 4～6 项的依据见第 8.4 节（DR-11）。拒绝时的提示说明具体原因，例如在 `apply` 的会话中执行时，提示另开一个终端。这些检查防的是误操作，不防有意绕过的 root（方案设计第 7.5 节）。

全部满足后：

1. 撤除自动恢复：停止定时器、停用开机兜底单元、删除标记；
2. 状态改为"已应用"，记录确认时间；
3. 输出面板隧道命令；
4. 释放操作锁，用 `exec` 运行 `verify`。

撤除失败时退出码为 3，状态仍为"待确认"，但自动恢复可能已部分撤除，例如定时器已经停止。这时应重新执行 `confirm`，完成撤除。

`confirm` 不创建临时目录：最后的 `exec` 不会触发 EXIT 陷阱，目录会留在系统中。

### 2.7 自动恢复

**布置（第 6 步）。**

1. 待确认标记 `/var/lib/vps-hardening/pending`：记录 `apply` 会话的审计会话编号、截止时间和当前定时器的单元名。
2. 开机兜底单元 `/etc/systemd/system/vps-hardening-rollback.service`：内容与期望不同时才重写并 `daemon-reload`，然后启用，并核实已启用。
3. 临时定时器：`systemd-run --unit=vps-hardening-timeout-<纳秒时间>-<PID> --collect --on-active=<秒> --timer-property=AccuracySec=1s -- vps-hardening _restore timeout <单元名>`。核实定时器在运行后，把单元名写入标记，再读回核对。

几个设计要点：

- 每次布置都用新的单元名。第 10 步重新计时时，先启动新定时器、核实并写入标记，再停止旧的，所以任何时刻都至少有一个定时器在运行。旧定时器恰好在这期间触发时，`_restore` 发现标记中的单元名已经不是自己，就不做任何事。
- `AccuracySec=1s`：systemd 默认允许把到期时间推迟最多 1 分钟，以便合并唤醒，这里不允许。
- `--collect`：单元结束后被回收，失败的也一样，所以名称不会残留。

开机兜底单元的内容（路径为安装位置，省略注释行）：

```ini
[Unit]
Description=vps-hardening: restore the previous configuration after a reboot before confirmation
DefaultDependencies=no
ConditionPathExists=/var/lib/vps-hardening/pending
RequiresMountsFor=/var/lib/vps-hardening /usr/local/bin /usr/local/lib/vps-hardening
After=local-fs.target
Before=sysinit.target ssh.service ssh.socket ufw.service fail2ban.service network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vps-hardening _restore boot

[Install]
WantedBy=sysinit.target
```

- `DefaultDependencies=no` 配合 `Before=`：在 sshd、UFW、Fail2ban 启动之前、网络配置之前运行。
- `RequiresMountsFor`：状态目录、入口和模块所在目录都已挂载后才运行。
- `ConditionPathExists`：确认或恢复完成后标记被删除，单元即使仍是启用状态也不会运行。

**恢复。** 超时和应用失败时在运行中的系统上恢复（下表"运行时"），待确认期间重启后在开机时恢复。两种方式共用同一个函数，依次执行下表各步；前一步失败也继续执行后面的步骤，最后汇总结果：

| 步骤 | 运行时 | 开机时 |
|---|---|---|
| 状态改为"恢复中"，记录开始时间，写日志 | 是 | 是 |
| 停止所有恢复定时器 | 是 | 不需要：重启后定时器不存在 |
| 应用前 UFW 未启用时，`ufw --force disable` | 是 | 不需要：受管文件恢复后为 `ENABLED=no`，UFW 不会启用 |
| 按快照恢复 8 个受管文件 | 是 | 是 |
| `sshd -t` 通过后 `try-reload-or-restart ssh.service` | 是 | 不需要：sshd 尚未启动 |
| 恢复 4 个受管单元 | 恢复启用状态和运行状态 | 只恢复启用状态，不重新加载 systemd（`--no-reload`）；应用前未启用的单元，用 `--no-block stop` 取消已排队的启动 |
| 撤除自动恢复 | 停止定时器、停用开机兜底单元、删除标记 | 停用开机兜底单元（`--no-reload`）、删除标记 |
| 结果 | 全部成功时记为"已回滚"，记录时间和原因 | 同左 |

- 任一步失败时，状态记为"恢复失败"，终端或日志提示从服务商控制台检查 SSH 和 UFW。前面的步骤失败时不撤除自动恢复，保留标记和开机兜底单元，下次开机再试；撤除这一步本身失败时，标记或开机兜底单元可能已经去掉，下次开机不一定再试。
- 开机时只恢复启用状态，因为重启前的运行状态不应延续：应用前已启用的服务照常随开机启动，未启用的不启动。`apply` 启用的单元在本次开机的事务计算时仍是启用状态，它们的启动已经排进事务，所以要显式取消。

**快照的范围。** 快照在安装软件包之后记录：

- 软件包带来的文件，恢复为软件包的版本；
- 本工具新建的 4 个文件（SSH 片段、jail、`fail2ban.local`、APT 配置），恢复为不存在。

恢复每个文件时，先写到 `<路径>.vh-restore`，按记录设置权限和属主，再改名替换，最后核对摘要。

**互斥。** `apply`、`confirm` 和 `_restore` 共用 `/run/vps-hardening.lock`（`flock`）：

- `apply` 和 `confirm` 不等待，锁被占用时直接拒绝；
- `_restore` 最多等 15 分钟。取得锁后再检查标记：确认已经完成，或应用失败后已经自行恢复时，标记已不存在，它不做任何事；
- 锁文件在 `/run` 中，重启后不会残留。

### 2.8 状态记录

目录 `/var/lib/vps-hardening` 的权限为 0700，其中的文件都是 0600，属主 root（FR-13）：

| 文件 | 内容 |
|---|---|
| `state` | 每行一个 `键=值`，见下表 |
| `pending` | 只在待确认期间存在：`session`（`apply` 会话的审计会话编号）、`deadline`（截止时间，Unix 秒）、`timer`（当前定时器的单元名） |
| `units` | 每行一个受管单元：名称、应用前是否存在、`is-enabled`、`is-active`。受管单元为 `ufw.service`、`fail2ban.service`、`apt-daily.timer`、`apt-daily-upgrade.timer` |
| `snapshot/` | `index` 每行一个受管文件：`序号 present 摘要 权限:UID:GID 路径`，或 `序号 absent - - 路径`；`0`～`7` 是对应文件的副本 |
| `ufw-rules` | 应用后 `ufw status` 的规则行 |
| `log` | 带 UTC 时间的操作记录（恢复时每一步一行，便于定位耗时），以及软件包安装、UFW、Fail2ban 命令的输出 |

受管文件：SSH 片段、`/etc/default/ufw`、`/etc/ufw/ufw.conf`、`/etc/ufw/user.rules`、`/etc/ufw/user6.rules`、Fail2ban 的 jail 和 `fail2ban.local`、APT 配置。

`state` 中的键：

| 键 | 含义 |
|---|---|
| `status` | `applying`（应用中）、`pending`（待确认）、`applied`（已应用）、`restoring`（恢复中）、`rolled-back`（已回滚）、`restore-failed`（恢复失败） |
| `version` | 工具版本 |
| `started_at`、`applied_at`、`confirmed_at`、`restore_started_at`、`rolled_back_at` | UTC 时间 |
| `rollback_reason` | 回滚原因：确认超时、待确认期间重启，或应用失败及其原因 |
| `panel_port`、`open`、`confirm_timeout` | 输入参数；`open` 带地址族，如 `443/tcp/both` |
| `apply_session` | 发起 `apply` 的审计会话编号 |
| `denied_users` | 被禁止经 SSH 登录的账户 |
| `root_keys` | root 可用公钥的 SHA256 指纹，不记录公钥本身 |
| `ufw_was_active` | 应用前 UFW 是否已启用 |
| `packages_added` | 本次安装的软件包 |
| `digest.0`～`digest.7` | 应用后每个受管文件的 SHA-256（或 `absent`）和路径 |

- 写入方式：整个文件经 awk 生成新文件，改名替换后 `sync`，中途断电不会留下写了一半的文件。值中不允许换行。
- "恢复中"和"恢复失败"是方案设计第 7.3 节状态图之外新增的状态。恢复没有全部完成时不能记为"已回滚"，否则预检会允许再次应用。
- 记录中没有密码和私钥：工具不读取密码，也不开启 `set -x`。

## 3. preflight 检查项

前两项是门槛：不满足时立即结束，后续检查不执行。

| 编号 | 检查 | 不符合的条件 |
|---|---|---|
| `root` | 运行权限 | 不是 root |
| `platform` | 平台 | 不是 Debian 12/13 或 Ubuntu 24.04（x86_64/aarch64）；PID 1 不是 systemd；运行在容器中 |
| `inputs.*` | 输入摘要 | 不判定不符合：只回显已校验的面板端口、公开端口和确认时限；没有公开端口时 `inputs.open` 为警告 |
| `new-host.xui` | 存量判定 S1 | 存在 `x-ui.service` 或 `/usr/local/x-ui` |
| `new-host.container` | 存量判定 S4 | 存在 Docker（命令或 `docker.service`）或 Podman |
| `new-host.ufw` | 存量判定 S2 | UFW 已启用 |
| `new-host.fail2ban` | 存量判定 S3 | 有 `*.local`；`jail.d`、`fail2ban.d` 中有发行版 `defaults-debian.conf` 以外的文件；或 `dpkg --verify fail2ban` 报告改动 |
| `new-host.state` | 是否执行过 | 存在 `/var/lib/vps-hardening`，且状态不是"已回滚"。上次应用已完全回滚的主机仍算新机（FR-02，方案设计第 7.3 节）；待确认、已应用、恢复失败等状态都不符合 |
| `sshd.config` | sshd 配置 | `sshd -t` 失败，或 `sshd -T` 读不出生效配置 |
| `sshd.include` | 片段能否生效 | 主配置在 `Include /etc/ssh/sshd_config.d/*.conf` 之前已设置受管选项或打开了 `Match` |
| `sshd.dropin-order` | 片段排序 | 排在 `00-vps-hardening.conf` 之前的片段设置了受管选项或 `Match`，或本工具的片段已存在 |
| `root.key`、`root.keys` | root 的公钥（需求 FR-01、FR-03） | root 的 `authorized_keys`（按 root 的 `AuthorizedKeysFile` 生效值展开）中没有可用的公钥。可用指同时满足：行首就是密钥类型，不带选项（cloud-init 用 `command=` 前缀禁止 root 登录时，这样的行不算）；能被 `ssh-keygen -l -E sha256` 解析；算法在 `pubkeyacceptedalgorithms` 中（`ssh-rsa` 密钥以 `rsa-sha2-*` 判定）。按指纹去重，每把可用的公钥输出一行 `INFO root.key`（类型和指纹）；有未计入的行时，`root.keys` 注明行数 |
| `sudo.nopasswd-accounts` | 免密账户 | 只报告（`INFO`）：有 SSH 密钥且免密 sudo 的账户，应用时将被禁止 SSH 登录（需求 D13） |
| `apt.idle` | 包管理器 | dpkg、apt 或 unattended-upgrades 的锁被持有，或 apt、dpkg 进程在运行 |
| `apt.candidates` | 软件包来源 | `ufw`、`fail2ban`、`nftables`、`python3-systemd`、`unattended-upgrades` 中有没有候选版本的 |
| `apt.fail2ban-version` | Ubuntu 的 fail2ban | 候选版本低于 `1.0.2-3ubuntu0.1` |

受管的 sshd 选项：`permitrootlogin`、`passwordauthentication`、`kbdinteractiveauthentication`、`pubkeyauthentication`、`denyusers`。

## 4. verify 检查项

区域和判定依据见方案设计第 7.6 节。"有应用记录"指状态为"已应用"或"待确认"。各检查项的实现状态：

| 编号 | 判定 | 状态 |
|---|---|---|
| `root`、`platform` | 同 preflight 的门槛 | 已实现 |
| `state` | "已应用"时通过；"待确认"时为警告，注明约几分钟后自动恢复；没有状态目录、"已回滚"和其他状态为不符合 | M2 已实现 |
| `ssh.dropin` | SSH 片段的 SHA-256 等于应用时的记录 | M2 已实现；没有应用记录时跳过 |
| `ssh.denied` | 每个被禁账户：以它的身份执行 `sshd -T -C`，它在 `DenyUsers` 中，密码和键盘交互认证都是 `no` | M2 新增；没有被禁账户时不输出 |
| `ufw.rules` | `ufw status` 的规则行排序后与应用时的记录完全一致，多出或缺少规则都不符合；IPv4、IPv6 规则分别计 | M2 已实现；没有应用记录时跳过 |
| `ufw.panel` | 没有放行面板端口的规则，判定方法与 `ufw.port80` 相同 | M2 已实现；没有应用记录时跳过 |
| `uu.dropin` | 本工具的 APT 配置 `/etc/apt/apt.conf.d/52vps-hardening` 的 SHA-256 等于应用时的记录 | M3 新增；没有应用记录时跳过 |
| `boundary.panel-listen` | 安装了 3X-UI 时（判定同 `new-host.xui`），应用时声明的面板端口上的 TCP 监听地址都是回环地址（`127.0.0.0/8`、`::1`、`::ffff:127.0.0.0/104`）；有非回环地址时不符合；端口上没有监听时为警告，无法核对 | M3 实现；未安装 3X-UI 时为 `INFO`，没有应用记录时跳过 |
| `accounts.nopasswd` | 有密钥、免密 sudo、又不在 `DenyUsers` 中的登录账户 | 已实现 |
| `ssh.permitrootlogin`、`ssh.passwordauthentication`、`ssh.kbdinteractive`、`ssh.pubkey`、`ssh.forwarding`、`ssh.port` | 以 root 身份执行 `sshd -T -C` 的生效值：`without-password` 或 `prohibit-password`（`sshd -T` 用旧名 `without-password` 输出 `prohibit-password`）、`no`、`no`、`yes`、`yes` 或 `local`、`22` | 已实现；被禁账户另由 `ssh.denied` 检查 |
| `root.key`、`root.keys` | 同 preflight：root 至少有一把可用的公钥 | 已实现 |
| `ssh.listen` | 22 端口在 IPv4 上监听为必需；没有 IPv6 时为警告 | 已实现 |
| `ufw.installed`、`ufw.active`、`ufw.defaults`、`ufw.ipv6`、`ufw.port80` | 已安装并启用；默认拒绝入站、允许出站、拒绝转发；`IPV6=yes`；没有放行 80 端口的入站规则。转发策略：`ufw status verbose` 显示 `deny (routed)` 或 `disabled (routed)`，并且 `/etc/default/ufw` 中为 `DEFAULT_FORWARD_POLICY="DROP"`。内核没有开启转发时，ufw 把转发策略显示为 `disabled`（第 8.4 节） | 已实现；转发策略的判定在 M2 修改 |
| `f2b.installed`、`f2b.service`、`f2b.jails`、`f2b.mainconf` | 已安装；服务启用且运行；jail 只有 `sshd`；`jail.conf`、`fail2ban.conf` 未改动 | 已实现 |
| `f2b.config` | `fail2ban-client -t` 成功 | M3 新增 |
| `f2b.values` | 服务有响应时，读取 14 项生效值，逐项等于 FR-08（见下文）；服务没有响应时不符合 | M3 实现；期望值都是常量，不需要应用记录 |
| `f2b.files` | 本工具的 `jail.d/99-vps-hardening.local` 和 `fail2ban.local` 的 SHA-256 等于应用时的记录；`/etc/fail2ban` 下没有软件包和本工具以外的文件；`dpkg --verify fail2ban` 没有报告 `jail.conf`、`fail2ban.conf` 以外的改动（这两个文件由 `f2b.mainconf` 报告） | M3 新增；没有应用记录时跳过 |
| `nft.service` | `nftables.service` 未启用 | 已实现 |
| `uu.installed`、`uu.periodic`、`uu.reboot`、`uu.origins`、`uu.timers` | 已安装；两个 `APT::Periodic` 值为 1；不自动重启；来源列表与 FR-09 一致；两个 APT 定时器启用且运行 | 已实现 |
| `boundary.container`、`boundary.xui-bbr` | 没有 Docker 或 Podman；没有 `/etc/sysctl.d/99-bbr-x-ui.conf` | 已实现 |
| `reboot.required` | 存在 `/var/run/reboot-required` | 警告 |

`ufw.rules` 用 `ufw status` 而不用 `ufw show added`：后者丢失地址族，只放行 IPv4 的 `proto udp to 0.0.0.0/0 port 8443` 显示为 `ufw allow 8443/udp`，与两个地址族都放行的规则无法区分（第 8.4 节）。`ufw status` 只在 UFW 启用时列出规则，未启用时 `ufw.rules` 与 `ufw.active` 一起报告不符合。

Fail2ban 各项的输出顺序为 `f2b.installed`、`f2b.service`、`f2b.config`、`f2b.jails`、`f2b.values`、`f2b.files`、`f2b.mainconf`。`f2b.values` 的读取和比较：

- 14 项：`sshd` 的 `bantime`、`findtime`、`maxretry`、`bantime.increment`、`bantime.maxtime`、`bantime.rndtime`、`ignoreself`、`ignoreip`、`usedns`、`journalmatch`、`actions`，动作 `nftables` 的 `port` 和 `protocol`，以及全局的 `dbpurgeage`。每项用 `fail2ban-client get` 读取，有 30 秒超时。
- 规整：输出多于一行时去掉第一行的标题（例如 `Current match filter:`），去掉列表项前缀 `|- ` 和 `` `- ``，排序后用空格连接；`dbpurgeage` 的 `2592000seconds` 取数字。时间按秒比较（`1d` 为 86400，`4w` 为 2419200）；布尔值为 `True`；`ignoreip` 按服务器规整后的网络比较（`127.0.0.1/8` 显示为 `127.0.0.0/8`）。
- 读不回的两项：过滤模式 `mode=normal` 和 `banaction`。`banaction = nftables` 体现为动作名 `nftables` 和它的端口、协议，已在 14 项中；过滤模式只写在 jail 文件中，由 `f2b.files` 的摘要覆盖。
- 期望值都是 FR-08 的常量，所以 `f2b.values` 不需要应用记录（v0.3 写的是"需要应用记录中的声明值"，实现时确认只有 `boundary.panel-listen` 需要，它取记录中的面板端口）。

`f2b.files`、`uu.dropin` 与 M2 的 `ssh.dropin` 用同一个摘要判定。SSH 片段、jail 文件和 APT 配置的首行注释都写着"verify reports any change"，M2 只对 SSH 片段兑现了这一点；`f2b.config` 对应方案设计第 7.6 节 Fail2ban 区域的"配置检查通过"。这三项超出 v0.3 第 1 节列给 M3 的范围，已经用户确认（第 1 节）。

`uu.origins` 的期望集合（从 `apt-config dump` 读取，`${distro_*}` 占位符原样比较）：

- Debian：`Origins-Pattern` 为发行版默认的三项（`label=Debian`、两项 `Debian-Security`），`Allowed-Origins` 为空；
- Ubuntu：`Allowed-Origins` 为 `${distro_id}:${distro_codename}-security` 和两项 ESM 安全来源，`Origins-Pattern` 为空。

## 5. 模块划分

| 文件 | 职责 |
|---|---|
| `bin/vps-hardening` | 环境、加载模块、ERR 陷阱（应用期间先调用恢复钩子）、子命令分派、帮助 |
| `lib/vps-hardening/common.sh` | 常量、退出码、`report` 和汇总、临时目录、通用小函数 |
| `lib/vps-hardening/platform.sh` | 解析 `/etc/os-release`（按数据解析，不执行）、平台判定、systemd 和容器判断 |
| `lib/vps-hardening/inputs.sh` | 参数解析和校验 |
| `lib/vps-hardening/probe.sh` | 只读探测：软件包、单元、sshd 生效配置、账户和密钥（含 root 的可用公钥）、sudo、监听端口、UFW、apt 配置、包管理器锁 |
| `lib/vps-hardening/preflight.sh` | preflight 检查 |
| `lib/vps-hardening/verify.sh` | verify 检查 |
| `lib/vps-hardening/state.sh` | 状态目录：状态文件读写、操作日志、操作锁、受管文件的快照和恢复、受管单元状态的记录 |
| `lib/vps-hardening/pending.sh` | 待确认：会话判定、开机兜底单元、临时定时器、布置和撤除自动恢复、恢复、`confirm`、`_restore` |
| `lib/vps-hardening/apply.sh` | `apply`：变更计划、交互确认、各步骤的写入和核实、失败处理 |

## 6. 实现约束

- **只读。** preflight 和 verify 只调用读取类命令；临时文件只写在 `mktemp -d` 创建的私有目录中，退出时删除。测试在每个用例前后比较状态摘要（第 7.4 节）。
- **有界。** 可能被服务阻塞的读取命令（`sshd`、`ufw`、`fail2ban-client`、`apt-config`、`apt-cache`、`sudo -l`）加 30 秒超时。`apply` 和恢复中改变系统的 `systemctl`、`ufw`、`systemd-run` 命令加 120 秒超时，软件包安装 30 分钟（方案设计第 7.5 节）。Bash 要等当前命令返回才执行信号陷阱，不设超时的话，一个卡住的命令会同时挡住断线后的恢复；定时器触发的恢复等锁 15 分钟后也会放弃。
- **写入。** 受管文件先写到 `<路径>.vh-new`，设权限 0644 后改名替换；状态文件同样改名替换（第 2.8 节）。`apply` 中 `apt-get` 的标准输入为 `/dev/null`，不会读走管理员终端上的输入。
- **管道与 `pipefail`。** 读取端不提前退出（不用 `head`、`grep -q` 截断长输出），否则写入端会因 SIGPIPE 失败，在 `pipefail` 下被误判。`apt-config dump` 的输出缓存后复用。
- **sshd 生效值。** 用 `sshd -T -C user=<用户>,host=vps-hardening.invalid,addr=192.0.2.1,laddr=192.0.2.2,lport=22` 按用户求值，结果按用户缓存。地址取自文档保留地址，使 `Match Address` 块按"普通外部来源"求值。
- **包管理器是否在运行。** 以锁的持有者（`lslocks`）为准，再加 apt、dpkg 进程名。进程名逐个交给 `pgrep -x`：整个模式超过 15 个字符时 pgrep 不匹配任何进程，用 `|` 拼接的模式会静默失效。不能用进程名判断 unattended-upgrades：它的关机辅助进程常驻，进程名截断后与升级进程相同。
- **ERR 陷阱。** 只在主 shell 中把意外失败转换为退出码 3。`$(...)` 和管道中的命令也会触发陷阱，其中包括预期的非零状态（如查询未安装的单元），所以子 shell 中不处理；真正的失败经退出状态回到主 shell 后再判定。
- **启发式判定。** `root.keys` 只计入格式明确的公钥行（带选项的行即使实际能登录也不计入），`new-host.fail2ban` 以文件存在为准。两者在不确定时都判为不符合，宁可误拒，不会误放行。

## 7. 测试框架

### 7.1 组成

| 文件 | 作用 |
|---|---|
| `tests/vm.py` | 运行器侧：下载并校验官方云镜像，生成 cloud-init 种子，启动 QEMU，按阶段在客体中执行测试，收集证据。改编自 vps-tuning 的 `tests/platform-vm.py` |
| `tests/guest/m1.sh` | 客体侧：M1 各阶段的准备、用例和判定，以及 `apply` 被预检拒绝的用例 |
| `tests/guest/m2.sh` | 客体侧：M2 的状态记录、第二来源、登录和端口检查、恢复后的核对；复用 `m1.sh` 的函数 |
| `tests/guest/m3.sh` | 客体侧：M3 的 Fail2ban、自动更新、3X-UI 共存和漂移用例；复用 `m2.sh` 的函数 |
| `tests/platform-images.json` | 镜像 URL 和摘要，与 vps-tuning 同源 |
| `tests/static.sh` | 不需要虚拟机的检查：shell 和 Python 语法、LF 行尾、通用秘密特征 |
| `.github/workflows/static.yml` | 运行 `tests/static.sh` 和 ShellCheck 0.11.0（固定容器镜像）。ShellCheck 只报告命令行列出的文件，不报告经 `-x` 跟随的文件，所以列出全部模块 |
| `.github/workflows/vm.yml` | matrix、recovery、negative 和 hardened 四组作业，证据作为构件保存 14 天。拉取请求和推送只运行 amd64；手动触发并选中 `arm64` 时，matrix、recovery 和 hardened 另在 arm64 上运行（需求 D26） |

### 7.2 客体初始状态

按验证计划第 3.2 节，由 cloud-init user-data 显式写入：

- `disable_root: false`，root 和镜像默认用户使用同一把测试驱动的密钥；默认用户由镜像的 cloud-init 配置赋予免密 sudo，测试开始前逐项核实（`check_profile`）；
- root 密码由 `runcmd` 经 `chpasswd` 设置，每次运行随机生成，同时作为泄露扫描的标记；
- `write_files` 写入 `/etc/ssh/sshd_config.d/50-cloud-init.conf`，内容为 `PasswordAuthentication yes`。

测试环境与"典型新机"的两处差异，都只为排除干扰：

- 每次启动后在运行期停止 `apt-daily.timer` 和 `apt-daily-upgrade.timer`（不改变启用状态），并等待包管理器空闲；
- 准备阶段用精简的 `apt-get update`：不下载翻译、AppStream 和 command-not-found 索引。

M2 的测试在此基础上增加以下内容，都只为测试服务：

- **默认用户的密码。** cloud-init 把同一个随机密码也设给镜像默认用户（UID 1000），用作 VT-13 的对照：应用前能用密码登录，应用后不能。密码只存放在客体的 `/root/vh-private` 中，不进证据。
- **客体内生成的密钥。** root 的 `authorized_keys` 追加一把 RSA 公钥（管理员实际使用 RSA，验证计划第 3.4 节），默认用户追加一把 Ed25519 公钥，供第二来源登录。
- **第二来源。** 客体内的网络命名空间 `vh-src`，经 veth 连接，地址取文档保留段 `192.0.2.0/24` 和 `2001:db8::/64`（验证计划第 3.3 节）：
  - 应当成功的登录和端口检查用 `.2` 地址；
  - 每种故意失败的登录各用一个地址：`.3` root 密码，`.4` 默认用户密码，`.5` 默认用户密钥。这样 Debian 13 sshd 的惩罚和 Fail2ban 的封禁都不会影响后续检查。失败的登录排在每个阶段的最后。
- **测试用 HTTP 服务。** 用 `systemd-run` 运行 `python3 -m http.server`，监听 `::`，同时接受 IPv4 和 IPv6。VT-15 的面板替身只监听 `127.0.0.1:2053`。
- **自动更新。** `apply` 会 `enable --now` 两个 APT 定时器。为免测试期间真的执行升级（升级可能重启 sshd，打断持续探测），基线阶段在 `/run` 下给 `apt-daily-upgrade.service` 加 drop-in，把 `ExecStart` 换成 `/bin/true`；重启后重新放置。不用屏蔽（mask）：触发的服务被屏蔽时，定时器无法启动，`apply` 的这一步会失败。
- **交互。** `apply` 经 `ssh -tt` 在伪终端中运行；测试驱动看到确认提示后输入 `yes`，与管理员的操作相同。工具中没有任何测试开关。

M3 的测试（hardened 套件）在 M2 的基础上再增加以下内容：

- **更多第二来源地址。** 每个用例一个地址，使 Fail2ban 的封禁和 Debian 13 sshd 的惩罚不会延续到下一个用例：`.6` VT-31；`.7` VT-33 的封禁；`.8` VT-33 的递增封禁；`.9` VT-34 的 ssh-agent 和 `IdentitiesOnly` 登录；`.10` VT-34 的认证前断开。VT-32 手工封禁 `203.0.113.123`（文档保留地址，不发出流量）。
- **失败样本。** 用不存在的用户名 `vh-nouser-<序号>` 和一把 Ed25519 密钥登录，与扫描器的客户端相同。相邻两次至少间隔 6 秒：Debian 13 sshd 的 `authfail` 惩罚为 5 秒，累积到 15 秒才执行（第 8.2 节），所以每次都能到达 sshd。尝试没有得到认证失败的结果时（被惩罚拒绝或连接出错），重试，每个样本最多尝试 3 次；来源已被封禁时，这次尝试算作完成。每次尝试的时间和结果写入证据。
- **APT 定时器保持运行。** `apply` 启用的两个定时器在 M3 中不停止（`verify` 要求它们运行）；需要包管理器的步骤（安装 3X-UI、dry-run）之前等待它空闲。M2 基线中 `apt-daily-upgrade.service` 的空操作替换仍然有效，重启后重新放置。
- **3X-UI 夹具。** 按验证计划第 3.5 节在确认之后安装（`XUI_PANEL_PORT=2053`，监听改为 `127.0.0.1`）。`install.sh` 解压后会删除发布包，所以 VO-1 在解压后的文件上核对：`/usr/local/x-ui/x-ui` 和 `/usr/local/x-ui/bin/xray-linux-<架构>` 的 SHA-256 等于从发布包中取得的值（验证计划第 3.5 节），`/usr/local/x-ui/x-ui.sh` 等于 tag 中的 `x-ui.sh`。负向套件的 S1 使用同一个安装函数。
- **面板的 WebBasePath。** 由测试驱动在客体中读取（`x-ui setting -show true`），只用于经隧道访问；它被加入泄露扫描的标记，不写入证据。

### 7.3 套件与用例

| 套件 | 平台 | 内容 |
|---|---|---|
| matrix | 三平台 amd64；arm64 按需（参考） | 准备；核实转发连接在客体中的来源地址；VT-01；VT-50 的未加固部分；sshd 探测研究。然后在同一客体上执行 M2 的主流程：应用 → 三种被拒绝的确认 → 从新会话确认 → 核对 → 隧道 → 重启后核对 |
| recovery | 三平台 amd64；arm64 按需（参考） | 准备好的磁盘为底，两个覆盖层：确认超时（时限 3 分钟，应用后不确认）；待确认期间从应用会话重启 |
| negative | 三平台 amd64 | 准备；VT-02、VT-04；关机后以准备好的磁盘为底，S1～S4 各用一个覆盖层磁盘启动（VT-03）；S2 中检查 UFW 是否过滤转发连接；再用一个覆盖层执行 VT-23 |
| hardened | 三平台 amd64；arm64 按需（参考） | 准备，记录基线；`apply --open 443/tcp --open 2096/tcp`（3X-UI 的入站和订阅端口），从新会话确认；VT-30、VT-31、VT-33 和 VT-35、VT-32、VT-34、VT-40；安装 3X-UI（VT-55 第一部分、VT-50、VT-71）；经隧道打开面板；重启后核对（VT-55 第二部分）。以上全程持续探测（VT-25）。关机后以这块磁盘为底，9 个覆盖层各注入一项漂移（VT-51） |

M1 用例的判定要点：

- VT-01：`preflight` 退出码为 0，`root.keys` 通过，前后状态摘要一致；
- VT-50（未加固）：`verify` 退出码为 1；`state`、`ssh.passwordauthentication`、`accounts.nopasswd`、`f2b.installed` 为不符合，Debian 上 `ufw.installed`、Ubuntu 上 `ufw.active` 为不符合；`ssh.permitrootlogin`（镜像默认已是 `prohibit-password`）、`root.keys`、`ssh.pubkey`、`ssh.port`、`nft.service`、`boundary.container`、`boundary.xui-bbr` 为通过；前后摘要一致；所有证据中没有测试密码；
- VT-02：非 root（`runuser -u nobody`）、不支持的版本（在私有挂载命名空间中覆盖 `/etc/os-release`）、root 没有可用的公钥（同样在私有挂载命名空间中，用只有注释、只有带 `command=` 选项、只有无法解析的行三种文件覆盖 root 的 `authorized_keys`）、dpkg 前端锁被占用、有不持锁的 `dpkg` 进程，分别得到对应的不符合项或退出码 2；
- VT-03：S1～S4 各自得到 `new-host.xui`、`new-host.ufw`、`new-host.fail2ban`、`new-host.container` 不符合，并提示"存量主机不在支持范围内"，`preflight` 前后摘要一致；
- VT-04：第 2.4 节的各类非法输入退出码为 2，已删除的参数（`--maxretry`）按未知参数处理；root 同时有 Ed25519 和 RSA 公钥时两把都被识别；时限 3 和 60 被接受；标准输入不是终端时 `apply` 被拒绝。
- VT-02、VT-03 中 `apply` 的部分（M2 补测）：`apply` 在伪终端中运行，不输入任何内容。非 root、不支持的版本、root 只有带 `command=` 选项的公钥、dpkg 前端锁被占用这 4 种情况，以及 S1～S4，都在预检阶段被拒绝：退出码 1，对应的检查项不符合，输出"预检有不符合项，未做任何变更"（非 root 时在预检之前就被拒绝）；S1～S4 还提示"存量主机不在支持范围内"。S1～S4 的 `preflight` 和 `apply` 在同一对状态摘要之间执行，摘要一致。

M2 用例的判定要点（验证计划第 4.2、4.3 节）：

- VT-10：`apply` 退出码为 0，输出"加固已应用，等待确认"；从新的 root 会话执行 `confirm`，输出"已确认"，随后的 `verify` 退出码为 0；状态为"已应用"，标记、开机兜底单元和定时器都已撤除；重启后 boot ID 改变，`verify` 退出码仍为 0。
- VT-11：默认用户用自己的密钥从第二来源登录被拒绝；root 的 `authorized_keys`、`/etc/sudoers`、`/etc/sudoers.d` 的摘要和 `sudo -l -U <默认用户>` 的输出与基线一致。
- VT-12：测试密码和客体私钥的内容不出现在状态目录、客体证据和基线之后的 journal 中；状态目录中不出现 root 的完整公钥；测试驱动另外扫描全部证据，查找测试密码和客户端私钥。
- VT-13：以 root 和默认用户分别执行 `sshd -T -C`：密码和键盘交互认证为 `no`，root 的 `permitrootlogin` 为 `without-password`、`pubkeyauthentication` 为 `yes`，默认用户在 `DenyUsers` 中；`50-cloud-init.conf` 仍含 `PasswordAuthentication yes`；从第二来源，root 密钥登录在 IPv4 和 IPv6 上都成功，root 密码、默认用户密码和密钥登录都被拒绝；22 端口的监听地址与基线一致。
- VT-14：`ufw status verbose` 的默认策略符合第 4 节；规则与声明的 6 条完全一致（`--open 443/tcp --open 2096/tcp/ipv6 --open 8443/udp/ipv4`）；从第二来源，443 在 IPv4 和 IPv6 上都可达，2096 只在 IPv6 上可达，2053、8080、80 在两个地址族上都不可达；从运行器经 QEMU 转发，只有 443 可达。
- VT-15：取 `apply` 输出中的隧道命令，只替换私钥和地址两个占位符，加上测试的主机密钥和端口选项；不建隧道时本地 8443 端口没有应答，建隧道后返回 HTTP 200。
- VT-20：时限 3 分钟，`apply` 的会话随即结束；待确认期间 root 能登录，8080 端口不可达；状态变为"已回滚"；恢复的开始时间（`restore_started_at`）与 `applied_at` 相差不少于时限减 5 秒、不多于时限加 60 秒，恢复耗时不超过 600 秒（模拟环境下可达数分钟，附录 A），测试驱动最多等 900 秒；`sshd -T`、UFW、受管文件、受管单元与基线一致，软件包保留；root 和默认用户都能登录，8080 端口恢复可达。
- VT-21：不确认的情况即 VT-20；确认的情况在主流程中：`apply` 的会话结束后，从新会话确认，之后不再恢复（重启后状态仍为"已应用"）。
- VT-22：同一会话中执行 `apply` 后立即 `systemctl reboot`；boot ID 改变；开机兜底单元的日志中有"已恢复到应用前的配置"，它的结束时间早于 `ssh.socket`、`ssh.service`、`ufw.service` 进入运行状态的时间；受管单元的启用状态与基线一致，应用前不存在的单元没有运行；`sshd -T`、UFW、受管文件与基线一致，软件包保留，root 和默认用户都能登录。
- VT-23：先安装发行版的 Fail2ban 并屏蔽 `fail2ban.service`；`apply` 在 Fail2ban 步骤失败，退出码为 1，输出"正在恢复应用前的配置"和"已恢复到应用前的配置"；状态为"已回滚"，原因含"应用失败"；`sshd -T`、UFW、受管文件、受管单元与基线一致，软件包保留，root 和默认用户都能登录。
- VT-24：在 `apply` 的会话中执行 `confirm`（提示另开终端）、默认用户在应用前打开的会话中经 `sudo` 执行 `confirm`（提示经 sudo 切换不算）、确认之后再执行 `confirm`（提示没有待确认的变更），都以退出码 1 被拒绝；前两次之后状态仍为"待确认"，标记、开机兜底单元和一个定时器都在。
- VT-25：每个流程期间，测试驱动每 3 秒用 root 的密钥登录一次（间隔依据第 8.2 节的 VO-2 结论）；失败时 1 秒后重试一次，两次都失败才算失败，只允许发生在声明的重启窗口内；证据记录每次探测的起止时间和第一次失败的错误信息；每次状态切换（待确认、确认后、重启后、恢复后）用当时应当可用的身份登录一次，恢复后 root 和默认用户都要能登录。
- VT-62：状态目录为 0700、其中文件为 0600，属主 root；状态文件含版本、时间、输入参数、会话编号、被禁账户、公钥指纹、新装的软件包和 8 个文件摘要；快照索引列出 8 个文件。
- VT-70：APT 源列表和密钥环的摘要与基线一致。
- VT-71（SSH 和 UFW 部分）：vps-tuning 管理的 17 项 sysctl（取自 vps-tuning `v0.2.0-rc.4` 的 `PROFILE_SYSCTL_KEYS`）和 qdisc 与基线一致；`/etc/ufw/sysctl.conf` 不变，UFW 由 `apply` 安装时等于软件包的版本。

M3 用例的判定要点（验证计划第 4.4～4.7 节）：

- VT-30：`fail2ban-client -t` 退出码为 0；服务启用并运行；`ping` 返回 `pong`；`status sshd` 中的 `Journal matches` 等于 FR-08 的 `journalmatch`；jail 列表只有 `sshd`；14 项 `get` 的原始输出与预期文本逐字一致（与 `verify` 的规整逻辑相互独立）；`jail.conf`、`fail2ban.conf` 的摘要等于软件包记录的摘要；17 项 sysctl、qdisc 与基线一致，`/etc/ufw/sysctl.conf` 不变。随后的 `verify` 退出码为 0、前后摘要一致，`f2b.config`、`f2b.jails`、`f2b.values`、`f2b.files`、`f2b.mainconf`、`uu.dropin` 都通过。
- VT-31：从 `.6` 做 1 次失败样本；按 jail 计数的增量，样本数的两倍仍低于 `maxretry` 时再做第 2 次，所以这个来源不会被封禁。判定：journal 中有与样本数相同的 `Invalid user` 记录；`fail2ban-regex -o ip --journalmatch <FR-08 的值> systemd-journal 'sshd[mode=normal]'` 中该来源的匹配数不少于样本数，并且等于 jail 计数的增量；来源没有被封禁。每个样本被匹配几次取决于 sshd 的日志行数，所以"匹配数与样本数一致"按"每个样本都被匹配，且匹配数与 jail 的计数一致"操作化。
- VT-33：`.7` 在不超过 5 次失败后被封禁；封禁时长在 86400～87000 秒之间（首次封禁不加随机时长，第 8.8 节）；该地址在 `inet f2b-table` 中；它的登录在连接阶段就被拒绝；测试驱动和 `.2` 的 root 登录不受影响。递增：运行期把 `bantime` 设为 20 秒，`.8` 第一次封禁为 20 秒，到期解封后再次触发，第二次封禁在 40～640 秒之间（`bantime.increment` 加倍，`bantime.rndtime` 最多加 600 秒）；之后 `reload sshd`，`bantime` 回到 86400。
- VT-35：VT-33 期间所有提到 `.7` 的 journal 记录都在 FR-08 的 `journalmatch` 范围内（`_SYSTEMD_UNIT=ssh.service`，或 `_COMM` 为 `sshd`、`sshd-session`）；三个平台都归档各记录的 `_COMM` 和 `SYSLOG_IDENTIFIER`。
- VT-32：`banip` 后该地址在 `inet f2b-table` 中，`unbanip` 后消失；中途中断（向执行封禁的进程发送 TERM）时，清理逻辑解封；全程 `.2` 的 root 密钥登录成功。
- VT-34：ssh-agent 中依次有 3 把错误的 Ed25519 密钥和正确的 RSA 密钥，从 `.9` 以 root 登录 6 次；`IdentitiesOnly=yes` 登录 6 次；从 `.10` 6 轮"读到版本信息就断开"加一次键盘交互认证被拒（服务器不提供这种方式，在认证前断开）。三组的计数增量都为 0，两个来源都没有被封禁；归档 sshd 的惩罚日志。
- VT-40：`apt-config dump` 中三个值符合要求；两个 APT 定时器启用并运行；`unattended-upgrade --dry-run --debug`（限时 15 分钟）退出码为 0，`Allowed origins are:` 列出的来源集合等于 D19：Debian 为 `label=Debian`、两项 `Debian-Security`（展开后的形式），Ubuntu 为 `<代号>-security` 和两项 ESM 安全来源。
- VT-55、VT-50、VT-71（安装 3X-UI 后）：安装前后，root 和默认用户的 `sshd -T`、UFW、受管文件、受管单元、Fail2ban 的 6 项生效值、17 项 sysctl 和 qdisc 都不变；`verify` 退出码为 0，没有不符合、警告和跳过，`boundary.panel-listen` 通过，前后摘要（含 3X-UI 的文件）一致。经 `apply` 输出的隧道命令访问 WebBasePath，返回 HTTP 200 和标题为 `Sign in` 的登录页。重启后 boot ID 改变，`verify` 的判定相同。
- VT-51：每项漂移注入后，`verify` 的不符合项集合和警告项集合与下表完全一致（多报、少报都算失败），前后摘要一致，没有内部错误：

| 漂移 | 注入方式 | 期望 |
|---|---|---|
| `firewall-install` | 3X-UI 菜单：防火墙 → 安装防火墙 | 退出码 0，没有不符合项；UFW 不变，菜单输出 `Firewall is already active`（第 9 节） |
| `firewall-reinstall` | 菜单：防火墙 → 停用防火墙，再安装防火墙 | `ufw.panel`、`ufw.port80`、`ufw.rules` |
| `iplimit` | 菜单：IP Limit → 安装 | `f2b.files`、`f2b.jails`、`f2b.mainconf` |
| `listen-all` | `x-ui setting -listenIP 0.0.0.0` 并重启 x-ui | `boundary.panel-listen` |
| `bbr` | 菜单：BBR → 启用 | `boundary.xui-bbr` |
| `ufw-rule` | `ufw allow 8080/tcp` | `ufw.rules` |
| `nftables` | `systemctl enable nftables.service` | `nft.service` |
| `sshd-dropin` | 在 SSH 片段末尾追加一行注释 | `ssh.dropin` |
| `reboot-required` | 创建 `/var/run/reboot-required` | 退出码 0，只有警告 `reboot.required` |

  菜单经标准输入应答，使用 tag 中已校验的 `x-ui.sh`（验证计划第 3.5 节）；菜单在输入意外时会递归调用自身，所以每次限时 300 秒。

### 7.4 状态摘要

每个用例前后各采集一次，逐行比较：

- `/etc` 下每个对象的类型、权限、属主和链接目标，以及每个普通文件的 SHA-256；
- root 和 `/home` 下各账户 `.ssh` 中的文件摘要；
- `nft -s list ruleset`，以及去掉注释和计数器的 `iptables-save`、`ip6tables-save`；
- `ufw status verbose`；
- 全部单元文件的启用状态（不含会话 scope），以及相关服务和定时器的启用、运行状态；
- 软件包列表；工具状态目录是否存在；
- 安装了 3X-UI 时，`/usr/local/x-ui` 下各文件和 `/usr/bin/x-ui` 的 SHA-256（M3 新增）。

排除项只有两类，都由其他进程在测试期间改变：

- 规则计数器：随测试自身的 SSH 流量变化；
- 3X-UI 数据库 `/etc/x-ui/x-ui.db` 及其 `-wal`、`-shm` 文件的内容（权限和属主仍比较）：运行中的面板会自行写入。首轮 CI 中，Debian 12 和 Debian 13 的 S1 都在 preflight 前后观察到这两个文件的变化，而 preflight 对 3X-UI 只做 `systemctl cat` 和文件存在判断。

### 7.5 验证计划第 3.3 节推断的核实方法

| 推断 | 核实方法 |
|---|---|
| 经端口转发的连接在客体中显示为 QEMU 网关地址，不是回环地址 | 每组平台都在客体中读取 `SSH_CONNECTION` 的来源地址 |
| 因此这些连接受 UFW 约束 | S2 中，在启用 UFW 前后分别访问客体的 8080（放行）和 2096（未放行）端口上的 HTTP 服务 |
| 连续探测的方式和间隔（VO-2） | 每组平台都做三组探测并记录 sshd 日志：30 次间隔 0.1 秒、不认证就断开的连接；20 次间隔 2 秒的同类连接；10 次间隔 0.5 秒的密钥登录。每组之后检查密钥登录是否立即可用，不可用时记录恢复时间 |

## 8. 运行证据

来源：GitHub Actions 运行 `39389558685`（v0.2 的代码，commit `e3de443`，2026-10-20），9 个作业全部通过；只改动文档的复核运行 `39391825013`（commit `4925946`）同样全部通过，VT-01～VT-04、VT-50 的结果一致。v0.1 的代码对应运行 `38438964687`（commit `63dda79`，2026-10-13）和代码未变的复核运行 `38503522626`（commit `7ef6e0f`），同样全部通过。证据构件 `vm-matrix-*`、`vm-negative-*` 保留 14 天。按验证计划第 6 节逐项核对了构件，不以 CI 状态为准。证据层次为"虚拟机生命周期"，不代表真实主机。除注明的以外，第 8.1 节的结果来自运行 `39389558685`。

第 8.1～8.3 节是 M1 的证据，第 8.4～8.6 节是 M2 的证据，第 8.7～8.9 节是 M3 的证据。按需求 D26，arm64 只作参考：第 8.1、8.2 节按当时的需求记录了 M1 的 arm64 结果，保持原样；M2 起 arm64 的结果放在附录 A。

### 8.1 结果

| 套件 | 平台 | 加速 | 作业时长 | 结果 |
|---|---|---|---|---|
| matrix | Debian 12 / 13、Ubuntu 24.04，amd64 | KVM | 2 分 15 秒～2 分 33 秒 | 通过 |
| matrix | 同上，arm64 | TCG | 10 分 30 秒～11 分 35 秒 | 通过 |
| negative | 三平台 amd64 | KVM | 2 分 41 秒～3 分 35 秒 | 通过 |

- 作业时长远低于 45 分钟的上限，arm64 不需要拆分作业（VR-2）。arm64 运行器上没有 `/dev/kvm`，使用 TCG。
- VT-01：6 组平台上 `preflight` 退出码均为 0，`root.keys` 通过（cloud-init 写入的一把 Ed25519 测试密钥），前后摘要一致。
- VT-50（未加固）：6 组平台上 `verify` 退出码均为 1，没有警告，没有内部错误，前后摘要一致，证据中没有测试密码。不符合项：
  - Debian 12、13：`state`、`accounts.nopasswd`、`ssh.passwordauthentication`、`ufw.installed`、`f2b.installed`、`uu.timers`；
  - Ubuntu 24.04：以 `ufw.active` 代替 `ufw.installed`，另有 `uu.origins`：发行版默认的 `Allowed-Origins` 含发布仓库本身 `${distro_id}:${distro_codename}`，FR-09 不含它（方案设计第 7.4 节）；
  - `uu.timers` 是测试环境造成的：测试在运行期停止了两个 APT 定时器（第 7.2 节），不代表镜像的状态；
  - `ssh.permitrootlogin` 在 6 组平台上都通过，镜像默认的生效值为 `without-password`。v0.1 按"禁止 root 登录"判定时，它在 6 组平台上都是不符合项。
- VT-02、VT-04：三平台各 25 个调用（v0.1 为 35 个：删去了管理用户和公钥文件的输入用例，新增 root 公钥的 4 个用例和已删除参数的用例），退出码和输出全部符合预期。root 没有可用公钥的 3 个用例中，`root.keys` 是唯一的不符合项；两把公钥的用例列出 Ed25519 和 RSA 各一行 `INFO root.key`，而主机本身只有一把 Ed25519 密钥，说明私有挂载命名空间中的覆盖生效。
- VT-03：三平台上 S1～S4 各自只有对应的一项存量判定不符合，`root.keys` 通过，`preflight` 前后摘要一致。S1 中面板只监听 `127.0.0.1:2053`。

### 8.2 验证计划第 3.3 节的推断

| 推断 | 结果 |
|---|---|
| 经端口转发的连接在客体中的来源地址 | 已核实：6 组平台上都是 QEMU 网关地址 `10.0.2.2`，不是回环地址；四次运行结果一致 |
| 这些连接受 UFW 约束 | 已核实（三平台 amd64）：启用 UFW 前，8080 和 2096 都能访问；启用后（只放行 22 和 8080），8080 能访问，2096 不能；四次运行结果一致 |
| 连续探测的方式和间隔（VO-2） | 已确定，见下文 |

探测研究的结果：

| 平台 | OpenSSH | 30 次不认证的连接，间隔 0.1 秒 | 20 次同类连接，间隔 2 秒 | 10 次密钥登录，间隔 0.5 秒 |
|---|---|---|---|---|
| Debian 13 amd64 | 1:10.0p1-7+deb13u4 | 来源被封：之后的密钥登录立即失败，四次运行分别在 15.5、20.4、20.4、15.3 秒后恢复 | 未被封 | 全部成功 |
| Debian 13 arm64 | 同上 | 四次运行中三次来源被封，分别在 30.4、28.0、30.8 秒后恢复；第三次（`39389558685`）未被封，sshd 日志中没有惩罚记录 | 未被封 | 全部成功 |
| Debian 12、Ubuntu 24.04（两种架构） | 1:9.2p1、1:9.6p1 | 未被封（没有该功能） | 未被封 | 全部成功 |

- Debian 13 的 sshd 默认启用 `PerSourcePenalties crash:90 authfail:5 noauth:1 grace-exceeded:10 refuseconnection:10 max:600 min:15 …`，豁免列表为空。日志记录为 `drop connection … penalty: connections without attempting authentication`。
- 结论（供 M2 使用）：测试驱动的连续探测使用密钥登录（`ssh … true`），间隔不小于 2 秒；不使用快速的"连上就断开"式探测。失败登录仍只从第二来源发起，每次运行归档惩罚日志。
- Debian 13 arm64 第三次运行的惩罚设置与其他三次相同，却没有被封。惩罚是否触发与连接的实际速率和并发有关；TCG 下连接建立较慢，可能来不及累积到 `min` 的 15 秒（推断，未单独核实）。这不改变上面的结论：快速探测的结果不稳定，测试驱动本来就不使用它。
- 置信度：中。每个平台运行了四次，环境是 CI 虚拟机；观察结果与 sshd_config(5)（OpenBSD-current 版，2026-10-13 查阅）的说明一致：`noauth` 指不尝试认证就断开的客户端被拒绝的时长，默认 1 秒；`min` 是开始执行前必须累积的最小惩罚，默认 15 秒；同一来源并发连接的惩罚会累积。"2 秒间隔不会累积"是由该语义推断的，只在 20 次、40 秒的窗口内观察过。

### 8.3 首轮 CI 发现并已修复的问题

首轮运行 `38437908056`（commit `71bd28b`）中有 6 个作业失败，原因和修复：

| 问题 | 影响 | 修复 |
|---|---|---|
| `set -E` 使 ERR 陷阱在 `$(...)` 中对预期的非零状态也触发 | 6 组 matrix 中 `verify` 输出"内部错误"，被测试判为失败 | 陷阱只在主 shell 中处理（第 6 节） |
| `pgrep -x` 的整个模式超过 15 个字符时不匹配任何进程 | `apt.idle` 的进程判断从未生效，且没有任何报错 | 逐个进程名匹配；VT-02 增加不持锁 `dpkg` 进程用例。这个问题是从测试脚本自身打印的 pgrep 警告发现的 |
| 运行中的 3X-UI 面板改写 `/etc/x-ui` 下的数据库文件 | Debian 12、13 的 S1 前后摘要不一致 | 摘要排除这些文件的内容（第 7.4 节） |

### 8.4 M2 实现前的研究运行

来源：GitHub Actions 运行 `39397581119`（研究分支 `claude/m2-research-20261020`，只含研究脚本，不合并，2026-10-20），6 组平台。目的是在编写 `confirm` 和重新加载逻辑之前，先核实 DR-11、DR-4 和几项 UFW、systemd 行为。

| 问题 | 结果 |
|---|---|
| DR-11：能否用审计会话编号区分新旧 root 会话 | 成立（6 组平台）。每个 root SSH 会话的 `sessionid` 都不同（例如 Debian 13 amd64 上依次为 6、7、8），`loginuid` 为 0；默认用户的会话，以及其中的 `sudo`、`sudo su`，`loginuid` 都保持 1000；祖先进程链中有 `sshd`（Debian 12、Ubuntu 24.04）或 `sshd-session`（Debian 13）。无须启用替代方案 |
| DR-4：`try-reload-or-restart ssh.service` 的效果 | 成立（6 组平台）。`ExecReload` 依次为 `sshd -t` 和 `kill -HUP $MAINPID`，执行前后主进程号相同；新配置立即生效：登录被拒时，服务器列出的认证方式从 `publickey,password` 变为 `publickey`。Ubuntu 24.04 上 `ssh.service` 为运行、未启用，`ssh.socket` 为运行、启用，结果相同 |
| 重新加载后立即发起的连接 | Debian 12（两种架构）上，这个连接得到 `kex_exchange_identification: read: Connection reset by peer`。推断原因：sshd 收到 SIGHUP 后重新执行自身，期间新连接被重置。其他平台没有出现 |
| UFW 规则的列出方式 | `ufw show added` 丢失地址族：`ufw allow proto udp to 0.0.0.0/0 port 8443` 显示为 `ufw allow 8443/udp`。`ufw status` 按地址族分别列出，结果正确 |
| UFW 转发策略的显示 | 执行 `ufw default deny routed` 后，内核没有开启转发时，`ufw status verbose` 仍显示 `disabled (routed)` |
| UFW 的单元状态 | 安装软件包后 `ufw.service` 已经是启用状态；`ufw --force enable` 之后，Debian 13 上为启用、未运行，Ubuntu 上为启用、运行。`ufw disable` 把 `ufw.conf` 改为 `ENABLED=no` |
| 临时定时器 | `systemd-run --on-active=… --timer-property=AccuracySec=1s` 按时触发；加 `--collect` 后单元被回收，同一个名称可以再次使用 |

- Debian 12 上的连接被重置后，研究脚本中止，UFW 部分没有在 Debian 12 上执行。三个平台的 ufw 上游版本都是 0.36.2；M2 运行中 Debian 12 的 UFW 检查全部通过（第 8.5 节），补上了这一空缺。
- 据此确定的做法：
  - `confirm` 采用第 2.6 节的判定，DR-11 不需要替代方案；
  - 应用和恢复都用 `try-reload-or-restart` 让 sshd 读取新配置；
  - VT-25 的持续探测失败后重试一次（第 7.3 节），把重新加载造成的单次重置与登录路径中断区分开；
  - `ufw.rules` 用 `ufw status` 判定，`ufw.defaults` 接受 `disabled (routed)` 并另查 `/etc/default/ufw`。
- 置信度：高（DR-11、DR-4），每项都在 6 组平台上观察到一致的结果；连接被重置的原因是推断，置信度中。

### 8.5 M2 运行结果

来源：GitHub Actions 运行 `39421643576`（commit `5200943`，2026-10-20），15 个作业全部通过；同一 commit 的静态检查运行 `39421643561` 通过。修复恢复报告之后（commit `fdcf3e6`，本节末尾的最后一项），运行 `39431069986` 同样 15 个作业全部通过，静态检查运行 `39431070014` 通过，逐个用例核对的结论相同，差异在下文注明。除注明的以外，本节的数字来自运行 `39421643576`。改为只在拉取请求中运行 amd64 之后（第 7.1 节），运行 `39443070853`（commit `5e9503a`）的 9 个 amd64 作业全部通过，逐个用例核对的结论相同；运行 `39444784916`（commit `aa04ae2`，只改文档）同样如此。更早的运行 `39407021387`（commit `022c702`）中 14 个作业通过、1 个失败，原因和修复见本节末尾。证据构件 `vm-matrix-*`、`vm-recovery-*`、`vm-negative-*` 保留 14 天，逐个用例核对，不以 CI 状态为准。证据层次为"虚拟机生命周期"，不代表真实主机。按需求 D26，本节只列 amd64 的结果；两次运行中 arm64 作业的结果见附录 A。

| 套件 | 平台 | 加速 | 作业时长 | 结果 |
|---|---|---|---|---|
| matrix | Debian 12 / 13、Ubuntu 24.04，amd64 | KVM | 3 分 51 秒～4 分 12 秒 | 通过 |
| recovery | 同上 | KVM | 5 分 22 秒～5 分 40 秒 | 通过 |
| negative | 同上 | KVM | 3 分 26 秒～4 分 7 秒 | 通过 |

- 作业时长：运行 `39431069986` 的作业时长相近（3 分 45 秒～5 分 56 秒）。M2 的主流程（从应用到重启后核对）用时 90～101 秒。
- matrix（三平台）：
  - VT-10、VT-21：`apply` 退出码为 0；从新会话 `confirm` 后，`verify` 为 33 项通过、0 项不符合、0 项警告、1 项跳过（`f2b.values`，M3）；重启后 `verify` 退出码仍为 0。
  - VT-24：三种被拒绝的确认都以退出码 1 结束，提示文字符合第 2.6 节。
  - VT-11～VT-14、VT-62、VT-70、VT-71：第 7.3 节的判定全部满足。Debian 12 上的 UFW 检查也全部通过，补上了第 8.4 节研究运行的空缺。`/etc/ufw/sysctl.conf` 在 Debian 上等于软件包的版本（UFW 由 `apply` 安装），在 Ubuntu 上与基线一致（镜像已预装 UFW）。从运行器经 QEMU 转发，应用后只有 443 可达（VT-14）。
  - VT-15：不建隧道时本地端口没有应答，建隧道后返回 HTTP 200。
- recovery（三平台）：VT-20、VT-22 的判定全部满足。恢复的时间如下（取自状态记录和工具日志，精确到秒）：

| 平台 | 超时恢复的开始（距 `applied_at`） | 超时恢复的耗时 | 开机恢复的耗时 |
|---|---|---|---|
| Debian 12 | 181 秒 | 3 秒 | 1 秒 |
| Debian 13 | 180 秒 | 4 秒 | 1 秒 |
| Ubuntu 24.04 | 180 秒 | 4 秒 | 2 秒 |

  - 定时器都按时触发：恢复的开始与 180 秒的时限相差不超过 1 秒。运行 `39431069986` 中同样如此；超时恢复的耗时都是 4 秒，开机恢复的耗时为 1～2 秒。
  - VT-22：三个平台上，开机兜底单元都在 `ssh.socket`、`ssh.service`、`ufw.service` 进入运行状态之前结束。
- negative（三平台）：
  - VT-02、VT-03 中 `apply` 的部分：4 种情况和 S1～S4 的 `apply` 都以退出码 1 被拒绝；S1～S4 的第一个不符合项依次为 `new-host.xui`、`new-host.ufw`、`new-host.fail2ban`、`new-host.container`，前后摘要一致。
  - VT-23：`apply` 输出"无法设置 fail2ban.service 开机启动"后恢复；保留的软件包在 Debian 上为 `ufw nftables`，在 Ubuntu 上为空（这两个软件包镜像已预装）。
  - UFW 路径检查的结果与第 8.2 节相同。
- VT-25：两次运行的 18 个 amd64 作业中，没有两次都失败的探测。重启窗口之外，第一次失败、1 秒后重试成功的探测共 3 次：

| 运行 | 作业 | 时间（UTC） | 第一次的错误 | 当时的操作（工具日志） |
|---|---|---|---|---|
| `39421643576` | negative Debian 12，VT-23 | 约 12:25:00～12:25:06 | `Connection timed out during banner exchange` | 应用失败后的恢复正在重新加载 sshd（12:25:02 `restore: sshd`） |
| `39431069986` | negative Debian 12，VT-23 | 约 13:35:07～13:35:13 | 同上 | 同上（13:35:08） |
| `39431069986` | negative Debian 13，VT-23 | 约 13:35:22～13:35:28 | 同上 | 同上（13:35:23） |

  - 3 次都发生在恢复重新加载 sshd 的那一秒前后，并且 Debian 13 上也出现过，不只是第 8.4 节研究中的 Debian 12。推断原因相同：sshd 收到 SIGHUP 后重新执行自身，这期间新建的连接失败。错误信息是等待版本信息超时（`ConnectTimeout=5`），而不是连接被重置，可能是因为探测经 QEMU 的端口转发；这一点是推断，未核实。matrix 主流程中应用时的重新加载没有碰上探测，运行 `39443070853` 的 VT-23 也没有，推断是因为探测每 3 秒一次，能否碰上取决于时机。运行 `39444784916` 中 negative Debian 12 的 VT-23 又出现 1 次，表现相同：第一次约在 15:06:34～15:06:40，`restore: sshd` 在 15:06:35。
  - 判定方式：NFR-02 的验收写的是"始终可达"，VT-25 按第 7.3 节"失败后 1 秒重试一次，两次都失败才算失败"判定，所以这 3 次不算中断；按字面理解，它们是 3 次单次失败。arm64 上另有 2 次（附录 A）。这一判定方式已随本版详细设计评审通过（需求 D28）。
- 置信度：功能结论为高，每项在三个平台上、两次运行中结果一致；单次失败的原因为中，是推断。

实现后的 CI、自查和代码审查中发现并已修复的问题：

| 问题 | 影响 | 修复 |
|---|---|---|
| VT-20 按恢复完成的时间判定（不晚于时限加 120 秒），没有考虑恢复本身的耗时 | 运行 `39407021387` 中 recovery Debian 13 arm64 失败：定时器按时触发（应用后 179 秒开始恢复），但 TCG 下恢复用了 175 秒，完成时距应用 353 秒 | 状态记录恢复的开始时间 `restore_started_at`，工具日志逐步记录；VT-20 按开始时间判定，耗时另设 600 秒上限，测试驱动最多等 900 秒；recovery 作业的上限从 45 分钟改为 60 分钟 |
| 改变系统的命令（`systemctl`、`ufw`、`systemd-run`）没有时间上限，不符合方案设计第 7.5 节"应用阶段调用的外部命令都设超时" | 自查发现，CI 中没有表现。某个命令挂起时，信号陷阱要等它返回才运行，恢复也随之推迟 | 这些命令统一限时 120 秒，超时 10 秒后强制结束（第 6 节） |
| VT-02、VT-03 中 `apply` 的部分没有用例 | 自查发现：设计约定在 M2 补测，首版实现遗漏 | 增加 4 种情况和 S1～S4 的 `apply` 用例（第 7.3 节） |
| 持续探测的证据只记录成败 | 无法判断重试的原因 | 记录第一次失败的错误信息（VT-25） |
| 恢复的其他步骤都成功、只有撤除自动恢复失败时，状态记为"恢复失败"，失败列表却为空 | PR 的自动代码审查发现，CI 中没有表现。终端提示"已恢复到应用前的配置"，`_restore` 退出码为 0，与状态矛盾 | 撤除失败也记入失败列表（"撤除自动恢复"），按恢复未全部完成报告，退出码为 1（第 2.7 节）。用替身函数核对了"其余步骤成功或失败"与"撤除成功或失败"的 4 种组合；虚拟机测试不覆盖这条路径 |

### 8.6 测试 VPS 上的试运行

来源：2026-10-20，在用户提供的一台测试 VPS 上试运行 M2 开发版（commit `aa04ae2`，从仓库导出后安装到 `/usr/local`）。用户确认这台主机刚重装、没有业务和数据，允许全量升级和反复应用，服务商控制台可用。这不是 M5 的验收：只有一台主机、一个平台，M3、M4 的功能还没有实现。主机地址和服务商不记录。时间为服务器的 UTC 时间。

| 项目 | 内容 |
|---|---|
| 主机 | KVM 虚拟机，x86_64；重装后为 Debian 13.4，内核 6.12.74 |
| 初始状态 | `permitrootlogin yes`；`passwordauthentication yes`，来自 `50-cloud-init.conf`。root 已有用户在服务商管理页面绑定的公钥，试运行另加一把临时公钥。没有镜像默认用户，也没有免密 sudo 规则。未安装 UFW、nftables、Fail2ban；已安装 unattended-upgrades 2.12，两个 APT 定时器已启用。systemd-resolved 在所有地址上监听 5355（LLMNR） |
| 全量升级（D24） | 升级 99 个软件包，内核升到 6.12.113，重启用时 23 秒。之后为 Debian 13.7、openssh-server `1:10.0p1-7+deb13u4`、systemd 257；sshd 的生效配置没有变化 |
| 预检 | `preflight --open 443/tcp --open 2096/tcp`：17 项通过，退出码 0 |
| 软件包 | ufw 0.36.2-9、fail2ban 1.1.0-8、nftables 1.1.3-1，三者由 `apply` 安装 |

| 场景 | 操作 | 结果 |
|---|---|---|
| A：确认超时 | 确认时限设为 3 分钟；15:32:28～15:32:46 应用，不确认 | 通过。恢复在 15:35:46 开始，距 `applied_at` 180 秒，用时 5 秒。状态为"已回滚"；待确认标记、临时定时器和开机兜底单元都已删除。`sshd -T` 与升级后的基线一致，服务器重新提供 `publickey` 和 `password` 认证；ufw、fail2ban、nftables 单元都不启用；本工具写入的文件都已删除，软件包保留 |
| B：待确认期间重启 | 默认时限 10 分钟；应用后立即重启 | 通过。开机兜底单元在开机后 7.58 秒（单调时钟）结束，`ssh.service` 在 10.13 秒进入运行状态；ufw、fail2ban 没有启动。状态为"已回滚"，原因为"待确认期间重启"；`sshd -T` 与基线一致，恢复后的状态摘要与 A 相同。软件包在 A 中已经装好，所以 `packages_added` 为空 |
| C：主流程 | 15:38:05 开始应用；从新的 SSH 会话执行 `confirm`；再重启 | 通过。15:38:20 确认成功，`verify` 为 32 项通过、1 项跳过（`f2b.values`，M3）。CI 中为 33 项，多出的是镜像默认用户的 `ssh.denied`，这台主机没有默认用户。重启后 `verify` 退出码为 0，状态为"已应用"，ufw、fail2ban、ssh 都在运行 |

- 连续探测（与 VT-25 相同：每 3 秒用密钥登录一次，失败后 1 秒重试）：从本地电脑经管理员的出口发起，与管理员平时使用的 SSH 客户端同一出口，覆盖三个场景，共 128 次。
  - 两次都失败的只有 1 次，在 B 的重启窗口中（`Connection timed out during banner exchange`）；C 的重启窗口中另有 1 次重试成功。
  - 重启窗口之外有 3 次重试成功，表现相同：连接约 6 秒后被服务器关闭（`Connection closed by … port 22`），1 秒后重试成功。按测得的时钟差（服务器快约 1.5 秒）折算，3 次开始时距最近一次 sshd 重新加载分别约 2、9、20 秒，不像 CI 中那样落在重新加载的那一秒（第 8.5 节）。
  - 服务器日志中没有对应的记录。sshd 因 `PerSourcePenalties` 丢弃连接时会记录（同一台主机上对扫描来源有 81 条这样的记录），并且立即断开（第 8.2 节），这 3 次却都在约 6 秒后才断开。第二次发生在 A 恢复之后，这时 UFW、Fail2ban 都未启用，sshd 配置与基线相同。试运行结束后，加固状态下的一条普通 SSH 命令也遇到一次同样的错误。
  - 推断：这几次失败与本工具的配置无关，可能出在网络路径上；原因未查明，置信度低。重试即成功，不影响已建立的会话。
- 扫描流量（sshd 和内核日志的计数）：
  - 重装后到全量升级前，约 8 小时，密码登录开启：467 次密码失败，233 次使用不存在的用户名；`PerSourcePenalties` 的丢弃记录 81 条（日志限速，实际丢弃更多）。
  - A 恢复后密码认证重新开启，恢复重新加载 sshd 后约 6 秒就有扫描来源尝试密码登录。
  - C 重启后的约 9 分钟内：没有密码失败；内核记录 41 条 `UFW BLOCK`；Fail2ban 在一个扫描来源累计 5 次失败后将其封禁，被封的不是管理员的出口。试运行期间，管理员自己的连接没有被 Fail2ban 计为失败。
- 附带核对（需求 FR-02、第 7.3 节）：vps-tuning 应用时会预先创建 `x-ui.service` 的 drop-in。在这台主机上为一个不存在的单元只创建 drop-in，`systemctl cat` 退出码为 1（`No files found`），`LoadState` 为 `not-found`；核对后已删除。所以先调优、后加固时，`new-host.xui` 不会因这个 drop-in 判为不符合。只核实了 systemd 257（Debian 13）；Debian 12 的 systemd 252 和 Ubuntu 24.04 的 255 待 VT-90 核实。
- 试运行结束后，用户确认仍能从平时使用的客户端用自己的密钥登录（需求 U16）。
- 置信度：三个场景的功能结论为高，与 CI 的结论一致（第 8.5 节），但只覆盖这一台主机，不能据此推出 Debian 12、Ubuntu 24.04 或其他服务商主机上的结果。

### 8.7 M3 运行结果

来源：GitHub Actions 运行 `39467916087`（commit `b9e8b3d`，2026-10-20），12 个 amd64 作业全部通过；同一 commit 的静态检查运行 `39467915956` 通过。第一轮运行 `39464754834`（commit `7f9f634`）中，9 个 M1、M2 的作业通过，3 个 hardened 作业都在 VT-51 失败，原因和修复见本节末尾。证据构件 `vm-hardened-*` 等保留 14 天，逐个用例核对，不以 CI 状态为准。证据层次为"虚拟机生命周期"，不代表真实主机。arm64 没有运行（第 9 节）。

| 套件 | 平台 | 作业时长 | 结果 |
|---|---|---|---|
| matrix | Debian 12 / 13、Ubuntu 24.04，amd64 | 3 分 57 秒～4 分 14 秒 | 通过 |
| recovery | 同上 | 5 分 24 秒～5 分 34 秒 | 通过 |
| negative | 同上 | 3 分 23 秒～4 分 7 秒 | 通过 |
| hardened | 同上 | 9 分 12 秒～10 分 26 秒 | 通过 |

被测的软件包版本：

| 平台 | fail2ban | openssh-server | ufw | unattended-upgrades |
|---|---|---|---|---|
| Debian 12 | 1.0.2-2 | `1:9.2p1-2+deb12u10` | 0.36.2-1 | 2.9.1+nmu3 |
| Debian 13 | 1.1.0-8 | `1:10.0p1-7+deb13u4` | 0.36.2-9 | 2.12 |
| Ubuntu 24.04 | 1.0.2-3ubuntu0.1 | `1:9.6p1-3ubuntu13.19` | 0.36.2-6 | 2.9.1+nmu4ubuntu1 |

- M1、M2 的套件：判定与第 8.5 节相同，全部满足。确认后的 `verify` 为 37 项通过、0 项不符合、警告和跳过（M2 为 33 项通过、1 项跳过）：`f2b.values` 由跳过变为通过，另增加 `f2b.config`、`f2b.files`、`uu.dropin`。未加固主机上的 VT-50，新增的 `uu.dropin` 和原有的 `ssh.dropin` 因没有应用记录而跳过，不符合项与 M1 相同。
- hardened 套件，三个平台的结果相同（不同之处注明）：
  - VT-30：各项满足，`verify` 为 37 项通过。14 项 `get` 的原始输出在 fail2ban 1.0.2 和 1.1.0 上逐字相同，第 4 节的规整规则对两个版本都成立。
  - VT-31：样本 2 个，jail 计数增加 2，`fail2ban-regex` 对该来源匹配 2 次，来源没有被封禁。每次尝试 sshd 记录两行（`Invalid user …` 和 `Connection closed by invalid user … [preauth]`），普通模式只计第一行。
  - VT-33：`.7` 每次失败计数加 1，第 5 次后被封禁，封禁时长正好 86400 秒；该地址在 `inet f2b-table` 中，它的登录被拒绝，`.2` 的 root 登录正常。递增部分：第一次封禁 20 秒；到期后，同一来源 3 次失败就再次被封，每次失败计数加 2，这是 Fail2ban 对封禁过的来源加重计数（需求第 10.1 节）；第二次封禁为 54、188、254 秒（Debian 12、13、Ubuntu 24.04；第一轮为 197、377、313 秒），都在 40～640 秒之间；`reload` 之后 `bantime` 回到 86400。
  - VT-35：VT-33 中提到 `.7` 的 journal 记录共 10 条（5 次尝试，各两行）。Debian 13 上都来自 `sshd-session`，Debian 12 和 Ubuntu 24.04 上都来自 `sshd`，没有 `sshd-auth`，都在 `journalmatch` 范围内。FR-08 不需要修改。
  - VT-32：封禁、解封和中途中断三种情况都满足，全程 `.2` 能登录。
  - VT-34：三组的计数增量都是 0，两个来源都没有被封禁；Debian 13 上 sshd 没有惩罚记录。需求 R-3 的证据状态随之更新。
  - VT-40：dry-run 列出的允许来源等于 D19 的集合（Debian 12 为 `bookworm`，Debian 13 为 `trixie`，Ubuntu 为 `noble` 的三项），退出码为 0，用时 15～42 秒。
  - VT-55、VT-50、VT-71：3X-UI 的两个二进制文件与发布包一致（VO-1）；安装前后 SSH、UFW、Fail2ban、受管文件和单元、sysctl、qdisc 都不变；`verify` 为 38 项通过（多出 `boundary.panel-listen`），没有不符合、警告和跳过；经隧道访问 WebBasePath 返回 HTTP 200 和登录页；重启后 boot ID 改变，`verify` 结果相同。
  - VT-51：9 项漂移的结果都与第 7.3 节的表一致。"安装防火墙"的菜单输出 `Firewall is already active`，UFW 不变，`verify` 退出码为 0。
  - VT-25：每个作业探测 98～111 次，只在重启窗口内各有 1 次两次都失败，窗口外没有失败。
  - 泄露扫描：三个作业都没有发现测试密码、客户端私钥和面板的 WebBasePath。
- 置信度：功能结论为高，三个平台、两次运行一致（第一轮只缺 VT-51 的后 6 项）；第二次封禁的时长含随机部分，只核对了范围。

第一轮运行发现并已修复的问题：

| 问题 | 影响 | 修复 |
|---|---|---|
| `f2b.mainconf` 用 `dpkg --verify fail2ban \| grep -q` 判定。dpkg 逐行输出，两个文件都被改动时，`grep -q` 读到第一行就退出，dpkg 写第二行时因 SIGPIPE 失败，`pipefail` 下整个条件为假，检查通过 | M1 起就存在，违反第 6 节"读取端不提前退出"的约束。VT-51 的 IP Limit 漂移同时改动这两个文件（状态摘要显示两者的摘要都变了），三个平台上 `f2b.mainconf` 都误报通过；只改一个文件时不受影响，所以 M1、M2 的测试没有发现。测试 VPS 上复现：30 次中漏报 28 次（第 8.8 节） | 先把 `dpkg --verify` 的输出读完，再匹配（commit `b9e8b3d`）。其他用 `grep -q` 读管道的地方，写入端是 awk 或 `printf`，输出很短、一次写出，或者只输出一行（`find -quit`），不受影响 |

### 8.8 测试 VPS 上的 M3 核对

来源：2026-10-20，第 8.6 节的同一台测试 VPS，处于 M2 主流程确认后的"已应用"状态；用户同意在 M3 中使用这台主机（需求 U17）。软件版本：Debian 13.7，fail2ban 1.1.0-8，openssh-server `1:10.0p1-7+deb13u4`，dpkg 1.22.22，systemd 257。除第 8.9 节的演练外只做只读查询；需要改动配置文件的核对，都在私有挂载命名空间（`unshare -m`）中用绑定挂载覆盖，主机上的文件不变。M3 开发版复制到 `/root` 下的临时目录运行，不覆盖已安装的版本。Fail2ban 的封禁只来自互联网上的扫描来源，测试没有从管理员的出口制造失败（验证计划第 5 节，需求 R-3）。

| 项目 | 结果 |
|---|---|
| `fail2ban-client get` 的输出格式 | 第 4 节 `f2b.values` 的规整规则依据这里的输出确定：多行的值带标题行，列表项带 `|- `、`` `- `` 前缀，`dbpurgeage` 带 `seconds` 后缀，`ignoreip` 中的 `127.0.0.1/8` 显示为 `127.0.0.0/8`。fail2ban 1.0.2（Debian 12、Ubuntu 24.04）的输出由 VT-30 逐字比较，结果相同（第 8.7 节） |
| M3 开发版的 `verify` | 36 项通过，0 项不符合、警告和跳过，退出码为 0；运行前后 `/etc` 的摘要一致 |
| `f2b.mainconf` 的漏报（第 8.7 节） | 同时覆盖 `jail.conf` 和 `fail2ban.conf`：修复前的写法 30 次中漏报 28 次，修复后 5 次都报告不符合；撤除覆盖后 36 项全部通过。`dpkg --verify` 在文件被改动时退出码仍为 0，所以问题只出在管道提前结束 |
| sshd 日志的进程字段（VT-35 的补充） | 2026-10-20 以来：`_COMM=sshd` 130 条，`sshd-session` 2984 条，`sshd-auth` 0 条。认证失败的记录都来自 `sshd-session`，在 FR-08 的 `journalmatch` 范围内 |
| 封禁时长（只读查询 Fail2ban 数据库） | 本工具的配置下，2 个扫描来源的首次封禁都正好是 86400 秒：首次封禁不加随机时长。被封过一次的来源再次被封 172847.6 秒，即 86400 × 2 加 47.6 秒的随机时长，符合 `bantime.increment` 和 `bantime.rndtime` |
| 安装软件包到写入配置之间 | 第 8.6 节场景 A 中，`apply` 于 15:32:33 安装 fail2ban。软件包的安装脚本随即启动服务，发行版默认的 sshd jail 运行到 15:32:43 本工具的配置生效为止，约 5 秒；它按 journal 中最近 10 分钟的失败记录，把 2 个扫描来源各封禁 600 秒（默认的 `bantime`） |

- 最后一项是 M2 实现中没有注意到的过渡状态。影响很小：默认 jail 同样只读 sshd 的认证失败，过滤模式也是 `normal`，只会封禁 10 分钟内已有 5 次失败的来源；管理员用密钥登录，不会在这 10 分钟内累积失败。M3 不修改，记录在第 9 节。
- 置信度：输出格式、修复前后的对比和封禁时长为高，都是直接观察；只覆盖 Debian 13 这一个平台。

### 8.9 测试 VPS 上的 D27 顺序演练

来源：第 8.8 节的同一台测试 VPS，服务器时间 2026-10-21 03:10～03:20（UTC）。在已加固并确认的主机上，按需求 D27 的顺序继续调优、安装 3X-UI 和严格验证，作为 VT-90 的预演。它不是 VT-90：本工具还没有发布版本，vps-tuning 用的是预发行版 `v0.2.0-rc.4`，"先调优、后加固"的另一半也没有执行。演练之后，这台主机上装有 vps-tuning 和 3X-UI，不再是新机。

| 步骤 | 操作 | 结果 |
|---|---|---|
| 0 | 把已安装的工具换成 M3 版（commit `813bc0c` 的 `bin`、`lib`），状态仍是第 8.6 节确认后的"已应用"；装上待升级的 ca-certificates 安全更新（不需要重启） | `verify` 36 项通过 |
| 1 | 按 vps-tuning 的 README 安装 rc.4（校验安装器摘要，`--no-launch`），再执行 `dvt preflight --port 200` 和 `dvt apply --port 200`。200 Mbps 是演练的取值，不是这台主机的套餐带宽 | 按 vps-tuning 使用说明的依赖要求装上 jq 后，预检通过，结果为 `PASS_WITH_PROVIDER_SYSCTL_TRANSFER`：`/etc/sysctl.conf` 中有服务商写入的 bbr、fq 两行，`apply` 把它们迁移到 vps-tuning 自己的文件。`apply` 退出码为 0，预置 `x-ui.service` 的 drop-in，创建 1 GiB swap。加固的 `verify` 仍为 36 项通过；`systemctl cat x-ui.service` 的退出码为 1，`boundary.panel-listen` 报告"未安装 3X-UI" |
| 2 | 重启 | boot ID 改变；`dvt verify` 通过，0 个警告；拥塞控制为 bbr，qdisc 为 fq；加固的 `verify` 36 项通过 |
| 3 | 按需求第 7.2 节安装 3X-UI v3.7.0：tag 中的 `install.sh`、`x-ui.sh` 校验摘要；带版本参数和四个环境变量，面板端口为应用时声明的 2053；用 tag 中的 `x-ui.sh` 替换 `/usr/bin/x-ui`；`x-ui setting -listenIP 127.0.0.1` 后重启 x-ui | 两个二进制文件与发布包一致（VO-1）；面板只监听 `127.0.0.1:2053`；`/etc/fail2ban/jail.d` 中只有本工具和发行版的文件，`nftables.service` 未启用 |
| 4 | `env REQUIRE_PROXY_SERVICE=1 PROXY_SERVICE_UNITS='x-ui.service' dvt verify`，然后 `vps-hardening verify` | 严格验证通过，0 个警告：x-ui 主进程和 Xray 子进程的 NOFILE 都是 65536。`verify` 37 项通过，其中 `boundary.panel-listen` 通过 |
| 5 | 从本地电脑经 SSH 隧道（`-L` 转到 `127.0.0.1:2053`）访问 WebBasePath | 不建隧道时本地端口没有应答；建隧道后返回 HTTP 200 和登录页。从外部直接连接面板端口被 UFW 拦截（见下文） |
| 6 | 重启后复核 | boot ID 改变；严格验证通过，0 个警告；`verify` 37 项通过；x-ui、fail2ban、ufw、ssh 都在运行，jail 只有 `sshd`；经隧道访问同样返回登录页 |

- 外部探测：本地电脑的出口经过代理，代理会先在本地接受任何 TCP 连接，连 9、65000 这种没有服务的端口也显示"已连接"，所以从本地直接探测端口的结果无效。改看 VPS 的内核日志：这几次探测（端口 9、65000、80、2053）都来自同一个代理出口，都有 `UFW BLOCK` 记录。
- 结论：D27 的顺序在这台 Debian 13 主机上可行。调优没有改动加固的对象；3X-UI 按约定安装后，加固和调优的验证都通过，重启后保持不变。
- 置信度：中。只有一台主机、一个平台；调优用的是演练取值；3X-UI 没有配置入站，没有代理流量。

## 9. 已知限制与后续

- 已在 M2 解决的 M1 遗留项：
  - VT-02 和 VT-03 中"`apply` 被拒绝且不改变系统"的部分，已在 M2 补测（第 7.3 节）；
  - `confirm` 用审计会话编号区分新旧 root 会话的做法已核实（第 8.4 节，DR-11）。
- 已在 M3 解决的 M2 遗留项：`f2b.values` 和 `boundary.panel-listen` 已实现（第 4 节）；FR-09 的 dry-run 验证已完成（VT-40，第 8.7 节）。
- 3X-UI 的"安装防火墙"菜单在 UFW 已启用时不做任何改动，与需求 v1.4 第 7.2 节和 FR-10 验收的描述不符。VT-51 改用"停用后再安装"作为这项漂移，单独"安装防火墙"作为对照保留；需求 v1.5 据此更正（D29，已经用户确认，D30）。
- `boundary.panel-listen` 只核对应用时声明的面板端口。管理员之后在面板中改了端口时，这一项报告警告（端口上没有监听），不能判断新端口的监听地址；端口变更由 FR-14（M4）处理。
- `f2b.files` 把 `/etc/fail2ban` 下软件包和本工具以外的文件都判为不符合，包括管理员自己加的、与 sshd 无关的配置。这与 FR-02"不接管存量 Fail2ban 配置"的边界一致：只支持本工具写入的配置。
- `apply` 安装 fail2ban 软件包后，发行版默认的 sshd jail 会在本工具写入配置前运行几秒，期间可能按最近 10 分钟的失败记录封禁来源 10 分钟（第 8.8 节）。管理员只用密钥登录时不受影响，所以不修改。
- VT-34 只覆盖测试中的三种客户端行为（多密钥的 ssh-agent、`IdentitiesOnly`、认证前断开），不能证明任何客户端配置都不会被计为失败。被封过的来源再次失败时计数加重（需求第 10.1 节），管理出口一旦被封，30 天内更容易再次被封。
- NFR-03 的幂等行为（已应用且没有漂移时再次 `apply`，退出码为 0）在 M4 实现。M2 中，已应用的主机上再次执行 `apply` 被预检拒绝，退出码为 1。
- 应用在布置自动恢复之前被强制中断（例如断电）时，状态停在"应用中"，预检会拒绝再次应用。这时还没有改动任何配置，最多装了一部分软件包，需要管理员检查 `dpkg` 状态后手工删除状态目录。M4 实现 `rollback` 时一并处理这种情况。布置之后的中断由开机兜底单元处理。
- sshd 重新加载的瞬间新建的 SSH 连接可能失败：研究中 Debian 12 上被重置，VT-23 中 Debian 12、13 上等待版本信息超时（第 8.4、8.5 节）。重试即可，不影响已建立的会话。M2 的测试用"失败后 1 秒重试一次"区分这种情况与登录路径中断（VT-25）。测试 VPS 上另有几次连接约 6 秒后被断开、重试即成功，原因未查明（第 8.6 节）。
- 恢复后保留已安装的软件包（方案设计第 4.4 节）。开机恢复只恢复单元的启用状态，所以应用前启用、但当时没有运行的服务，开机后会运行。真实的新机上，受管单元一般不处于这种状态；测试环境中的两个 APT 定时器正是这种状态（第 7.2 节：测试在运行期停止了它们），开机恢复后照常运行，所以 VT-22 只比较启用状态。
- `confirm` 的检查防的是误操作，不防有意绕过的 root（方案设计第 7.5 节）。
- 测试中 `apt-daily-upgrade.service` 被替换为空操作（第 7.2 节），因此没有覆盖真正的无人值守升级；FR-09 只有 dry-run 的证据（VT-40）。
- arm64 只作参考（需求 D26）：按需手动运行，覆盖 matrix、recovery 和 hardened 套件，结果见附录 A；negative 套件只在 amd64 上运行（验证计划第 3.1 节的"三平台"范围）。hardened 套件还没有在 arm64 上运行过：TCG 下 M2 的主流程就要 14～19 分钟，加上 M3 的用例和 9 个覆盖层，可能超过 60 分钟的作业上限（推断，未测量）。
- 除第 8.6、8.8、8.9 节在一台测试 VPS 上的试运行和核对外，结论只到 CI 虚拟机层次；真实主机验收在 M5，需要用户另行授权。
- 外部连通测试不能从出口经过代理的电脑直接做：代理会在本地接受任何 TCP 连接（第 8.9 节）。M5 的外部测试要用不经代理的来源，或者以 VPS 上的 UFW 日志、抓包为准。

## 附录 A arm64 参考结果

按需求 D26，arm64（aarch64）只作参考，结果不作为里程碑出口。M1 的 arm64 结果按当时的需求（D11）记录在第 8.1、8.2 节，保持原样。本附录记录 M2 的两次运行 `39421643576`、`39431069986` 中 arm64 作业的结果，核对方法与第 8.5 节相同。GitHub 的 arm64 运行器上没有 `/dev/kvm`，客体用 TCG 模拟运行。此后 arm64 只在手动触发时运行（第 7.1 节）。

| 套件 | 平台 | 作业时长（`39421643576`） | 作业时长（`39431069986`） | 结果 |
|---|---|---|---|---|
| matrix | Debian 12 / 13、Ubuntu 24.04，arm64 | 24 分 10 秒～30 分 21 秒 | 24 分 21 秒～30 分 17 秒 | 两次都通过 |
| recovery | 同上 | 30 分 16 秒～38 分 42 秒 | 27 分 54 秒～39 分 18 秒 | 两次都通过 |

- 判定结果与 amd64 相同：确认后的 `verify` 为 33 项通过、0 项不符合、0 项警告、1 项跳过；VT-10～VT-15、VT-20～VT-22、VT-24、VT-62、VT-70、VT-71 的判定全部满足。M2 的主流程用时 824～1134 秒，amd64 为 90～101 秒。
- 恢复的时间（两次运行依次以"/"分隔）：

| 平台 | 超时恢复的开始（距 `applied_at`） | 超时恢复的耗时 | 开机恢复的耗时 |
|---|---|---|---|
| Debian 12 | 179 秒 / 179 秒 | 122 秒 / 110 秒 | 42 秒 / 39 秒 |
| Debian 13 | 180 秒 / 180 秒 | 178 秒 / 165 秒 | 63 秒 / 59 秒 |
| Ubuntu 24.04 | 180 秒 / 181 秒 | 111 秒 / 126 秒 | 53 秒 / 60 秒 |

  - 定时器按时触发，与 amd64 相同；耗时来自 TCG 模拟。按第一次运行的工具日志，超时恢复中停止定时器和关闭 UFW 用了 17～25 秒，恢复受管单元一步用了 89～149 秒；开机恢复中受管单元一步用了 37～57 秒。amd64（KVM）上整个恢复只用 1～4 秒。真实的 arm64 主机不经模拟，耗时应接近 amd64 的结果（推断，未在真实主机上测量）。
  - 第一次运行之前，VT-20 按恢复完成的时间判定，arm64 的这一耗时使运行 `39407021387` 失败（第 8.5 节末尾的第一项）。
- VT-25：重启窗口之外，第一次失败、1 秒后重试成功的探测有 2 次，都在 recovery Debian 13 的超时恢复中，第一次的错误都是"60 秒内没有应答"：

| 运行 | 时间（UTC） | 当时的操作（工具日志） |
|---|---|---|
| `39421643576` | 12:40:52～12:42:30 | 恢复正在处理受管单元（12:40:52～12:43:21） |
| `39431069986` | 13:50:33～13:51:58 | 同上（13:50:30～13:52:48） |

  - 推断是模拟造成的处理延迟：两次都在 TCG 下处理受管单元期间，amd64 上同一步骤没有出现。
- 置信度：功能结论为高，两次运行一致；耗时数字为中，只来自模拟环境，不代表真实的 arm64 主机。
