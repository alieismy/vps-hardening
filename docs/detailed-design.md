# VPS Hardening 详细设计

| 项目 | 内容 |
|---|---|
| 状态 | v0.9 已批准：新增第 8.18 节（`v0.1.0-rc.3` 的发布和 VT-72 的公开部分）、第 8.19 节（真实主机验收 M5），并修改第 9 节：M5 发现的问题（安装脚本结尾的提示仍是 `preflight --open <公开端口>`），M5 再次观察到的 fail2ban 过渡状态，外部探测改为在 VPS 上抓包，真实主机验收的范围。用户于 2026-10-24 评审通过（需求 U31、D46）。评审之后更正一处：fail2ban 的过渡状态（应用时按软件包自带配置产生的封禁只有 600 秒）不是 M5 新发现的问题，第 8.8 节和第 9 节已有记录，当时判断影响小、不修改；第 8.19、9 节改为"再次观察到"，其余内容不变。v0.8 已批准：按需求 v1.9（D41～D43）修改第 2.4、3、7.3、9 节，新增第 8.17 节（运行结果）：推荐流程中 `apply` 不声明公开端口，没有公开端口时 `inputs.open` 通过；预检增加 `reboot.required`，待重启时只警告；hardened 套件改为不声明公开端口加固，安装 3X-UI 后用 `ports` 开放 443/tcp、2096/tcp 并确认；VT-01 增加放置待重启标记的预检。用户于 2026-10-24 评审通过（需求 U28、D44）。v0.7 已批准：按需求 v1.8（D40）修复 `v0.1.0-rc.1` 发布后核实的四个问题，涉及第 1、2.12、3、4、6、7.3、9 节，新增第 8.15 节：检查 sshd 配置时按 sshd 的规则读取每一行，带引号的关键字、带引号或转义空格的 `Include` 路径不再漏查；安装脚本的"未做变更"还要求属主和权限相同；替换文件的过程中失败或被中断时，恢复为安装前的文件。合并之后发布预发行版 `v0.1.0-rc.2`，增补第 8.16 节（发布与 VT-72 的公开部分）。用户于 2026-10-24 与 v0.8 一并评审通过（需求 U28、D44）。v0.6 已批准：按需求 v1.7（D34～D36）修复评审发现的缺口，涉及第 1～4、6、7、9 节，新增第 8.13 节：预检和 `verify` 拒绝 sshd 配置中的 `Match` 块；UFW 未启用时，预检也拒绝已添加的规则和被改动的 before/after 框架文件，`verify` 比较同样的框架文件；`ufw.rules` 和 `ports.rules` 改为与声明比较，不再记录规则行；公开端口不能是 80/tcp；安装脚本按状态提示下一步。按需求 D37，`verify` 增加 `ufw.userrules`，`ports` 增加变更前检查 `ports.userrules`：`user.rules`、`user6.rules` 须与记录的摘要相同。合并之后发布预发行版 `v0.1.0-rc.1`，增补第 2.12 节的发布步骤和第 8.14 节（发布与 VT-72 的公开部分）。用户于 2026-10-22 评审通过（需求 U25、D39）。v0.5 已批准：增补里程碑 M4（`status`、`rollback`、`ports`、已应用时的 `apply`、发行版安装脚本）的契约、状态记录、测试和运行证据（第 8.10～8.12 节），涉及第 1～9 节；按需求 v1.6（D32）把测试中的 3X-UI 改为 v3.10.2。用户于 2026-10-22 评审通过（需求 U24、D38），并要求安装脚本在已应用的主机上的结尾提示在发布前修复，已在 v0.6 中修复（第 2.12 节）。v0.4 已批准：增补里程碑 M3 的检查项（第 4 节）、测试（第 7 节）和运行证据（第 8.7～8.9 节），涉及第 1、4、7～9 节。超出 v0.3 第 1 节所列 M3 范围的三个检查项（`f2b.config`、`f2b.files`、`uu.dropin`）已经用户确认（需求 U18、D30）。用户于 2026-10-20 评审通过（需求 U19、D31）。评审之后，按拉取请求 #9 的代码评审意见修复三处忽略 `dpkg --verify` 退出码的判定，第 4、6 节和第 8.7 节随之补充。v0.3 已批准：增补里程碑 M2（`apply`、`confirm`、自动恢复）的契约、状态记录、测试和运行证据，涉及第 1～9 节；M3、M4 实现时继续增补。第 1 节的范围调整（Fail2ban 和自动更新的写入提前到 M2）偏离方案设计 v1.1 第 10 节，已经评审通过，方案设计 v1.2 第 10 节随之修改。按需求 v1.4（D26），arm64 改为按需运行的参考，M2 的 arm64 结果放在附录 A。增补第 8.6 节：在用户提供的一台测试 VPS 上试运行 M2 开发版，不是 M5 的验收。用户于 2026-10-20 评审通过（需求 U16、D28），包括第 1 节的范围调整和 VT-25 的判定方式。此前的版本：v0.1 于 2026-10-20 经用户评审，除第 2.4 节的 `--maxretry` 和第 4 节 `ssh.permitrootlogin` 的期望值两处外通过；v0.2 按需求 v1.3（D22、D23）修改第 2.2、2.4、3～7、9 节，删除管理用户和公钥文件参数、sudo 条件检查，新增 root 公钥检查 `root.keys`，于同日经用户评审通过（需求 U13、D25） |
| 日期 | 2026-10-24（v0.1 为 2026-10-13） |
| 上游 | [需求规格说明 v1.9](requirements.md)（已批准）、[方案设计 v1.5](solution-design.md)（已批准）、[验证计划 v1.7](verification-plan.md)（已批准） |
| 下游 | 实现、测试 |
| 深度 | 命令契约、检查项目录、模块划分、实现约束和测试框架；不重复上游已有的决策理由 |

**证据状态。** 第 2～6 节描述的是仓库中的实现，第 7 节描述的是测试框架。运行证据见第 8 节：第 8.1～8.5、8.7、8.10、8.13 节来自 CI 虚拟机；第 8.6、8.8、8.9、8.11 节来自一台测试 VPS，只有一台主机，不能代替真实主机验收（M5）；第 8.12 节是按这些输出做的人工走查；第 8.15 节既有 CI 虚拟机的结果，也有在这台测试 VPS 上用临时配置和私有挂载命名空间做的核对，后者没有改动主机上在用的配置和已安装的文件；第 8.16 节与第 8.14 节一样，是发布和从公开地址的回验。

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

M4 实现（v0.5，方案设计第 10 节的 P1 部分）：

- `status`：只读显示状态、变更记录和确认截止时间（第 2.9 节，FR-13）；
- `rollback`：先检查回滚后 root 能否登录，交互确认后恢复到应用前的配置（第 2.10 节，FR-12）；
- `ports`：增减公开端口，与 `apply` 共用确认窗口和自动恢复（第 2.11 节，FR-14）；
- `apply` 在已应用的主机上只核对参数和当前状态，不做变更（第 2.5 节，NFR-03）；
- 发行版安装脚本 `install.sh`（第 2.12 节，NFR-07）；
- 预检和 `verify` 识别新状态"端口变更待确认"；应用中断或恢复未完成时，预检和 `status` 提示执行 `rollback`（第 3、4 节）；
- 测试增加 VT-60、VT-61、VT-63、VT-64 和 VT-72 的本地部分，3X-UI 夹具改为 v3.10.2（需求 D32，第 7 节）。

发布预发行版和 VT-72 的公开部分在用户评审、合并之后进行，不在 v0.5 的证据中；预发行版 `v0.1.0-rc.1` 于 2026-10-22 发布，证据见第 8.14 节。

**修复（v0.6，需求 D34～D36）。** 对需求 v1.6 草案的评审发现三处缺口，都是自 M2 起就有的：

- **sshd 的 `Match` 块。** `sshd -T -C` 只按一个假定的连接求值（第 6 节）。排在片段的 `Include` 之后或后面片段中的 `Match Address` 块，可以对其他来源保留密码登录，而 `verify` 仍然通过。现在预检（`sshd.match`）和 `verify`（`ssh.match`）拒绝主配置及其包含的文件中的任何 `Match` 块（第 3、4 节）。
- **`ufw status` 不显示的规则。** 预检原来只拒绝已启用的 UFW。UFW 未启用时已添加的规则，会在 `apply` 启用 UFW 时一起生效；before/after 框架文件中的规则则始终不显示。现在预检也拒绝这两种情况，`verify` 另外比较框架文件（第 3、4 节）。
- **规则的基线。** `ufw.rules` 原来与 `apply` 之后记录的规则行比较，`apply` 之前已添加的规则因此进入基线。现在与声明比较，不再记录规则行（第 2.5、2.8、2.11 节）。

另外两处改动：公开端口不能是 80/tcp，80/udp 可以（需求 D35，第 2.4 节）；安装脚本在已应用的主机上提示 `verify` 和 `status`（第 2.12 节）。`apply` 除了不再记录规则行以外没有改变，`confirm`、自动恢复和 `rollback` 也没有改变。

**直接写入的规则（v0.6，需求 D37）。** `ufw status` 不显示 `user.rules`、`user6.rules` 中没有 tuple 注释的行，UFW 启动时却载入它们。`verify` 增加 `ufw.userrules`，核对两个文件与记录的摘要，已应用时的 `apply` 经 `verify` 的检查项同样核对；`ports` 增加变更前检查 `ports.userrules`（第 2.11、4 节）。剩下的缺口见第 9 节。

**发布后的修复（v0.7，需求 D40）。** `v0.1.0-rc.1` 发布后核实了四个问题（第 9 节），都在 v0.6 的实现中：

- **sshd 配置的读法。** 原来的检查按空白拆分 `Include` 的参数、按 awk 的第一个字段取关键字，与 sshd 不同：带引号或转义空格的 `Include` 路径所指的文件，以及以带引号的关键字（`"Match"`）开头的块，sshd 都会应用，`sshd.match`、`ssh.match` 却漏查。现在 `sshd.include`、`sshd.dropin-order`、`sshd.match` 和 `ssh.match` 用同一组 awk 函数按 sshd 的规则读取每一行（第 6 节）。
- **安装脚本的"未做变更"。** 还要求属主为 root，入口和模块目录为 0755，模块为 0644（第 2.12 节）。
- **安装脚本的替换。** 新入口运行成功之前的失败或信号，都恢复为安装前的入口和模块，新机上不留下文件（第 2.12 节）。

`preflight` 和 `verify` 的其余检查、`apply`、`confirm`、自动恢复、`rollback`、`ports` 都没有改变。

## 2. 命令契约

### 2.1 调用与环境

- 入口为 `bin/vps-hardening`，模块在 `lib/vps-hardening/`。入口用 `readlink -f` 定位自身，按"上两级目录下的 `lib/vps-hardening`"找模块，所以安装后（`/usr/local/bin` 和 `/usr/local/lib`，方案设计第 7.2 节）和在仓库中运行使用同一套相对布局。
- 入口固定 `PATH`、`LC_ALL=C`（被解析的工具输出保持英文格式）和 `umask 077`，并启用 `set -Eeuo pipefail`。
- 输出中的说明文字为中文；检查项编号为英文，保持稳定，测试按编号判定。
- `apply` 和 `ports` 把入口的绝对路径写进 systemd 单元（第 2.7 节）。路径中只允许字母、数字和 `._/-`，含其他字符时它们在做任何变更之前拒绝执行。

### 2.2 退出码

| 退出码 | 含义 |
|---|---|
| 0 | 检查全部通过（允许有警告和跳过） |
| 1 | 至少一项不符合 |
| 2 | 用法或输入错误：未知命令或参数、参数取值不合法、`apply`、`rollback`、`ports` 不在交互终端中运行 |
| 3 | 内部错误：命令意外失败。由 ERR 陷阱统一转换，避免被误读为"不符合"（退出码 1） |

M2 新增命令的退出码 0、1、3 的具体含义（2 的含义同上表）：

| 命令 | 0 | 1 | 3 |
|---|---|---|---|
| `apply` | 应用完成，进入待确认 | 不是 root；预检有不符合项；管理员没有输入 `yes`；另一个操作正在进行；应用失败（已恢复，或恢复未全部完成） | 内部错误。应用已经开始时，先恢复再退出 |
| `confirm` | 确认成功，随后的 `verify` 全部通过 | 确认被拒绝（第 2.6 节），状态不变；或者确认成功，但 `verify` 有不符合项 | 撤除自动恢复失败（第 2.6 节）；或者确认成功，但 `verify` 出现内部错误 |
| `_restore` | 已恢复，或无需恢复 | 恢复未全部完成 | 等待操作锁超过 15 分钟 |

`confirm` 成功后用 `exec` 运行 `verify`，退出码就是 `verify` 的退出码；输出中有"已确认"的就是第二种 1。`_restore` 只由 systemd 单元调用，不在帮助中列出。

M4 起 `confirm` 和 `_restore` 也处理 `ports` 的变更，退出码的含义同上表（第 2.11 节）。M4 新增和改变的退出码：

| 命令 | 0 | 1 | 3 |
|---|---|---|---|
| `status` | 已输出状态，包括"未应用" | 不是 root | 内部错误 |
| `rollback` | 回滚完成 | 不是 root；另一个操作正在进行；没有可回滚的变更（未应用、已回滚）；回滚前检查有不符合项；管理员没有输入 `yes`；恢复未全部完成 | 内部错误 |
| `ports` | 端口变更已生效，进入待确认 | 不是 root；另一个操作正在进行；状态不是"已应用"；变更前检查有不符合项；管理员没有输入 `yes`；变更失败（已恢复原端口，或恢复未全部完成） | 内部错误。变更已经开始时，先恢复原端口再退出 |
| `apply`（已应用时） | 参数与记录一致，`verify` 的检查全部通过，未做变更 | 参数与记录不一致或有不符合项，未做变更 | 内部错误 |

`ports` 的参数中，与记录有关的错误（新增面板端口或已声明的端口，撤销未声明的端口），以及在同一处判定的新增 22 和 80/tcp，在取得操作锁、读取记录之后才报告，退出码同样为 2；这时还没有执行变更前检查，也未做任何变更。安装脚本的退出码见第 2.12 节。

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

`apply` 先按上述格式输出预检结果，然后输出变更计划和 6 个步骤的标题（`== 1/6` 等）。软件包安装、UFW、Fail2ban 命令的输出写入工具日志（第 2.8 节），终端只显示每步的结论。`ports` 同样先输出变更前检查，再输出变更计划和 3 个步骤的标题；`rollback` 输出回滚前检查和回滚计划。

### 2.4 输入参数

`preflight` 和 `apply` 共用同一个解析器（`lib/vps-hardening/inputs.sh`），支持 `--选项 值` 和 `--选项=值` 两种写法。任何一项不合法都以退出码 2 结束，不做主机检查。

| 参数 | 规则 |
|---|---|
| `--panel-port` | 默认 2053（需求 D20）；1～65535，不能是 22 |
| `--open` | 可重复，最多 16 个；`端口/tcp\|udp[/both\|ipv4\|ipv6]`，地址族默认 `both`；端口不能是 22 或面板端口，`端口/协议` 不能是 80/tcp（80/udp 可以，需求 D35），同一端口和协议不能重复。可以不给出，这时 UFW 只放行 22/tcp；推荐流程中，3X-UI 的端口在安装 3X-UI 时用 `ports --add` 开放（需求 D41） |
| `--confirm-timeout` | 3～60 的整数分钟，默认 10（需求 D18） |

`apply` 先检查标准输入是否为终端（方案设计第 7.1 节），再解析参数。

`ports` 用同一文件中的另一个解析器（`parse_ports_options`），写法相同，同样先检查标准输入是否为终端：

| 参数 | 规则 |
|---|---|
| `--add` | 可重复；格式同 `--open`；不能是 22 或应用时的面板端口；`端口/协议` 不能是 80/tcp，也不能已在声明中 |
| `--remove` | 可重复；格式同 `--open`；必须是已声明的 `端口/协议`，不能是 22；省略地址族时按声明的地址族撤销，给出时须与声明的一致 |
| `--confirm-timeout` | 同上表 |

`--add`、`--remove` 至少一个，同一选项中 `端口/协议` 不能重复，变更后的公开端口最多 16 个。先撤销、后增加，所以同一端口换地址族可以在一次变更中完成（如 `--remove 443/tcp --add 443/tcp/ipv4`）。格式和范围在检查主机之前判定，与记录有关的几项在读取记录之后判定（第 2.2 节）。`status` 和 `rollback` 不接受参数。

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
5. 核实状态为 active。规则行不记录：`verify` 的 `ufw.rules` 与声明比较（第 4 节）。v0.5 及之前把这时 `ufw status` 的规则行记入 `ufw-rules`，以它为准；UFW 未启用时已添加的规则在第 4 步一起生效，也进入了记录，此后 `verify` 不会报告（需求 D34）。

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

**再次执行。** 取得操作锁之后按状态处理：

- "已应用"：不做预检，也不提示确认（NFR-03，方案设计第 7.3 节）。先比较本次的面板端口和公开端口（含地址族，按集合比较）与应用记录（`apply.inputs`），再执行 `verify` 的全部检查。全部通过时输出"已应用，全部通过，未做任何变更"，退出码为 0；否则列出不符合项，退出码为 1，同样不做变更。确认时限不比较：它只在待确认期间起作用。漂移不修复：公开端口用 `ports` 变更，其他不符合项由管理员处理，或回滚后重新应用。
- "已回滚"：预检的 `new-host.state` 通过，按正常流程再次应用；第 3 步删除上次的记录和快照，包括端口变更的快照。
- 其他状态：被预检拒绝（第 3 节）。

M2、M3 中，已应用的主机上再次执行 `apply` 被预检拒绝，退出码为 1。

### 2.6 `confirm`

`confirm` 不接受参数。它依次检查以下各项，任一项不满足就拒绝（退出码 1），状态不变：

1. 以 root 运行。
2. 取得操作锁，不等待。
3. 状态为"待确认"或"端口变更待确认"，且待确认标记存在。
4. 本进程的登录 UID（`/proc/$$/loginuid`）为 0，即会话是以 root 登录的，不是经 sudo 或 su 切换的。
5. 本进程的审计会话编号（`/proc/$$/sessionid`）有效（不是表示"未设置"的 4294967295），且与标记中记录的发起会话（`apply` 或 `ports`）的编号不同。
6. 祖先进程中有 `sshd` 或 `sshd-session`，即会话来自 SSH，不是控制台。OpenSSH 9.8 起每个会话由 `sshd-session` 进程处理（Debian 13）。

第 4～6 项的依据见第 8.4 节（DR-11）。拒绝时的提示说明具体原因，例如在发起变更的会话中执行时，提示另开一个终端。这些检查防的是误操作，不防有意绕过的 root（方案设计第 7.5 节）。

全部满足后：

1. 撤除自动恢复：停止定时器、停用开机兜底单元、删除标记；
2. 状态改为"已应用"，记录确认时间（端口变更记录 `ports_confirmed_at`，并删除端口变更的快照）；
3. 输出面板隧道命令；
4. 释放操作锁，用 `exec` 运行 `verify`。

撤除失败时退出码为 3，状态仍为"待确认"，但自动恢复可能已部分撤除，例如定时器已经停止。这时应重新执行 `confirm`，完成撤除。

`confirm` 不创建临时目录：最后的 `exec` 不会触发 EXIT 陷阱，目录会留在系统中。

### 2.7 自动恢复

**布置（第 6 步）。**

1. 待确认标记 `/var/lib/vps-hardening/pending`：记录变更的种类（`apply` 或 `ports`）、发起会话的审计会话编号、截止时间和当前定时器的单元名。`ports` 用同一套布置（第 2.11 节）。
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

**按种类恢复。** `_restore` 读取标记中的种类：`ports` 只撤销端口变更（第 2.11 节）；其他值（包括 M2、M3 写的、没有种类的标记）执行上表的完整恢复。完整恢复成功时一并删除端口变更的快照，所以端口变更待确认期间执行 `rollback`，端口变更随其他变更一起撤销。

**快照的范围。** 快照在安装软件包之后记录：

- 软件包带来的文件，恢复为软件包的版本；
- 本工具新建的 4 个文件（SSH 片段、jail、`fail2ban.local`、APT 配置），恢复为不存在。

恢复每个文件时，先写到 `<路径>.vh-restore`，按记录设置权限和属主，再改名替换，最后核对摘要。

**互斥。** `apply`、`confirm`、`ports`、`rollback`、`_restore` 和安装脚本共用 `/run/vps-hardening.lock`（`flock`）：

- `apply`、`confirm`、`ports`、`rollback` 和安装脚本不等待，锁被占用时直接拒绝；`status` 不取锁（第 2.9 节）；
- `_restore` 最多等 15 分钟。取得锁后再检查标记：确认已经完成，或应用失败后已经自行恢复时，标记已不存在，它不做任何事；
- 锁文件在 `/run` 中，重启后不会残留。

### 2.8 状态记录

目录 `/var/lib/vps-hardening` 的权限为 0700，其中的文件都是 0600，属主 root（FR-13）：

| 文件 | 内容 |
|---|---|
| `state` | 每行一个 `键=值`，见下表 |
| `pending` | 只在待确认期间存在：`kind`（`apply` 或 `ports`，M4 新增）、`session`（发起变更的会话的审计会话编号）、`deadline`（截止时间，Unix 秒）、`timer`（当前定时器的单元名） |
| `units` | 每行一个受管单元：名称、应用前是否存在、`is-enabled`、`is-active`。受管单元为 `ufw.service`、`fail2ban.service`、`apt-daily.timer`、`apt-daily-upgrade.timer` |
| `snapshot/` | `index` 每行一个受管文件：`序号 present 摘要 权限:UID:GID 路径`，或 `序号 absent - - 路径`；`0`～`7` 是对应文件的副本 |
| `snapshot-ports/` | M4 新增，只在端口变更待确认期间存在：`index` 和副本的格式同 `snapshot/`，只含 `/etc/ufw/user.rules`、`/etc/ufw/user6.rules`；`open` 为变更前的公开端口。确认或恢复后删除。与 `snapshot/` 分开，所以 `rollback` 始终以应用前的快照为准 |
| `log` | 带 UTC 时间的操作记录（恢复时每一步一行，便于定位耗时），以及软件包安装、UFW、Fail2ban 命令的输出 |

受管文件：SSH 片段、`/etc/default/ufw`、`/etc/ufw/ufw.conf`、`/etc/ufw/user.rules`、`/etc/ufw/user6.rules`、Fail2ban 的 jail 和 `fail2ban.local`、APT 配置。

`state` 中的键：

| 键 | 含义 |
|---|---|
| `status` | `applying`（应用中）、`pending`（待确认）、`applied`（已应用）、`ports-pending`（端口变更待确认，M4 新增）、`restoring`（恢复中）、`rolled-back`（已回滚）、`restore-failed`（恢复失败） |
| `version` | 工具版本 |
| `started_at`、`applied_at`、`confirmed_at`、`restore_started_at`、`rolled_back_at` | UTC 时间 |
| `rollback_reason` | 回滚原因：确认超时、待确认期间重启、应用失败及其原因，或手工回滚；恢复未全部完成时附失败的步骤 |
| `panel_port`、`open`、`confirm_timeout` | 输入参数；`open` 带地址族，如 `443/tcp/both`，端口变更后更新为新的声明 |
| `apply_session` | 发起 `apply` 的审计会话编号 |
| `denied_users` | 被禁止经 SSH 登录的账户 |
| `root_keys` | root 可用公钥的 SHA256 指纹，不记录公钥本身 |
| `ufw_was_active` | 应用前 UFW 是否已启用 |
| `packages_added` | 本次安装的软件包 |
| `digest.0`～`digest.7` | 应用后每个受管文件的 SHA-256（或 `absent`）和路径；端口变更后更新两个 UFW 规则文件的 |
| `ports_started_at`、`ports_confirmed_at`、`ports_rolled_back_at` | 最近一次端口变更的开始、确认和恢复原端口的时间（UTC，M4 新增） |
| `ports_rollback_reason` | 最近一次端口变更恢复原端口的原因（M4 新增） |

- 写入方式：整个文件经 awk 生成新文件，改名替换后 `sync`，中途断电不会留下写了一半的文件。值中不允许换行。
- "恢复中"和"恢复失败"是方案设计第 7.3 节状态图之外新增的状态。恢复没有全部完成时不能记为"已回滚"，否则预检会允许再次应用。
- "端口变更待确认"也是新增的状态（M4）。它与"待确认"共用标记和自动恢复，但恢复只撤销端口变更，成功后回到"已应用"。端口变更的恢复同样先记为"恢复中"，没有全部完成时记为"恢复失败"，原因以"端口变更："开头，之后由 `rollback` 处理（第 2.10 节）。
- 记录中没有密码和私钥：工具不读取密码，也不开启 `set -x`。
- M2～M4 的开发版还写有 `ufw-rules`（应用后 `ufw status` 的规则行，端口变更时在 `snapshot-ports/` 中另存一份）。v0.6 起不再写入，也不再读取（第 2.5 节）；旧版本留在状态目录中的这个文件不影响任何判定。

### 2.9 `status`

`status` 不接受参数，只读，不取操作锁，所以另一个操作运行时也能回答，显示的是那一刻的状态。需要 root（状态目录只有 root 可读），否则退出码为 1。它不重新检查主机：当前配置是否仍然符合，由 `verify` 判定。

输出依次为（值为空的行省略）：

1. 工具版本和状态（中文名称）。没有状态文件时输出"未应用"并结束。
2. 应用记录：应用时的版本，应用开始、完成和确认的时间，面板端口（注明不开放，只经 SSH 隧道访问），公开端口（22/tcp 在前），确认时限，被禁账户，root 公钥指纹，本工具安装的软件包。
3. 受管文件：每个文件应用前和最近一次变更后的 SHA-256 前 12 位，"不存在"表示当时没有这个文件（FR-13）。
4. 最近一次端口变更：开始时间，以及确认时间，或恢复原端口的时间和原因。
5. 回滚的时间和原因，日志的路径。
6. 待确认（"待确认"或"端口变更待确认"）时：端口变更前的公开端口，确认截止时间和剩余分钟数，确认命令，以及到期或重启的后果。"应用中""恢复中""恢复失败"时：提示确认没有其他操作在运行后执行 `rollback`。
7. 有应用记录时（第 4 节）：面板隧道命令，与 `apply`、`confirm` 输出的相同。

### 2.10 `rollback`

`rollback` 不接受参数，必须在交互终端中运行，对应方案设计第 7.3 节的手工回滚（FR-12）：

1. 不是 root 时拒绝；取操作锁，不等待。
2. 按状态处理：已应用、待确认、端口变更待确认可以回滚；"应用中""恢复中""恢复失败"也可以，用回滚完成被中断的应用或恢复；已回滚、未应用和无法识别的状态被拒绝（退出码 1）。
3. 回滚前检查，任一项不符合就以退出码 1 结束，不做变更：

| 编号 | 判定 |
|---|---|
| `rollback.snapshot` | 应用前快照的索引列出 8 个文件，每个副本的摘要与索引一致；否则不符合，无法完整回滚。状态为"应用中"且没有待确认标记时为 `INFO`：应用在布置自动恢复（第 6 步）之前中断，还没有修改配置，回滚只恢复服务状态 |
| `root.key`、`root.keys` | 同 preflight：root 至少有一把可用的公钥 |
| `rollback.sshd` | 回滚后的 sshd 配置（见下文）以 root 求值：`permitrootlogin` 为 `yes`、`without-password` 或 `prohibit-password`，`pubkeyauthentication` 为 `yes`，`port` 含 22；无法求值时不符合 |
| `rollback.password` | 不判定不符合：回滚后 `passwordauthentication` 为 `yes` 时为警告（公网主机上的密码猜测会随即开始），否则为 `INFO` |
| `rollback.ufw` | 记录中应用前 UFW 未启用。已启用时不符合：新机不会出现这种情况（FR-02），回滚后的规则也无法预先确认放行 22/tcp |

4. 输出回滚计划：恢复或删除的文件、停用 UFW、恢复 4 个受管单元、撤除待确认的自动恢复（如有）；保留本工具安装的软件包、root 的 `authorized_keys`、3X-UI 和 vps-tuning 的文件、本工具的状态记录和日志。
5. 与 `apply` 相同的两项确认（当前会话保持到回滚完成、服务商控制台可用），输入 `yes` 才继续。
6. 在运行中的系统上执行第 2.7 节的完整恢复，原因记为"手工回滚"。成功时退出码为 0，提示另开终端确认 root 仍可登录；恢复未全部完成时退出码为 1，状态为"恢复失败"，提示从服务商控制台检查。

`rollback.sshd` 在变更之前评估回滚后的配置：把 `/etc/ssh/sshd_config.d` 复制到临时目录，用快照中的版本替换本工具的片段（应用前不存在时删除），然后在私有挂载命名空间中（`unshare --mount --propagation private`）把副本绑定挂载到原目录上，执行 `sshd -t` 和 `sshd -T -C`（连接参数见第 6 节）。真实目录不变。主配置和其他片段不是受管文件，回滚不改变它们，所以这样求得的就是回滚后的生效配置。

应用在布置自动恢复之前中断时，开机兜底单元可能还没有写入。撤除自动恢复时跳过不存在的单元，不把"停用不存在的单元"算作失败，所以这种情况下的回滚也能完成。

### 2.11 `ports`

`ports` 在已应用的主机上增减公开端口（FR-14，方案设计第 7.3 节），必须在交互终端中运行。只有 `/etc/ufw/user.rules`、`/etc/ufw/user6.rules` 两个文件改变（`ufw allow`、`ufw delete` 只改写这两个文件）；面板端口始终不开放（需求 D16）。

1. 解析参数（第 2.4 节）；不是 root 时拒绝；取操作锁，不等待。
2. 状态必须是"已应用"。待确认、端口变更待确认、未应用和其他状态都被拒绝（退出码 1），提示先确认、等待到期或先执行 `apply`。
3. 计算新的声明：记录中的公开端口去掉 `--remove` 的，再加上 `--add` 的。与记录有关的参数错误在这一步报告（退出码 2）。
4. 变更前检查，任一项不符合就以退出码 1 结束，不做变更：`ports.ufw`（UFW 已启用）、`ports.rules`（当前规则与记录中的声明逐条一致，判定同 `verify` 的 `ufw.rules`；不一致时先用 `verify` 查看差异）、`ports.userrules`（`user.rules`、`user6.rules` 与记录的摘要相同，判定同 `verify` 的 `ufw.userrules`。`ufw allow`、`ufw delete` 按已解析的规则重写文件，不先拒绝的话，直接写入的行从文件中消失、摘要被重新记下，而这一行在 UFW 下次启动前仍然生效；v0.6 新增）、`ports.ssh`（有放行 22/tcp 的规则）、`root.key` 和 `root.keys`。
5. 输出变更计划：撤销和增加的端口、变更后放行的端口、面板端口不放行、确认时限；然后与 `apply` 相同的两项确认。
6. 执行三步：
   1. 记录变更前的规则：两个规则文件的快照和变更前的声明（`open`），都放在 `snapshot-ports/`，与应用前的快照分开；
   2. 布置自动恢复：与 `apply` 的第 6 步相同，标记的种类为 `ports`；状态改为"端口变更待确认"；
   3. UFW：先撤销、后增加。增加的命令与 `apply` 的相同；撤销用 `ufw delete allow …`，带上注释，与本工具写入的规则精确对应。然后核实结果，更新记录中的声明和两个文件的摘要，用完整时限重新计时，输出截止时间和确认命令。

`ufw delete` 删除不存在的规则时退出码仍为 0，所以第 3 步核实的是结果：`ufw status` 的规则行去掉 `(v6)` 标记、压缩空格、按地址族标记后，必须正好是 22/tcp 和新声明中的每个端口，在声明的地址族上各一条，来源为 `Anywhere`，带注释 `vps-hardening`。只放行一个地址族的规则在 `ufw status` 中也显示为 `Anywhere`，只靠 `(v6)` 区分 IPv6（ufw 0.36.2 `backend_iptables.py` 的 `get_status`）。

确认、恢复和失败：

- `confirm` 的检查与 `apply` 之后的相同（第 2.6 节），新会话不能是发起 `ports` 的会话。确认后删除端口变更的快照，记录 `ports_confirmed_at`，然后运行 `verify`。
- 到期未确认（运行时）或待确认期间重启（开机时），`_restore` 按标记的种类只撤销端口变更：状态改为"恢复中"；运行时先停止定时器；按 `snapshot-ports/` 恢复两个规则文件；运行时执行 `ufw reload`（开机时 UFW 尚未启动，启动时读取恢复后的文件）；恢复记录中的声明和两个文件的摘要；撤除自动恢复。全部成功时状态回到"已应用"，记录 `ports_rolled_back_at` 和原因；否则按第 2.8 节记为"恢复失败"。
- 失败分两个阶段，与 `apply` 相同：第 1 步（记录变更前的规则）失败时，删除端口变更的快照并记录原因（注明"尚未修改规则"），状态仍为"已应用"；从第 2 步起的失败、ERR 陷阱和 SIGINT、SIGTERM、SIGHUP 都立即按上面的方式恢复原端口，退出码为 1（内部错误为 3）。
- 端口变更待确认期间执行 `rollback`，执行的是完整恢复，端口变更随其他变更一起撤销（第 2.7 节）。

### 2.12 安装脚本

仓库根目录的 `install.sh` 是发行版安装脚本（NFR-07，方案设计第 4.5、7.9 节）。它只放置文件，不执行 `preflight` 或 `apply`。退出码：0 为安装完成或无需变更；1 为拒绝或失败；2 为用法错误（未知参数、缺少取值、`--source-dir` 不是绝对路径）。

- **绑定。** 脚本中的 `INSTALLER_VERSION`、`RELEASE_TAG`（须为 `v` 加版本）和 `EXPECTED_MANIFEST_SHA256`（发行版 `SHA256SUMS` 的 SHA-256）在每次发布时一起设置。仓库中的副本摘要为空，不绑定任何发行版，执行时拒绝。`tests/static.sh` 核对资产清单等于入口加它加载的全部模块，版本等于入口的 `VH_VERSION`。
- **来源。** 默认从 `https://github.com/alieismy/vps-hardening/releases/download/<标签>/` 下载 `SHA256SUMS` 和 13 个资产（入口和 12 个模块）。`curl` 只允许 HTTPS，重定向也只允许 HTTPS，最多 5 次，每个文件最长 120 秒；下载失败时结束，不会改用其他版本。`--source-dir 绝对路径` 从本地目录读取同样的文件，用于发布前验证（VT-72 的本地部分），校验规则相同。
- **校验。** `SHA256SUMS` 的摘要等于内置值；清单的非空行正好 13 行，每个资产一行、只出现一次，格式为 64 位小写十六进制摘要加文件名；每个资产的摘要等于清单中的值；入口中的 `VH_VERSION` 等于安装脚本的版本。
- **拒绝条件。** 不是 root；缺少所需的命令；存在待确认标记（待确认期间 systemd 单元会调用已安装的工具）；操作锁被占用（第 2.7 节，不等待）。
- **放置。** 已安装的文件与发行版完全一致时，输出"未做变更"。一致指：入口和每个模块的摘要相同，模块目录中没有多余的文件；入口和模块目录为 0755、模块为 0644，属主和属组都是 root（v0.7 增加属主和权限，需求 D40）。否则模块先写到 `/usr/local/lib/.vps-hardening.stage.<PID>`（目录 0755，文件 0644，属主 root），入口写到 `/usr/local/bin/.vps-hardening.new.<PID>`（0755）；已有入口时，用 `cp -a` 复制一份到 `/usr/local/bin/.vps-hardening.old.<PID>`。然后把旧模块目录改名为 `/usr/local/lib/.vps-hardening.old.<PID>`，新目录改名就位，入口改名替换，运行 `vps-hardening --version` 核对版本，`sync` 后删除旧目录和旧入口的副本。
- **未完成的替换（v0.7，需求 D40）。** 从复制旧入口之后到删除旧文件之前，失败或 INT、TERM、HUP 信号都由退出陷阱恢复安装前的文件，版本核对失败也一样：
  - 入口已被替换（临时入口已不在原处）时放回旧入口的副本，原来没有入口时删除入口；
  - 模块已被替换（暂存目录已不在原处）时删除新目录；旧目录存在时放回。
  - 每次改名是否已经发生，由文件是否还在原处判断，不由改名后才设置的变量判断，所以信号落在改名和下一行之间时也照样处理。恢复期间忽略这三种信号。
  - 恢复成功时输出"安装未完成，已恢复为安装前的状态"，退出码为 1；某一步失败时报告错误，旧目录和旧入口的副本保留，不删除。
  - v0.6 只在模块目录不存在时把旧目录放回：新目录就位之后、入口替换之前失败或被中断，留下新模块和旧入口，旧目录也不删除；新机上则留下没有入口的模块目录（第 8.15 节复现）。
  - `SIGKILL` 和断电不能由陷阱处理：临时文件和旧副本留在原处，要手工删除；重新执行安装脚本可以换成一致的文件。
- **awk 的正则。** 清单的格式检查不用正则区间（第 6 节）。
- **发布步骤（v0.6）。** 写入版本号的提交合并后，在合并提交上打附注标签 `v<版本>`。从这个合并提交的树中逐字节取出 13 个资产（入口和 12 个模块）；`SHA256SUMS` 每行为 64 位摘要、两个空格和文件名，入口在前、模块按名称排序，与 VT-72 本地部分的 `release_dir` 相同。Windows 的 Git Bash 中 `sha256sum` 输出 `*文件名`（二进制模式的标记），不符合上面的清单格式，不能直接用来生成清单。安装脚本的副本把 `EXPECTED_MANIFEST_SHA256` 设为这份 `SHA256SUMS` 的 SHA-256，与另外 14 项一起以 Pre-release 发布，不设为 Latest；仓库中的副本保持不绑定。发布后做 VT-72 的公开部分（第 8.14 节）。
- **结尾的提示（v0.6）。** 安装完成时，状态文件中有 `status=applied` 一行（已应用）就提示执行 `verify` 核对配置、`status` 查看记录；否则说明安装没有执行 `preflight` 或 `apply`，提示执行 `preflight`。v0.5 总是提示 `preflight`，而已应用的主机上预检会因 `new-host.state` 不符合而结束（第 8.11 节）。

## 3. preflight 检查项

前两项是门槛：不满足时立即结束，后续检查不执行。

| 编号 | 检查 | 不符合的条件 |
|---|---|---|
| `root` | 运行权限 | 不是 root |
| `platform` | 平台 | 不是 Debian 12/13 或 Ubuntu 24.04（x86_64/aarch64）；PID 1 不是 systemd；运行在容器中 |
| `inputs.*` | 输入摘要 | 不判定不符合：只回显已校验的面板端口、公开端口和确认时限；没有公开端口时 `inputs.open` 也通过，说明 UFW 只放行 22/tcp（v0.8，需求 D41；此前为警告） |
| `new-host.xui` | 存量判定 S1 | 存在 `x-ui.service` 或 `/usr/local/x-ui` |
| `new-host.container` | 存量判定 S4 | 存在 Docker（命令或 `docker.service`）或 Podman |
| `new-host.ufw` | 存量判定 S2 | UFW 已启用；或者未启用，但已有添加的规则（`ufw show added` 非空，这些规则会在 `apply` 启用 UFW 时生效）；无法读取已添加的规则时同样不符合。未安装 UFW 时通过 |
| `new-host.ufw-framework` | 存量判定 S2 | 只在 UFW 已安装、未启用时输出：`/etc/ufw` 中的 `before.rules`、`before6.rules`、`after.rules`、`after6.rules`、`before.init`、`after.init` 有与 `/usr/share/ufw` 中软件包的原始文件不同的（逐字节比较，缺少也算）。这些文件中的规则不显示在 `ufw status` 中（需求 D34） |
| `new-host.fail2ban` | 存量判定 S3 | 有 `*.local`；`jail.d`、`fail2ban.d` 中有发行版 `defaults-debian.conf` 以外的文件；或 `dpkg --verify fail2ban` 报告改动 |
| `new-host.state` | 是否执行过 | 存在 `/var/lib/vps-hardening`，且状态不是"已回滚"。上次应用已完全回滚的主机仍算新机（FR-02，方案设计第 7.3 节）；待确认、端口变更待确认、已应用、恢复失败等状态都不符合；"应用中""恢复中""恢复失败"时提示先执行 `rollback`（M4） |
| `sshd.config` | sshd 配置 | `sshd -t` 失败，或 `sshd -T` 读不出生效配置 |
| `sshd.include` | 片段能否生效 | 主配置在 `Include /etc/ssh/sshd_config.d/*.conf` 之前已设置受管选项或打开了 `Match`。`Include` 的参数按 sshd 的规则读取（第 6 节），带引号时同样识别（v0.7） |
| `sshd.dropin-order` | 片段排序 | 排在 `00-vps-hardening.conf` 之前的片段设置了受管选项或 `Match`，或本工具的片段已存在 |
| `sshd.match` | `Match` 块 | 主配置或它包含的任何文件中有 `Match` 行，不论位置和条件（需求 D36）。包含的文件按 `Include` 递归展开，相对路径以 `/etc/ssh` 为基准；注释行不计。每一行按 sshd 的规则读取（第 6 节）：带引号的关键字、带引号或转义空格的 `Include` 路径与普通写法相同（v0.7，需求 D40） |
| `root.key`、`root.keys` | root 的公钥（需求 FR-01、FR-03） | root 的 `authorized_keys`（按 root 的 `AuthorizedKeysFile` 生效值展开）中没有可用的公钥。可用指同时满足：行首就是密钥类型，不带选项（cloud-init 用 `command=` 前缀禁止 root 登录时，这样的行不算）；能被 `ssh-keygen -l -E sha256` 解析；算法在 `pubkeyacceptedalgorithms` 中（`ssh-rsa` 密钥以 `rsa-sha2-*` 判定）。按指纹去重，每把可用的公钥输出一行 `INFO root.key`（类型和指纹）；有未计入的行时，`root.keys` 注明行数 |
| `sudo.nopasswd-accounts` | 免密账户 | 只报告（`INFO`）：有 SSH 密钥且免密 sudo 的账户，应用时将被禁止 SSH 登录（需求 D13） |
| `apt.idle` | 包管理器 | dpkg、apt 或 unattended-upgrades 的锁被持有，或 apt、dpkg 进程在运行 |
| `apt.candidates` | 软件包来源 | `ufw`、`fail2ban`、`nftables`、`python3-systemd`、`unattended-upgrades` 中有没有候选版本的 |
| `apt.fail2ban-version` | Ubuntu 的 fail2ban | 候选版本低于 `1.0.2-3ubuntu0.1` |
| `reboot.required` | 待重启 | 不判定不符合：存在 `/var/run/reboot-required` 时为警告，不阻止 `apply`；与第 4 节的同名检查项相同（v0.8，需求 D43） |

受管的 sshd 选项：`permitrootlogin`、`passwordauthentication`、`kbdinteractiveauthentication`、`pubkeyauthentication`、`denyusers`。

## 4. verify 检查项

区域和判定依据见方案设计第 7.6 节。"有应用记录"指状态为"已应用"、"待确认"或"端口变更待确认"（端口变更待确认时，记录中已是新的声明）。各检查项的实现状态：

| 编号 | 判定 | 状态 |
|---|---|---|
| `root`、`platform` | 同 preflight 的门槛 | 已实现 |
| `state` | "已应用"时通过；"待确认"时为警告，注明约几分钟后自动恢复；"端口变更待确认"时为警告，注明约几分钟后恢复原端口；没有状态目录、"已回滚"和其他状态为不符合 | M2 已实现；端口变更为 M4 新增 |
| `ssh.dropin` | SSH 片段的 SHA-256 等于应用时的记录 | M2 已实现；没有应用记录时跳过 |
| `ssh.denied` | 每个被禁账户：以它的身份执行 `sshd -T -C`，它在 `DenyUsers` 中，密码和键盘交互认证都是 `no` | M2 新增；没有被禁账户时不输出 |
| `ufw.rules` | `ufw status` 的规则行与记录中的声明逐条一致：22/tcp 和每个公开端口在声明的地址族上各一条，来源为 `Anywhere`，带注释 `vps-hardening`（规整方法同第 2.11 节）；多出或缺少规则都不符合；IPv4、IPv6 规则分别计 | M2 已实现；v0.6 改为与声明比较（之前与应用后记录的规则行比较，第 2.5 节）；没有应用记录时跳过 |
| `ufw.userrules` | `/etc/ufw/user.rules`、`/etc/ufw/user6.rules` 的 SHA-256 等于记录：`apply` 结束时记下，`ports` 变更后和恢复后更新（第 2.8 节）。`ufw status` 只列出带 tuple 注释的规则，直接写入文件的行由这一项发现；不一致时列出不一致的文件 | v0.6 新增（需求 D37）；没有应用记录时跳过 |
| `ufw.panel` | 没有放行面板端口的规则，不论协议；判定方法与 `ufw.port80` 相同 | M2 已实现；没有应用记录时跳过 |
| `uu.dropin` | 本工具的 APT 配置 `/etc/apt/apt.conf.d/52vps-hardening` 的 SHA-256 等于应用时的记录 | M3 新增；没有应用记录时跳过 |
| `boundary.panel-listen` | 安装了 3X-UI 时（判定同 `new-host.xui`），应用时声明的面板端口上的 TCP 监听地址都是回环地址（`127.0.0.0/8`、`::1`、`::ffff:127.0.0.0/104`）；有非回环地址时不符合；端口上没有监听时为警告，无法核对 | M3 实现；未安装 3X-UI 时为 `INFO`，没有应用记录时跳过 |
| `accounts.nopasswd` | 有密钥、免密 sudo、又不在 `DenyUsers` 中的登录账户 | 已实现 |
| `ssh.permitrootlogin`、`ssh.passwordauthentication`、`ssh.kbdinteractive`、`ssh.pubkey`、`ssh.forwarding`、`ssh.port` | 以 root 身份执行 `sshd -T -C` 的生效值：`without-password` 或 `prohibit-password`（`sshd -T` 用旧名 `without-password` 输出 `prohibit-password`）、`no`、`no`、`yes`、`yes` 或 `local`、`22` | 已实现；被禁账户另由 `ssh.denied` 检查 |
| `ssh.match` | 同 preflight 的 `sshd.match`：主配置及其包含的文件中没有 `Match` 块。有 `Match` 块时，上一行以 root 求得的值不代表所有来源 | v0.6 新增（需求 D36）；v0.7 按 sshd 的规则读取（需求 D40） |
| `root.key`、`root.keys` | 同 preflight：root 至少有一把可用的公钥 | 已实现 |
| `ssh.listen` | 22 端口在 IPv4 上监听为必需；没有 IPv6 时为警告 | 已实现 |
| `ufw.installed`、`ufw.active`、`ufw.defaults`、`ufw.ipv6`、`ufw.port80` | 已安装并启用；默认拒绝入站、允许出站、拒绝转发；`IPV6=yes`；没有放行 80/tcp 的入站规则（不限协议的 80 也算，只放行 80/udp 的不算，需求 D35）。转发策略：`ufw status verbose` 显示 `deny (routed)` 或 `disabled (routed)`，并且 `/etc/default/ufw` 中为 `DEFAULT_FORWARD_POLICY="DROP"`。内核没有开启转发时，ufw 把转发策略显示为 `disabled`（第 8.4 节） | 已实现；转发策略的判定在 M2 修改；`ufw.port80` 在 v0.6 改为只判 80/tcp |
| `ufw.framework` | 同 preflight 的 `new-host.ufw-framework`：6 个框架文件与 `/usr/share/ufw` 中的原始文件相同。UFW 未安装时，与 UFW 的其他检查项一样不输出（`ufw.installed` 不符合） | v0.6 新增（需求 D34） |
| `f2b.installed`、`f2b.service`、`f2b.jails`、`f2b.mainconf` | 已安装；服务启用且运行；jail 只有 `sshd`；`jail.conf`、`fail2ban.conf` 未改动 | 已实现 |
| `f2b.config` | `fail2ban-client -t` 成功 | M3 新增 |
| `f2b.values` | 服务有响应时，读取 14 项生效值，逐项等于 FR-08（见下文）；服务没有响应时不符合 | M3 实现；期望值都是常量，不需要应用记录 |
| `f2b.files` | 本工具的 `jail.d/99-vps-hardening.local` 和 `fail2ban.local` 的 SHA-256 等于应用时的记录；`/etc/fail2ban` 下没有软件包和本工具以外的文件；`dpkg --verify fail2ban` 没有报告 `jail.conf`、`fail2ban.conf` 以外的改动（这两个文件由 `f2b.mainconf` 报告） | M3 新增；没有应用记录时跳过 |
| `nft.service` | `nftables.service` 未启用 | 已实现 |
| `uu.installed`、`uu.periodic`、`uu.reboot`、`uu.origins`、`uu.timers` | 已安装；两个 `APT::Periodic` 值为 1；不自动重启；来源列表与 FR-09 一致；两个 APT 定时器启用且运行 | 已实现 |
| `boundary.container`、`boundary.xui-bbr` | 没有 Docker 或 Podman；没有 `/etc/sysctl.d/99-bbr-x-ui.conf` | 已实现 |
| `reboot.required` | 存在 `/var/run/reboot-required` | 警告 |

`ufw.rules` 用 `ufw status` 而不用 `ufw show added`：后者丢失地址族，只放行 IPv4 的 `proto udp to 0.0.0.0/0 port 8443` 显示为 `ufw allow 8443/udp`，与两个地址族都放行的规则无法区分（第 8.4 节）。`ufw status` 只在 UFW 启用时列出规则，未启用时 `ufw.rules` 与 `ufw.active` 一起报告不符合。预检的 `new-host.ufw` 反过来用 `ufw show added`：UFW 未启用时 `ufw status` 不列出规则，而预检只需要知道有没有已添加的规则，不需要地址族。

Fail2ban 各项的输出顺序为 `f2b.installed`、`f2b.service`、`f2b.config`、`f2b.jails`、`f2b.values`、`f2b.files`、`f2b.mainconf`。`f2b.values` 的读取和比较：

- 14 项：`sshd` 的 `bantime`、`findtime`、`maxretry`、`bantime.increment`、`bantime.maxtime`、`bantime.rndtime`、`ignoreself`、`ignoreip`、`usedns`、`journalmatch`、`actions`，动作 `nftables` 的 `port` 和 `protocol`，以及全局的 `dbpurgeage`。每项用 `fail2ban-client get` 读取，有 30 秒超时。
- 规整：输出多于一行时去掉第一行的标题（例如 `Current match filter:`），去掉列表项前缀 `|- ` 和 `` `- ``，排序后用空格连接；`dbpurgeage` 的 `2592000seconds` 取数字。时间按秒比较（`1d` 为 86400，`4w` 为 2419200）；布尔值为 `True`；`ignoreip` 按服务器规整后的网络比较（`127.0.0.1/8` 显示为 `127.0.0.0/8`）。
- 读不回的两项：过滤模式 `mode=normal` 和 `banaction`。`banaction = nftables` 体现为动作名 `nftables` 和它的端口、协议，已在 14 项中；过滤模式只写在 jail 文件中，由 `f2b.files` 的摘要覆盖。
- 期望值都是 FR-08 的常量，所以 `f2b.values` 不需要应用记录（v0.3 写的是"需要应用记录中的声明值"，实现时确认只有 `boundary.panel-listen` 需要，它取记录中的面板端口）。

`f2b.files`、`f2b.mainconf` 和预检的 `new-host.fail2ban` 都依据 `dpkg --verify fail2ban` 的输出。文件被改动时它的退出码仍为 0；非 0 表示无法校验：软件包未安装为 1，读取文件出错为 2，此时输出可能不完整（dpkg 1.21.22、1.22.6、1.22.22 的 `src/main/verify.c` 相同）。退出码非 0 时三项都判为不符合（第 6 节）。

`f2b.files`、`uu.dropin` 与 M2 的 `ssh.dropin` 用同一个摘要判定。SSH 片段、jail 文件和 APT 配置的首行注释都写着"verify reports any change"，M2 只对 SSH 片段兑现了这一点；`f2b.config` 对应方案设计第 7.6 节 Fail2ban 区域的"配置检查通过"。这三项超出 v0.3 第 1 节列给 M3 的范围，已经用户确认（第 1 节）。

`uu.origins` 的期望集合（从 `apt-config dump` 读取，`${distro_*}` 占位符原样比较）：

- Debian：`Origins-Pattern` 为发行版默认的三项（`label=Debian`、两项 `Debian-Security`），`Allowed-Origins` 为空；
- Ubuntu：`Allowed-Origins` 为 `${distro_id}:${distro_codename}-security` 和两项 ESM 安全来源，`Origins-Pattern` 为空。

## 5. 模块划分

| 文件 | 职责 |
|---|---|
| `bin/vps-hardening` | 环境、加载模块、ERR 陷阱（应用期间先调用恢复钩子）、子命令分派、帮助 |
| `lib/vps-hardening/common.sh` | 常量、退出码、`report` 和汇总、临时目录、拒绝（`refuse`）、`apply`、`ports`、`rollback` 共用的两项确认（`safeguards_prompt`）、通用小函数 |
| `lib/vps-hardening/platform.sh` | 解析 `/etc/os-release`（按数据解析，不执行）、平台判定、systemd 和容器判断 |
| `lib/vps-hardening/inputs.sh` | `preflight`、`apply` 和 `ports` 的参数解析和校验 |
| `lib/vps-hardening/probe.sh` | 只读探测：软件包、单元、sshd 生效配置、账户和密钥（含 root 的可用公钥）、sudo、监听端口、UFW、apt 配置、包管理器锁 |
| `lib/vps-hardening/preflight.sh` | preflight 检查 |
| `lib/vps-hardening/verify.sh` | verify 检查 |
| `lib/vps-hardening/state.sh` | 状态目录：状态文件读写、操作日志、操作锁、快照（应用前的和端口变更的）和恢复、受管文件摘要的记录、受管单元状态的记录 |
| `lib/vps-hardening/pending.sh` | 待确认：会话判定、开机兜底单元、临时定时器、布置和撤除自动恢复、完整恢复和端口恢复、`confirm`、`_restore` |
| `lib/vps-hardening/apply.sh` | `apply`：已应用时的核对、变更计划、交互确认、各步骤的写入和核实、失败处理 |
| `lib/vps-hardening/status.sh` | `status` |
| `lib/vps-hardening/rollback.sh` | `rollback`：回滚前检查（含在私有挂载命名空间中评估回滚后的 sshd 配置）、回滚计划 |
| `lib/vps-hardening/ports.sh` | `ports`：计算新的声明、变更前检查、UFW 规则的变更和核实、失败处理 |
| `install.sh` | 发行版安装脚本，独立运行，不加载上面的模块（第 2.12 节） |

## 6. 实现约束

- **只读。** preflight 和 verify 只调用读取类命令；临时文件只写在 `mktemp -d` 创建的私有目录中，退出时删除。测试在每个用例前后比较状态摘要（第 7.4 节）。
- **有界。** 可能被服务阻塞的读取命令（`sshd`、`ufw`、`fail2ban-client`、`apt-config`、`apt-cache`、`sudo -l`）加 30 秒超时。`apply` 和恢复中改变系统的 `systemctl`、`ufw`、`systemd-run` 命令加 120 秒超时，软件包安装 30 分钟（方案设计第 7.5 节）。Bash 要等当前命令返回才执行信号陷阱，不设超时的话，一个卡住的命令会同时挡住断线后的恢复；定时器触发的恢复等锁 15 分钟后也会放弃。
- **写入。** 受管文件先写到 `<路径>.vh-new`，设权限 0644 后改名替换；状态文件同样改名替换（第 2.8 节）。`apply` 中 `apt-get` 的标准输入为 `/dev/null`，不会读走管理员终端上的输入。
- **管道与 `pipefail`。** 读取端不提前退出（不用 `head`、`grep -q` 截断长输出），否则写入端会因 SIGPIPE 失败，在 `pipefail` 下被误判。`apt-config dump` 的输出缓存后复用。
- **sshd 生效值。** 用 `sshd -T -C user=<用户>,host=vps-hardening.invalid,addr=192.0.2.1,laddr=192.0.2.2,lport=22` 按用户求值，结果按用户缓存。地址取自文档保留地址。按一个连接求值不能代表所有来源，所以有 `Match` 块的配置被拒绝（`sshd.match`、`ssh.match`，需求 D36）；没有 `Match` 块时，求得的值与这些连接参数无关。v0.5 写的是"使 `Match Address` 块按普通外部来源求值"，这只覆盖了一个来源（需求 D34）。
- **包管理器是否在运行。** 以锁的持有者（`lslocks`）为准，再加 apt、dpkg 进程名。进程名逐个交给 `pgrep -x`：整个模式超过 15 个字符时 pgrep 不匹配任何进程，用 `|` 拼接的模式会静默失效。不能用进程名判断 unattended-upgrades：它的关机辅助进程常驻，进程名截断后与升级进程相同。
- **ERR 陷阱。** 只在主 shell 中把意外失败转换为退出码 3。`$(...)` 和管道中的命令也会触发陷阱，其中包括预期的非零状态（如查询未安装的单元），所以子 shell 中不处理；真正的失败经退出状态回到主 shell 后再判定。
- **启发式判定。** `root.keys` 只计入格式明确的公钥行（带选项的行即使实际能登录也不计入），`new-host.fail2ban` 以文件存在为准，`dpkg --verify` 无法校验时视为有改动。两者在不确定时都判为不符合，宁可误拒，不会误放行。
- **awk 的正则。** awk 程序中不用正则区间（`{n}`、`{m,n}`）：Debian 12 默认的 mawk 1.3.4 20200120 不支持，这样的模式匹配不到定长的文本（第 8.10 节）。需要定长时用 `length()` 加字符类判断。Bash 的 `[[ =~ ]]` 不受影响。
- **sshd 配置的读取（v0.7）。** `preflight.sh` 中的 `VH_SSHD_AWK` 是一组 awk 函数，`sshd.include`、`sshd.dropin-order`、`sshd.match` 和 `ssh.match` 都用它读取 sshd 配置，按 sshd 的规则（需求第 10.1 节）：`sshd_keyword` 照 `load_server_config()` 和 `process_server_config_line_depth()` 去掉首尾空白，照 `strdelim()` 取出关键字并转为小写；`sshd_args` 照 `argv_split()` 拆分其余部分。这几段代码在 OpenSSH 9.2p1、9.6p1、10.0p2 中相同；Debian、Ubuntu 的补丁是否改动了它们没有逐一核对，VT-02 在三个平台上用 `sshd -T -C` 确认 sshd 应用了这些写法的块（第 7.3 节）。`sshd_config_files` 按行记录已列出的文件，路径中的空白不会使两个文件混同。函数在 bash 的单引号字符串中，单引号写作 `"\047"`。

## 7. 测试框架

### 7.1 组成

| 文件 | 作用 |
|---|---|
| `tests/vm.py` | 运行器侧：下载并校验官方云镜像，生成 cloud-init 种子，启动 QEMU，按阶段在客体中执行测试，收集证据。改编自 vps-tuning 的 `tests/platform-vm.py` |
| `tests/guest/m1.sh` | 客体侧：M1 各阶段的准备、用例和判定，以及 `apply` 被预检拒绝的用例 |
| `tests/guest/m2.sh` | 客体侧：M2 的状态记录、第二来源、登录和端口检查、恢复后的核对；复用 `m1.sh` 的函数 |
| `tests/guest/m3.sh` | 客体侧：M3 的 Fail2ban、自动更新、3X-UI 共存和漂移用例；复用 `m2.sh` 的函数 |
| `tests/guest/m4.sh` | 客体侧：VT-61、VT-63、VT-64 和 VT-72 本地部分的准备、用例和判定；复用 `m2.sh` 的函数。VT-60 在 matrix 的主流程中执行，回滚后的核对复用 `m2.sh` 的阶段 |
| `tests/platform-images.json` | 镜像 URL 和摘要，与 vps-tuning 同源 |
| `tests/static.sh` | 不需要虚拟机的检查：shell 和 Python 语法、安装脚本的资产清单和版本（第 2.12 节）、LF 行尾、通用秘密特征 |
| `.github/workflows/static.yml` | 运行 `tests/static.sh` 和 ShellCheck 0.11.0（固定容器镜像）。ShellCheck 只报告命令行列出的文件，不报告经 `-x` 跟随的文件，所以列出全部模块和 `install.sh` |
| `.github/workflows/vm.yml` | matrix、recovery、negative 和 hardened 四组作业，证据作为构件保存 14 天。`bin`、`lib`、`tests`、`install.sh` 或工作流本身改动时运行（M4 加入 `install.sh`）。拉取请求和推送只运行 amd64；手动触发并选中 `arm64` 时，matrix、recovery 和 hardened 另在 arm64 上运行（需求 D26） |

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
- **3X-UI 夹具。** 按验证计划第 3.5 节在确认之后安装 v3.10.2（需求 D32；`XUI_PANEL_PORT=2053`，监听改为 `127.0.0.1`）。`install.sh` 解压后会删除发布包，所以 VO-1 在解压后的文件上核对：`/usr/local/x-ui/x-ui` 和 `/usr/local/x-ui/bin/xray-linux-<架构>` 的 SHA-256 等于从发布包中取得的值（验证计划第 3.5 节），`/usr/local/x-ui/x-ui.sh` 和 `/usr/bin/x-ui` 都等于 tag 中的 `x-ui.sh`。v3.10.2 的 `install.sh` 从同一 tag 取得菜单脚本，所以不再像 v3.7.0 那样用 tag 中的 `x-ui.sh` 替换 `/usr/bin/x-ui`。负向套件的 S1 使用同一个安装函数。
- **面板的 WebBasePath。** 由测试驱动在客体中读取（`x-ui setting -show true`），只用于经隧道访问；它被加入泄露扫描的标记，不写入证据。

M4 的测试再增加以下内容：

- **交互命令。** `rollback`、`ports` 和再次执行的 `apply` 与 `apply` 一样经 `ssh -tt` 在伪终端中运行，测试驱动看到两项确认的提示后输入 `yes`；取消的情况输入其他内容。标准输入不是终端的情况不经伪终端运行。
- **覆盖层。** VT-61、VT-63、VT-64 各用一个以 hardened 磁盘为底的覆盖层，与 VT-51 相同；启动后重新放置 `apt-daily-upgrade.service` 的空操作替换，并等待包管理器空闲。
- **测试用 HTTP 服务。** VT-63 在 443、2096、8443、9443 上各运行一个，方式同 M2；可达性从第二来源 `.2` 在 IPv4 和 IPv6 上检查。
- **工具记录。** VT-63、VT-64 判定"不产生变更"时比较：状态目录中每个文件的摘要、8 个受管文件的摘要、`ufw status verbose`、受管单元和开机兜底单元的状态，以及恢复定时器的列表。
- **发行版目录。** VT-72 的本地部分在客体中按发布流程生成发行版目录（入口、12 个模块和 `SHA256SUMS`），把安装脚本的一个副本绑定到这个目录的摘要，然后用 `--source-dir` 安装。仓库中的安装脚本保持未绑定。

### 7.3 套件与用例

| 套件 | 平台 | 内容 |
|---|---|---|
| matrix | 三平台 amd64；arm64 按需（参考） | 准备；核实转发连接在客体中的来源地址；VT-01；VT-50 的未加固部分；sshd 探测研究。然后在同一客体上执行 M2 的主流程：应用 → 三种被拒绝的确认 → 从新会话确认 → 核对 → 隧道 → 重启后核对 → 回滚（VT-60）。待确认、确认后和回滚后各执行一次 `status` |
| recovery | 三平台 amd64；arm64 按需（参考） | 准备好的磁盘为底，两个覆盖层：确认超时（时限 3 分钟，应用后不确认）；待确认期间从应用会话重启 |
| negative | 三平台 amd64 | 准备；VT-02、VT-04；关机后以准备好的磁盘为底，S1～S4 各用一个覆盖层磁盘启动（VT-03），S2 的覆盖层在启用 UFW 之前先检查两种未启用时的情形；S2 中检查 UFW 是否过滤转发连接；再用一个覆盖层执行 VT-23，之后在这个覆盖层上解除对 `fail2ban.service` 的屏蔽，再次应用并确认（VT-64 的第四种情况）；最后用一个覆盖层执行 VT-72 的本地部分 |
| hardened | 三平台 amd64；arm64 按需（参考） | 准备，记录基线；不声明公开端口执行 `apply`，从新会话确认，核对记录中没有公开端口、UFW 只放行 22/tcp（v0.8，需求 D41）；VT-30、VT-31、VT-33 和 VT-35、VT-32、VT-34、VT-40；安装 3X-UI（VT-55 第一部分、VT-50、VT-71）；`ports --add 443/tcp --add 2096/tcp`（3X-UI 的入站和订阅端口），从新会话确认，核对状态为"已应用"、声明为 `443/tcp/both 2096/tcp/both`、没有残留的自动恢复、UFW 规则与声明逐条一致，`verify` 通过（v0.8）；经隧道打开面板；重启后核对（VT-55 第二部分）。以上全程持续探测（VT-25）。关机后以这块磁盘为底，12 个覆盖层各注入一项漂移（VT-51）；另有 VT-61、VT-63、VT-64 各一个覆盖层 |

M1 用例的判定要点：

- VT-01：`preflight` 退出码为 0，`root.keys` 和 `reboot.required` 通过，前后状态摘要一致。v0.8 增加一次：放置 `/var/run/reboot-required` 后不带 `--open` 执行 `preflight`，退出码为 0，`reboot.required` 为警告，`inputs.open` 通过，前后摘要一致，之后删除标记（需求 D41、D43）；
- VT-50（未加固）：`verify` 退出码为 1；`state`、`ssh.passwordauthentication`、`accounts.nopasswd`、`f2b.installed` 为不符合，Debian 上 `ufw.installed`、Ubuntu 上 `ufw.active` 为不符合；`ssh.permitrootlogin`（镜像默认已是 `prohibit-password`）、`root.keys`、`ssh.pubkey`、`ssh.port`、`nft.service`、`boundary.container`、`boundary.xui-bbr` 为通过；前后摘要一致；所有证据中没有测试密码；
- VT-02：非 root（`runuser -u nobody`）、不支持的版本（在私有挂载命名空间中覆盖 `/etc/os-release`）、root 没有可用的公钥（同样在私有挂载命名空间中，用只有注释、只有带 `command=` 选项、只有无法解析的行三种文件覆盖 root 的 `authorized_keys`）、dpkg 前端锁被占用、有不持锁的 `dpkg` 进程，分别得到对应的不符合项或退出码 2。v0.6 增加 sshd 配置中有 `Match` 块的两种情况，都在私有挂载命名空间中覆盖，真实文件不变：主配置末尾加 `Match Address 198.51.100.0/24` 块（块内 `PasswordAuthentication yes`），`preflight` 退出码为 1，`sshd.match` 不符合，`sshd.include` 通过；片段目录中加同样内容的 `99-match.conf`，`apply` 在预检阶段被拒绝，`sshd.match` 不符合。v0.7 增加两种按 sshd 的规则写的主配置副本（需求 D40）。第一种把片段目录的 `Include` 加上引号，并在末尾包含 `/root/vh-private/match dir/` 中的两个文件，一个路径用双引号括起，一个用反斜杠转义空格，两个文件中分别是 `Match Address 198.51.100.0/25` 和 `198.51.100.128/25` 块。第二种在末尾加以 `"Match"` 开头的 `198.51.100.0/24` 块。每个块除了 `PasswordAuthentication yes`，还设各不相同的 `MaxAuthTries`（2、3、4）作为标记：客体在加固前就允许密码登录（第 7.2 节的 `50-cloud-init.conf`），`passwordauthentication` 不能说明块是否生效。先在私有挂载命名空间中用 `sshd -T -C` 确认：三个块对各自的来源给出各自的标记值，第一种对假定的连接两个标记值都不给出。然后 `preflight` 退出码为 1：第一种的 `sshd.match` 不符合，并且只列出两个被包含的文件，`sshd.include` 通过；第二种的 `sshd.match` 不符合，列出主配置；
- VT-03：S1～S4 各自得到 `new-host.xui`、`new-host.ufw`、`new-host.fail2ban`、`new-host.container` 不符合，并提示"存量主机不在支持范围内"，`preflight` 前后摘要一致。S2 的覆盖层在启用 UFW 之前先检查两种情形（v0.6），`preflight` 和 `apply` 都被拒绝，前后摘要一致：私有挂载命名空间中 `before.rules` 加一条放行 8081/tcp 的 IPv4 规则，`new-host.ufw-framework` 不符合、`new-host.ufw` 通过；`ufw allow proto tcp to ::/0 port 8081` 添加一条只放行 IPv6 的规则后，`new-host.ufw` 不符合（"UFW 未启用，但已有 1 条规则"）、`new-host.ufw-framework` 通过；
- VT-04：第 2.4 节的各类非法输入退出码为 2，已删除的参数（`--maxretry`）按未知参数处理；root 同时有 Ed25519 和 RSA 公钥时两把都被识别；时限 3 和 60 被接受；标准输入不是终端时 `apply` 被拒绝；公开端口为 80/tcp 时 `preflight` 和经伪终端的 `apply` 退出码都为 2，80/udp 被接受（v0.6）。
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
| `firewall-reinstall` | 菜单：防火墙 → 停用防火墙，再安装防火墙 | `ufw.panel`、`ufw.port80`、`ufw.rules`、`ufw.userrules` |
| `iplimit` | 菜单：IP Limit → 安装 | `f2b.files`、`f2b.jails`、`f2b.mainconf` |
| `listen-all` | `x-ui setting -listenIP 0.0.0.0` 并重启 x-ui | `boundary.panel-listen` |
| `bbr` | 菜单：BBR → 启用 | `boundary.xui-bbr` |
| `ufw-rule` | `ufw allow 8080/tcp` | `ufw.rules`、`ufw.userrules` |
| `nftables` | `systemctl enable nftables.service` | `nft.service` |
| `sshd-dropin` | 在 SSH 片段末尾追加一行注释 | `ssh.dropin` |
| `sshd-match` | 新增片段 `99-match.conf`：`Match Address 198.51.100.0/24`，块内 `PasswordAuthentication yes`（v0.6） | `ssh.match`；`ssh.passwordauthentication` 仍通过，按假定的连接求值仍为 `no` |
| `ufw-framework` | 在 `before6.rules` 的 `COMMIT` 之前加一条放行 8081/tcp 的规则（v0.6） | `ufw.framework` |
| `ufw-userrules` | 在 `user.rules` 的 `COMMIT` 之前直接写入一条放行 8081/tcp 的规则，没有 tuple 注释（v0.6） | `ufw.userrules`；`ufw.rules` 仍通过 |
| `reboot-required` | 创建 `/var/run/reboot-required` | 退出码 0，只有警告 `reboot.required` |

  菜单经标准输入应答，使用安装时已校验的 `/usr/bin/x-ui`（等于 tag 中的 `x-ui.sh`，验证计划第 3.5 节）；菜单在输入意外时会递归调用自身，所以每次限时 300 秒。

M4 用例的判定要点（验证计划第 4.8、4.9 节）：

- VT-60：在 matrix 主流程的重启核对之后执行，全程持续探测。标准输入不是终端时退出码为 2；经伪终端回滚，输出"已恢复到应用前的配置"和保留的软件包，并有 `[WARN] rollback.password`（测试镜像应用前允许密码认证，第 7.2 节）；root 和默认用户都能用密钥登录。随后按 VT-20 的判据核对，原因为"手工回滚"：没有残留的自动恢复，`sshd -T`、UFW、受管文件、受管单元与基线一致，软件包保留，没有秘密泄露。`status` 显示"已回滚"和原因；再次回滚退出码为 1，输出"已经回滚"。
- `status`（VT-62 的 M4 部分）：待确认时退出码为 0，显示"待确认"和确认截止时间；确认后显示"已应用"、受管文件的前后摘要和隧道命令（`ssh -N -L`）。
- VT-61：回滚前记录 3X-UI 的文件摘要（`/usr/local/x-ui`、`/usr/bin/x-ui`、`/etc/x-ui`、`x-ui.service` 及其 drop-in 目录；排除数据库、指标文件和运行中生成的 Xray 配置 `bin/config.json`）和 `x-ui.service` 的启用、运行状态；回滚全程持续探测；回滚后按 VT-60 的判据核对，3X-UI 的文件和服务状态不变，面板只监听 `127.0.0.1:2053`。
- VT-63：变更前 UFW 正好放行 22、443、2096（各两个地址族），从第二来源 443、2096 可达，8443、9443、2053 不可达。8 种请求被拒绝或取消：标准输入不是终端、`--add 22/tcp`、`--add 2053/tcp`、`--add 80/tcp`（v0.6）、`--add 443/tcp/ipv4`、`--remove 8080/tcp` 的退出码为 2；在 `user6.rules` 的 `COMMIT` 之前直接写入一条规则后 `--add 8443/tcp`，退出码为 1，`ports.userrules` 不符合、`ports.rules` 通过，之后放回原文件（v0.6）；在提示处取消的为 1；前后的工具记录相同（第 7.2 节）。`--add 8443/tcp --remove 2096/tcp` 输出"端口变更已生效，等待确认"，待确认期间 root 能登录；从新会话确认后状态为"已应用"，声明为 `443/tcp/both 8443/tcp/both`，没有残留的自动恢复和端口变更的快照，UFW 规则与声明逐条一致，443、8443 可达，2096、2053、9443 不可达，`verify` 通过，前后摘要一致。再执行 `--add 9443/tcp --confirm-timeout 3` 而不确认：状态为"端口变更待确认"，标记的种类为 `ports`，9443 可达，`status` 显示变更前的公开端口，`verify` 退出码为 0（`state` 警告，`ufw.rules` 通过）；测试驱动最多等 900 秒，状态回到"已应用"，原因为"确认超时"，两个规则文件的摘要等于确认后的，9443 不可达，`verify` 通过。全程持续探测。
- VT-64：用与记录一致的参数（`--open 443/tcp --open 2096/tcp`；v0.8 起这两个端口在 hardened 套件中由 `ports` 新增）再次 `apply`，退出码为 0，输出"未做任何变更"，没有出现两项确认的提示；只换公开端口（`--open 443/tcp`），退出码为 1，`apply.inputs` 不符合；手工 `ufw allow 8080/tcp` 后再次 `apply`，退出码为 1，`ufw.rules` 和 `ufw.userrules` 不符合。每次前后的工具记录相同。第四种情况在 negative 套件中：VT-23 回退后解除屏蔽，`apply --open 443/tcp` 进入待确认，从新会话确认后状态为"已应用"，上次的回滚记录已删除，没有残留的自动恢复，`verify` 通过。
- VT-72（本地部分）：在从未运行过本工具的覆盖层上执行（状态目录和 `/usr/local/bin/vps-hardening` 都不存在）。未绑定的安装脚本退出码为 1，相对路径为 2；正常安装为 0，入口和模块目录为 0755，12 个模块为 0644，属主 root，没有残留的临时文件，与发行版目录逐个相同，版本正确，已安装的工具与仓库副本的 `preflight` 输出和退出码相同；重复安装输出"未做变更"；被篡改的资产、被篡改的清单（重新生成而没有更新内置摘要）、缺少的资产、存在待确认标记、操作锁被占用，都以退出码 1 拒绝，已安装的文件不变；本地改动一个已安装的模块后再次安装，恢复为发行版的内容。正常安装的结尾提示下一步执行 `preflight`；最后一种情况执行前写入只含 `status=applied` 的状态文件，结尾提示改为 `verify`，之后删除状态目录（v0.6）。v0.7 增加 8 种情况（需求 D40），都以安装后的记录（权限、属主、摘要和残留的临时文件）判定。重复安装之后，依次把 `common.sh` 改为 0600、模块目录改为 0700、入口的属主改为 65534:65534，每次安装都输出"安装完成"，记录与正常安装后相同。故障用测试替身 `/usr/local/sbin/mv` 注入：安装脚本的 PATH 以 `/usr/local/sbin` 开头；环境变量 `VH_TEST_FAULT` 为 `lib-fail`、`lib-term`、`bin-fail`、`bin-term` 时，替身让暂存目录或临时入口的改名失败，或在改名后向安装脚本发 SIGTERM，其余调用都交给 `/bin/mv`。在新机上用 `bin-fail` 安装：退出码为 1，输出"已恢复为安装前的状态"，入口、模块目录和临时文件都不存在。替换之前先在已安装的 `status.sh` 末尾加一行，记下记录，四种故障各安装一次：退出码都为 1，输出同上，记录都与故障前相同。

### 7.4 状态摘要

每个用例前后各采集一次，逐行比较：

- `/etc` 下每个对象的类型、权限、属主和链接目标，以及每个普通文件的 SHA-256；
- root 和 `/home` 下各账户 `.ssh` 中的文件摘要；
- `nft -s list ruleset`，以及去掉注释和计数器的 `iptables-save`、`ip6tables-save`；
- `ufw status verbose`；
- 全部单元文件的启用状态（不含会话 scope），以及相关服务和定时器的启用、运行状态；
- 软件包列表；工具状态目录是否存在；
- 安装了 3X-UI 时，`/usr/local/x-ui` 下各文件和 `/usr/bin/x-ui` 的 SHA-256（M3 新增）。

排除项只有三类，都由其他进程在测试期间改变：

- 规则计数器：随测试自身的 SSH 流量变化；
- 3X-UI 数据库 `/etc/x-ui/x-ui.db` 及其 `-wal`、`-shm` 文件的内容（权限和属主仍比较）：运行中的面板会自行写入。首轮 CI 中，Debian 12 和 Debian 13 的 S1 都在 preflight 前后观察到这两个文件的变化，而 preflight 对 3X-UI 只做 `systemctl cat` 和文件存在判断。
- v3.10.2 的指标文件 `/etc/x-ui/system_metrics.gob` 的内容（权限和属主仍比较）：面板每 60 秒重写一次。M4 首轮 CI 中，Debian 12 的 VT-63 因它在两次 `verify` 之间变化而失败（第 8.10 节）。

VT-61 比较 3X-UI 的文件时同样排除数据库和指标文件，另排除面板运行中生成的 Xray 配置 `/usr/local/x-ui/bin/config.json`。

### 7.5 验证计划第 3.3 节推断的核实方法

| 推断 | 核实方法 |
|---|---|
| 经端口转发的连接在客体中显示为 QEMU 网关地址，不是回环地址 | 每组平台都在客体中读取 `SSH_CONNECTION` 的来源地址 |
| 因此这些连接受 UFW 约束 | S2 中，在启用 UFW 前后分别访问客体的 8080（放行）和 2096（未放行）端口上的 HTTP 服务 |
| 连续探测的方式和间隔（VO-2） | 每组平台都做三组探测并记录 sshd 日志：30 次间隔 0.1 秒、不认证就断开的连接；20 次间隔 2 秒的同类连接；10 次间隔 0.5 秒的密钥登录。每组之后检查密钥登录是否立即可用，不可用时记录恢复时间 |

## 8. 运行证据

来源：GitHub Actions 运行 `39389558685`（v0.2 的代码，commit `e3de443`，2026-10-20），9 个作业全部通过；只改动文档的复核运行 `39391825013`（commit `4925946`）同样全部通过，VT-01～VT-04、VT-50 的结果一致。v0.1 的代码对应运行 `38438964687`（commit `63dda79`，2026-10-13）和代码未变的复核运行 `38503522626`（commit `7ef6e0f`），同样全部通过。证据构件 `vm-matrix-*`、`vm-negative-*` 保留 14 天。按验证计划第 6 节逐项核对了构件，不以 CI 状态为准。证据层次为"虚拟机生命周期"，不代表真实主机。除注明的以外，第 8.1 节的结果来自运行 `39389558685`。

第 8.1～8.3 节是 M1 的证据，第 8.4～8.6 节是 M2 的证据，第 8.7～8.9 节是 M3 的证据，第 8.10～8.12 节是 M4 的证据，第 8.13 节是修复（v0.6）的证据，第 8.14 节是预发行版和 VT-72 公开部分的证据，第 8.15 节是发布后修复（v0.7）的证据，第 8.16 节是预发行版 `v0.1.0-rc.2` 和 VT-72 公开部分的证据。按需求 D26，arm64 只作参考：第 8.1、8.2 节按当时的需求记录了 M1 的 arm64 结果，保持原样；M2 起 arm64 的结果放在附录 A。

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

第一轮运行和代码评审发现并已修复的问题：

| 问题 | 影响 | 修复 |
|---|---|---|
| `f2b.mainconf` 用 `dpkg --verify fail2ban \| grep -q` 判定。dpkg 逐行输出，两个文件都被改动时，`grep -q` 读到第一行就退出，dpkg 写第二行时因 SIGPIPE 失败，`pipefail` 下整个条件为假，检查通过 | M1 起就存在，违反第 6 节"读取端不提前退出"的约束。VT-51 的 IP Limit 漂移同时改动这两个文件（状态摘要显示两者的摘要都变了），三个平台上 `f2b.mainconf` 都误报通过；只改一个文件时不受影响，所以 M1、M2 的测试没有发现。测试 VPS 上复现：30 次中漏报 28 次（第 8.8 节） | 先把 `dpkg --verify` 的输出读完，再匹配（commit `b9e8b3d`）。其他用 `grep -q` 读管道的地方，写入端是 awk 或 `printf`，输出很短、一次写出，或者只输出一行（`find -quit`），不受影响 |
| `f2b.files`、`f2b.mainconf` 和预检的 `new-host.fail2ban` 只看 `dpkg --verify` 的输出，不看退出码。拉取请求 #9 的自动代码评审指出了 `f2b.files`，另两处原因相同 | `dpkg --verify` 无法校验时（退出码 1 或 2，第 4 节），输出为空或不完整，三项都判为通过，违反第 6 节"不确定时判为不符合"。CI 中没有触发，属于潜在的漏报 | 三处改用同一个函数 `fail2ban_changed_files`，它读完输出，`dpkg --verify` 失败时返回 1，三项随之判为不符合（commit `267fe1f`）。测试 VPS 上在私有挂载命名空间中验证：用退出码为 2 的 `dpkg` 替身时，`f2b.files`、`f2b.mainconf` 和 `new-host.fail2ban`（`/etc/fail2ban` 换成只有软件包文件的副本）都报告不符合；用真实的 dpkg 时结果不变，`verify` 37 项通过、`new-host.fail2ban` 通过；同时改动 `jail.conf` 和 `filter.d/sshd.conf` 时，前者由 `f2b.mainconf`、后者由 `f2b.files` 报告 |

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

### 8.10 M4 运行结果

来源：GitHub Actions 运行 `39585494737`（commit `8134443`，2026-10-21），12 个 amd64 作业全部通过；同一 commit 的静态检查运行 `39585494528` 通过。第一轮运行 `39582157065`（commit `d2692e0`）中 10 个作业通过，negative Debian 12 和 hardened Debian 12 失败，原因和修复见本节末尾。证据构件逐个用例核对，不以 CI 状态为准。证据层次为"虚拟机生命周期"，不代表真实主机。arm64 没有运行（第 9 节）。3X-UI 为 v3.10.2（需求 D32）。

| 套件 | 平台 | 作业时长 | 结果 |
|---|---|---|---|
| matrix | Debian 12 / 13、Ubuntu 24.04，amd64 | 4 分 4 秒～4 分 6 秒 | 通过 |
| recovery | 同上 | 5 分 26 秒～5 分 50 秒 | 通过 |
| negative | 同上 | 4 分 9 秒～4 分 38 秒 | 通过 |
| hardened | 同上 | 14 分 27 秒～16 分 12 秒 | 通过 |

三个平台的结果相同，不同之处注明：

- M1～M3 的用例：判定与第 8.5、8.7 节相同，全部满足。3X-UI 夹具的 `install.sh`、两个二进制文件、`/usr/local/x-ui/x-ui.sh` 和 `/usr/bin/x-ui` 的摘要都与 v3.10.2 一致（VO-1）；安装后 `verify` 为 38 项通过；VT-51 的 9 项漂移都与第 7.3 节的表一致，`firewall-install` 同样输出 `Firewall is already active`。
- VT-60：回滚前检查 4 项通过、1 项警告（`rollback.password`），回滚完成；按 VT-20 判据的核对全部满足；保留的软件包，Debian 为 `ufw fail2ban nftables python3-systemd`，Ubuntu 为 `fail2ban`；非终端时退出码为 2，再次回滚为 1。
- `status`：待确认、确认后、回滚后三次输出都满足第 7.3 节；确认后列出 8 个受管文件的前后摘要。
- VT-61：回滚前检查与 VT-60 相同；回滚后 3X-UI 的 19 个文件和 `x-ui.service` 的状态不变，面板只监听 `127.0.0.1:2053`。
- VT-63：6 种请求中 5 种退出码为 2、取消为 1，工具记录不变。确认后 `verify` 为 38 项通过；待确认期间为 37 项通过、1 项警告（`state`）；恢复原端口后为 38 项通过。不确认的变更，测试驱动从待确认阶段的核对结束起等待 173～174 秒，状态回到"已应用"；截止时间为变更后 3 分钟。持续探测 72～74 次，没有失败。
- VT-64：同参数再次 `apply` 为 39 项通过（`apply.inputs` 加 `verify` 的 38 项），退出码为 0；不同参数时只有 `apply.inputs` 不符合；手工放行 8080/tcp 后只有 `ufw.rules` 不符合；三次前后工具记录不变。negative 套件中，回退后再次应用并确认，`verify` 为 37 项通过。
- VT-72（本地部分）：10 种情况的退出码和输出都符合第 7.3 节，包括第一轮失败的 Debian 12。
- VT-25：所有流程中都没有在重启窗口外两次都失败的探测。第一次失败、1 秒后重试成功的探测：matrix 和 hardened 的主流程每个平台各 1 次，recovery 的重启流程每个平台 1～2 次，都在声明的重启窗口内；窗口外只有 1 次，在 Ubuntu 24.04 recovery 的超时流程中，探测开始后 195 秒（确认时限为 3 分钟），错误为等待版本信息超时，推断与第 9 节记录的 sshd 重新加载时新建连接失败相同。VT-23、VT-61、VT-63 的探测没有失败。
- 泄露扫描：12 个作业都没有发现测试密码、客户端私钥和面板的 WebBasePath。

第一轮运行和评审发现并已修复的问题：

| 问题 | 影响 | 修复 |
|---|---|---|
| 安装脚本的清单校验用 awk 的正则区间 `^[0-9a-f]{64}$`。Debian 12 的 mawk 为 1.3.4 20200120，正则区间在 20200717 版才加入、20200724 版起默认启用（mawk 的 CHANGES） | Debian 12 上 VT-72 的正常安装被拒绝，提示"SHA256SUMS 的内容与安装脚本的资产清单不一致"；Debian 13、Ubuntu 24.04 上同一检查通过 | 改为长度加字符类判断（commit `c4d3bfa`），第 6 节增加约束 |
| v3.10.2 的面板每 60 秒重写 `/etc/x-ui/system_metrics.gob`，状态摘要原来只排除数据库 | Debian 12 的 VT-63 在两次 `verify` 之间观察到这个文件变化，判为状态改变，作业在 VT-63 中途结束，VT-64 没有运行。Debian 13、Ubuntu 24.04 上没有触发（推断：两次采集之间没有发生重写） | 状态摘要和 VT-61 的文件比较都排除这个文件（commit `8ff62cf`，第 7.4 节） |
| 已应用的主机上再次 `apply` 有不符合项时，结尾总是提示"请先处理漂移" | 只有 `apply.inputs` 不符合（参数与记录不同，主机没有漂移）时，提示有误导 | 改为"请按上面的不符合项处理，或执行 vps-hardening rollback 后重新应用"（commit `8134443`） |
| VM 工作流的路径过滤不含 `install.sh` | 只改安装脚本时不运行 VT-72 | 两处路径过滤加入 `install.sh`（commit `d2692e0`） |

- 置信度：功能结论为高，三个平台在第二轮全部通过，第一轮中其余 10 个作业的结论相同。Debian 12 的 VT-63 后半部分和 VT-64 只有第二轮的证据。端口恢复的确切时刻没有归档（工具日志不在 VT-63 的证据中），只核对了测试驱动的等待时间。

### 8.11 测试 VPS 上的 M4 核对

来源：第 8.9 节的同一台测试 VPS，服务器时间 2026-10-21 10:08～10:12（UTC）。起始状态是第 8.9 节结束时的状态：本工具已应用并确认，vps-tuning 已应用，3X-UI v3.7.0 已安装。按用户的选择，先卸载 3.7.0，再安装 v3.10.2（需求 U20、D33）。软件版本：Debian 13.7，内核 `6.12.113+deb13-amd64`，fail2ban 1.1.0-8，openssh-server `1:10.0p1-7+deb13u4`，ufw 0.36.2-9，unattended-upgrades 2.12。这台主机不是新机，结果不能代替 M5 的验收。没有执行 `rollback` 和 `ports`，两者只有虚拟机中的证据（第 8.10 节，第 9 节）。

| 步骤 | 操作 | 结果 |
|---|---|---|
| 1 | 卸载前，用已安装的 M3 版执行 `verify` | 37 项通过 |
| 2 | `x-ui uninstall`，在提示处输入 `y` | 删除了 `/etc/x-ui`、`/usr/local/x-ui`、`/usr/bin/x-ui` 和 `x-ui.service`，输出 `Uninstalled Successfully`；退出码为 1，来自卸载脚本最后删除自身的一步。UFW 的 6 条规则不变 |
| 3 | 按验证计划第 3.5 节安装 v3.10.2：tag `608ef4e` 中的 `install.sh` 校验摘要后，带版本参数和四个环境变量运行；`x-ui setting -listenIP 127.0.0.1` 后重启 x-ui | 安装退出码为 0；两个二进制文件、`/usr/local/x-ui/x-ui.sh` 和 `/usr/bin/x-ui` 的摘要与 v3.10.2 一致（VO-1）；`x-ui -v` 为 3.10.2；面板只监听 `127.0.0.1:2053`，订阅端口 2096 监听所有地址（应用时已声明为公开端口）；`verify` 37 项通过 |
| 4 | 在主机上按 VT-72 的方式生成发行版目录和绑定的安装脚本副本，用本地模式安装 M4 开发版 | 仓库中未绑定的副本被拒绝；绑定的副本安装完成，入口和模块目录 0755、模块 0644、属主 root，与发行版目录逐个相同；重复安装输出"未做变更" |
| 5 | M4 版的 `status`、`verify` | `status` 读取第 8.6 节应用时写入的记录（M4 之前的版本），显示"已应用"、确认时间和公开端口；`verify` 37 项通过 |
| 6 | 用应用时的参数 `apply --open 443/tcp --open 2096/tcp` | 退出码为 0，输出"已应用，全部通过，未做任何变更"（38 项通过，含 `apply.inputs`）；没有出现确认提示，没有布置定时器 |
| 7 | `apply --open 443/tcp` | 退出码为 1，`apply.inputs` 不符合；记录和 UFW 规则不变 |
| 8 | 从本地电脑经 SSH 隧道访问 WebBasePath | HTTP 200 和登录页 |
| 9 | 重启后复核 | boot ID 改变；`verify` 37 项通过；面板只监听 `127.0.0.1:2053`；经隧道访问同样返回登录页；`x-ui.service` 的 drop-in 目录中有 v3.10.2 的 `10-xui-sandbox.conf` 和 vps-tuning 的 `90-proxy-vps.conf`，x-ui 的 `LimitNOFILE` 为 65536 |

- 安装脚本在第 4 步结束时提示"下一步：vps-hardening preflight"，在已应用的主机上不适用（第 9 节）。
- vps-tuning 的命令没有常驻安装（第 8.9 节是临时安装），这次没有重新执行它的严格验证。
- 结论：在这台主机上，v3.10.2 与加固后的配置共存，`verify` 的结果与 v3.7.0 时相同；M4 版能读取之前版本写入的记录，已应用主机上的再次 `apply` 不做变更。
- 置信度：中。一台主机、一个平台；3X-UI 是卸载后重装，不是在新机上首次安装（需求 D33）；没有配置入站，没有代理流量。

### 8.12 VT-80 便利性走查

依据：本工具的实际输出，以及第 8.5、8.7、8.9～8.11 节的运行结果。按需求 SC3、SC4 逐步对照加固前的做法（NFR-06）。M5 时在真实主机上复核（验证计划第 4.10 节）。

| 场景与步骤 | 加固后的实际情况 | 与加固前相比 |
|---|---|---|
| SC3：开隧道 | `apply`、`confirm` 和 `status` 都输出同一条隧道命令 `ssh -N -L 127.0.0.1:8443:127.0.0.1:<面板端口> -i <私钥> -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes root@<VPS 地址>`，只需替换私钥和地址两个占位符。root 的 `allowtcpforwarding` 为 `yes`；22 端口对所有来源开放，不需要维护来源地址清单 | 多出"先开隧道"：面板端口不开放（需求 D16） |
| SC3：打开面板 | 浏览器打开 `http://127.0.0.1:8443/` 加面板的访问路径。CI（VT-15、VT-55）和测试 VPS（第 8.9、8.11 节，从本地电脑）上都返回 HTTP 200 和登录页 | 访问路径和面板的登录方式由 3X-UI 决定，本工具不改变 |
| SC4：登录 | 以 root 用密钥登录 22 端口，不需要二次验证；`permitrootlogin` 为 `without-password`，`passwordauthentication` 为 `no` | 多出"不能用密码登录" |
| SC4：运行调优工具 | 第 8.9 节：加固确认后执行 vps-tuning 的预检、应用、重启和严格验证，都通过，加固的 `verify` 结果不变 | 无 |
| SC4：自动安全更新 | 两个 `APT::Periodic` 值为 1，不自动重启（第 8.11 节主机上 `apt-config dump` 的结果）；VT-40 的 dry-run 列出的来源等于需求 D19 的集合。需要重启时，`verify` 以 `reboot.required` 警告提示 | 重启仍由管理员决定 |

- 结论：满足 VT-80 的判据。以 root 用密钥登录的日常管理中，只多出"不能用密码登录、先开隧道再访问面板"。
- 另外两点不属于以 root 管理的日常操作，但会改变加固前的行为：镜像默认的免密 sudo 账户不能再经 SSH 登录（需求 D13）；管理员的出口在 10 分钟内累积 5 次认证失败会被封禁 1 天（需求 R-3）。只用密钥登录时，ssh-agent 中有多把密钥、`IdentitiesOnly` 和认证前断开都不计为失败（VT-34）。
- 置信度：中。走查基于 CI 虚拟机和一台测试 VPS 的输出；3X-UI 没有配置入站。

### 8.13 修复的运行结果

来源：GitHub Actions 运行 `39778449517`（拉取请求 #11 的合并提交 `2486e83`，它的树与 commit `5649b5d` 相同，2026-10-22），12 个 amd64 作业全部通过；同一 commit 的静态检查运行 `39778449550` 通过。证据构件逐个用例核对，不以 CI 状态为准。证据层次为"虚拟机生命周期"，不代表真实主机。arm64 没有运行（第 9 节）。

这是第二轮。第一轮运行 `39762487646`（合并提交 `24414a4`，树与 commit `bafa4b7` 相同）在增加 `ufw.userrules`、`ports.userrules`（需求 D37）之前，12 个作业同样全部通过；除下文注明的计数和用例外，两轮的结果相同。

这一轮 runner 上安装 QEMU 的时间在 18 秒～30 分 20 秒之间，作业时长因此不可比，下表列运行套件那一步的时长：

| 套件 | 平台 | 套件时长 | 结果 |
|---|---|---|---|
| matrix | Debian 12 / 13、Ubuntu 24.04，amd64 | 3 分 27 秒～4 分 06 秒 | 通过 |
| recovery | 同上 | 4 分 51 秒～5 分 26 秒 | 通过 |
| negative | 同上 | Debian 3 分 09 秒～5 分 22 秒，Ubuntu 24.04 22 分 21 秒（见本节末尾） | 通过 |
| hardened | 同上 | 14 分 29 秒～18 分 31 秒 | 通过 |

三个平台的结果相同，不同之处注明：

- VT-01：`sshd.match` 通过，三个镜像的 sshd 配置都没有 `Match` 块。Ubuntu 24.04 的镜像预装 UFW，`new-host.ufw`（已安装但未启用，没有已添加的规则）和 `new-host.ufw-framework` 都通过；Debian 12、13 的镜像没有 UFW，`new-host.ufw` 为"UFW 未安装"，框架文件一项不输出。应用后三个平台的 `ufw.framework` 都通过，即 `apply` 安装的（Debian）和预装的（Ubuntu）6 个框架文件都与模板相同（第 9 节）；`ufw.userrules` 也都通过。
- VT-02、VT-04：negative 基础阶段的调用由 28 个增加到 33 个，新增的 5 个都符合第 7.3 节：`--open 80/tcp` 的 `preflight` 和经伪终端的 `apply` 退出码都为 2，输出"公开端口不能是 80/tcp"；`--open 80/udp` 为 0；主配置末尾有 `Match` 块时，`preflight` 退出码为 1，唯一的不符合项是 `sshd.match`，`sshd.include` 通过；片段目录中有 `Match` 块时，`apply` 在预检阶段以退出码 1 被拒绝，不符合项同样只有 `sshd.match`。其余调用的结果与第 8.10 节相同，前后摘要一致。
- VT-03：S1～S4 的结果与第 8.10 节相同。S2 启用 UFW 之前的两种情形，`preflight` 和 `apply` 都以退出码 1 被拒绝，提示"存量主机不在支持范围内"，前后摘要一致：`before.rules` 中加规则时，唯一的不符合项是 `new-host.ufw-framework`，`new-host.ufw` 通过；添加只放行 IPv6 的规则后，唯一的不符合项是 `new-host.ufw`（"UFW 未启用，但已有 1 条规则"），`new-host.ufw-framework` 通过。
- `verify` 的通过项比第 8.10 节多 3 项（`ssh.match`、`ufw.framework`、`ufw.userrules`），比第一轮多 1 项：matrix 应用后和重启后为 40 项通过；安装 3X-UI 后为 41 项通过；VT-63 确认后和恢复原端口后为 41 项通过，待确认期间为 40 项通过、1 项警告（`state`）；VT-64 同参数再次 `apply` 为 42 项通过（`apply.inputs` 加 `verify` 的 41 项）；negative 中回退后再次应用并确认为 40 项通过。
- VT-51：12 项漂移的结果都与第 7.3 节的表一致。`ufw-userrules` 只有 `ufw.userrules` 不符合（"/etc/ufw/user.rules 与记录不一致"），`ufw.rules` 通过：`ufw status` 不显示这一行，去掉 `ufw.userrules` 就没有不符合项，即第一轮的 `verify` 会通过（依据不符合项集合推断）。`firewall-reinstall` 和 `ufw-rule` 另外报告 `ufw.userrules`：菜单和 `ufw allow` 都改写了 `user.rules`。`sshd-match` 只有 `ssh.match` 不符合，`ssh.passwordauthentication` 通过（按假定的连接求值仍为 `no`）。`ufw-framework` 只有 `ufw.framework` 不符合，`ufw.rules` 通过。`firewall-install` 同样输出 `Firewall is already active`。
- VT-63：8 种请求中 6 种退出码为 2（包括 `--add 80/tcp`）；`user6.rules` 被直接写入后的 `--add 8443/tcp` 退出码为 1，`ports.userrules` 不符合、`ports.rules` 通过；取消为 1。工具记录都不变。不确认的变更，测试驱动从待确认阶段的核对结束起等待 174～183 秒，状态回到"已应用"。
- VT-64：不同参数时只有 `apply.inputs` 不符合；手工放行 8080/tcp 后 `ufw.rules` 和 `ufw.userrules` 不符合，这时 `ufw.rules` 与声明比较（第 4 节）。
- VT-72（本地部分）：10 种情况的退出码与第 8.10 节相同。正常安装的结尾提示"下一步：vps-hardening preflight"；状态文件为"已应用"时，替换安装的结尾提示"下一步：vps-hardening verify"。
- VT-25：没有在重启窗口外两次都失败的探测。窗口外第一次失败、1 秒后重试成功的有 2 次，错误都是等待版本信息超时，第一次尝试的 5 秒都覆盖恢复重新加载 sshd 的时刻，与第 9 节记录的情况相同：
  - Debian 13 的 VT-23，尝试从 12:38:42 开始，应用失败后的恢复在 12:38:44 重新加载 sshd；
  - Ubuntu 24.04 的 VT-20（确认超时），尝试从 12:36:48 开始，恢复在 12:36:49 重新加载 sshd。
  第一轮 Debian 12 的 VT-63 在恢复端口时那 1 次重试，这一轮没有再出现，三个平台的 VT-63 都没有重试。
- 泄露扫描：12 个作业都没有发现测试密码、客户端私钥和面板的 WebBasePath（测试驱动在扫描通过后才写入 `COMPLETED`）。

两轮各有一个 Ubuntu 24.04 的套件慢了很多，时间都花在客体从 Ubuntu 软件源下载上：

- 第一轮是 hardened 套件（31 分 31 秒，第 8.10 节约 16 分钟）。VT-40（`unattended-upgrade --dry-run`）用了 824 秒，第 8.10 节为 42 秒；准备阶段下载 24.8 MB 用了 1 分 25 秒，第 8.10 节为 4 秒。VT-40 的 dry-run 限时 15 分钟，只剩约 76 秒。
- 这一轮是 negative 套件（22 分 21 秒，第一轮为 4 分 15 秒）。准备阶段下载 24.8 MB 用了 5 分 21 秒（77.4 kB/s）；S4 安装容器软件包，下载 73.3 MB 用了 11 分 38 秒，第一轮的 S4 阶段为 14 秒。作业加上 9 分 48 秒的 QEMU 安装共 32 分 17 秒，作业限时 45 分钟。

推断原因是 Ubuntu 软件源的下载速度在不同运行之间变化，与修复无关（置信度中）。今后如果因此超时，先重跑确认是环境原因。

- 置信度：功能结论为高：三个平台一次运行全部通过，新增用例的结果与第 7.3 节的判据逐项一致。

### 8.14 预发行版和 VT-72 的公开部分

来源：2026-10-22 的发布，以及在本地电脑和测试 VPS 上从公开地址的回验。公开下载的比较是对真实发布文件的逐字节核对；从公开地址安装只在一台测试 VPS 上做过，这台主机不是新机，结果不能代替 M5 的验收。

- **发布。** 拉取请求 #12 只改版本号（入口的 `VH_VERSION`，安装脚本的 `INSTALLER_VERSION`、`RELEASE_TAG`）。它的 VM 运行 `39787829609` 的 12 个作业全部通过，测试的合并提交 `6829f8b` 是 `d34e5ce` 合并到它的父提交，树与之后 `master` 上的合并提交 `d33e938` 相同；静态检查运行 `39787829699` 通过。在 `d33e938` 上打附注标签 `v0.1.0-rc.1`，按第 2.12 节的发布步骤生成资产，以 Pre-release 发布，共 15 项。`SHA256SUMS` 的 SHA-256 为 `0ce61014c9117c94e530fa0618e61edb8ae99b54341d63f829ea70256c04d310`，绑定后的 `install.sh` 为 `b6771abb497e7a24aae71e2d65ee8275796d194f60513e30ec1fc89581a61d45`。
- **构建的一致性。** 对同一棵树，本地构建的 `SHA256SUMS` 与 CI 中 VT-72 本地部分在三个平台的客体里生成的逐行相同：`5649b5d`（运行 `39778449517`）和 `d34e5ce`（运行 `39787829609`）各比较一次。运行 `39787829609` 中 VT-72 本地部分的 10 种情况，退出码与第 8.10 节相同，安装后的版本为 `0.1.0-rc.1`。
- **公开下载（本地电脑）。** 不带认证，从 `https://github.com/alieismy/vps-hardening/releases/download/v0.1.0-rc.1/` 下载 15 项，与构建逐字节相同；13 个资产通过 `SHA256SUMS` 的校验；`install.sh` 中绑定的摘要等于下载的 `SHA256SUMS` 的 SHA-256。GitHub 为每个资产记录的 SHA-256 与此一致。
- **从公开地址安装（测试 VPS）。** 第 8.11 节的同一台主机，Debian 13.7、curl 8.14.1，服务器时间 2026-10-22 14:33～14:34（UTC）。起始状态：本工具的 M4 开发版已应用，3X-UI v3.10.2 在运行。没有执行 `preflight`、`apply`、`ports` 和 `rollback`。

| 步骤 | 操作 | 结果 |
|---|---|---|
| 1 | 从公开地址下载 `install.sh`，按发布说明核对 SHA-256 | 一致 |
| 2 | `bash install.sh` | 退出码为 0；从公开地址下载 `SHA256SUMS` 和 13 个资产，输出"安装完成……版本 0.1.0-rc.1"；结尾提示执行 `verify` 和 `status`（已应用的主机，第 2.12 节） |
| 3 | 核对已安装的文件 | 与公开的 `SHA256SUMS` 逐个相同；入口和模块目录 0755、12 个模块 0644，属主 root，模块目录中正好 12 项；没有残留的临时文件；状态目录中每个文件的摘要与安装前相同 |
| 4 | 再次 `bash install.sh` | 退出码为 0，输出"文件与发行版一致，未做变更" |
| 5 | `vps-hardening verify`（0.1.0-rc.1，只读） | 退出码为 0，40 项通过，没有不符合、警告和跳过，状态目录不变。比第 8.13 节安装 3X-UI 后的 41 项少 `ssh.denied`：这台主机没有被禁账户，这一项不输出（第 4 节）。记录中的 `user.rules`、`user6.rules` 摘要与现在的文件相同，`ufw.userrules` 通过 |

- 结论：公开地址上的资产与标签所在的提交一致；绑定的安装脚本能从公开地址完成安装，重复安装不做变更，在已应用的主机上给出正确的提示，不改变已应用的配置。
- 置信度：公开下载的一致性为高（逐字节比较）。从公开地址安装为中：只在一台已应用的 Debian 13 主机上做过（第 9 节）。

### 8.15 发布后修复的运行结果

来源：GitHub Actions 运行 `39811184450`，以及 2026-10-22 在测试 VPS 上的核对。CI 部分的证据层次为"虚拟机生命周期"，不代表真实主机，arm64 没有运行（第 9 节）。测试 VPS 上的核对没有改动主机上在用的配置和已安装的文件：sshd 只读取 `/root/rc2-probe` 中的临时配置（`sshd -t -f`、`sshd -T -f`）；`preflight` 在私有挂载命名空间中覆盖主配置运行；安装脚本在私有挂载命名空间中运行，`/usr/local` 上挂了 tmpfs，前后比较主机上已安装文件的摘要，两者相同。

**CI 运行。** 运行 `39811184450`（拉取请求 #14 的合并提交 `8b463a3`，它的树与 commit `c6a1d30` 相同，2026-10-22），12 个 amd64 作业全部通过；同一 commit 的静态检查运行 `39811184687` 通过。证据构件逐个用例核对，不以 CI 状态为准。matrix 的 Debian 12 作业第一次尝试停在 runner 安装 QEMU 的那一步，45 分 14 秒后因作业限时被取消，这时仓库的代码还没有运行；重跑后通过，下文用的是重跑的结果。

之前的运行 `39809498894`（commit `604b373`）中，negative 的 Ubuntu 24.04 作业在 VT-02 新增的前置断言处失败。这个断言原来用 `passwordauthentication yes` 判断 sshd 是否应用了被包含的块，而 CI 镜像在加固之前已经全局允许密码（第 7.2 节），假定的连接也得到 `yes`，断言不能区分两者。这是测试的缺陷：commit `c6a1d30` 改为每个块各设一个 `MaxAuthTries` 标记（第 7.3 节），被测代码没有改动；那次运行随后手动取消。

| 套件 | 平台 | 套件时长 | 结果 |
|---|---|---|---|
| matrix | Debian 12 / 13、Ubuntu 24.04，amd64 | 3 分 27 秒～3 分 45 秒 | 通过 |
| recovery | 同上 | 4 分 47 秒～5 分 25 秒 | 通过 |
| negative | 同上 | Debian 3 分 48 秒～3 分 57 秒，Ubuntu 24.04 12 分 00 秒（S4 从 Ubuntu 软件源下载 73.3 MB 用了 7 分 34 秒，161 kB/s，与第 8.13 节记录的情况相同） | 通过 |
| hardened | 同上 | 15 分 44 秒～16 分 51 秒 | 通过 |

三个平台的结果相同：

- VT-02：negative 基础阶段的调用由 33 个增加到 35 个，新增的 2 个都符合第 7.3 节。前置断言中，sshd 对三个块的来源求得的 `MaxAuthTries` 依次为 2、3、4，假定的连接为 6（默认值），即三个镜像的 sshd 都读取了带双引号和转义空格的 `Include` 路径、带引号的关键字。主配置包含这两个文件时，`preflight` 退出码为 1，唯一的不符合项是 `sshd.match`，列出 `/root/vh-private/match dir/10-quoted.conf` 和 `/root/vh-private/match dir/20-escaped.conf`；主配置中有以 `"Match"` 开头的块时，退出码为 1，唯一的不符合项是 `sshd.match`，列出 `/etc/ssh/sshd_config`。两次 `sshd.include` 都通过，主配置中片段目录的 `Include` 带双引号。
- VT-72（本地部分）：情况由 10 种增加到 18 种，原有 10 种的退出码与第 8.13 节相同。新机上入口改名失败时退出码为 1，最后一行为"安装未完成，已恢复为安装前的状态"，入口和模块目录都不存在，没有残留的临时文件。模块改为 0600、模块目录改为 0700、入口的属主改为 nobody 之后，再次安装的退出码都为 0，输出"安装完成"，安装记录（权限、属主、摘要）与正常安装后的相同。本地改动一个模块之后，4 种替换中的故障退出码都为 1，最后一行同上，记录与故障前相同；故障前的记录与正常安装后的只差这个模块的摘要。去掉测试替身后替换，记录与正常安装后相同。记录中没有 `.vps-hardening.` 开头的临时文件。
- 各作业日志中的汇总行（"N 项通过，……"）的种类和次数与第 8.13 节的运行 `39778449517` 逐作业相同；应用后 `ssh.match` 都通过。
- 泄露扫描：12 个作业都通过。扫描不通过时测试驱动以非零状态退出，作业失败；`COMPLETED` 在扫描之后写入，三个 negative 构件中都有。

**sshd 的读法（测试 VPS：Debian 13，openssh-server 1:10.0p1-7+deb13u4，`sshd -V` 为 OpenSSH_10.0p2，awk 为 mawk 1.3.4 20250131）。** 每个被包含的文件中是一个 `Match Address` 块，块内 `PasswordAuthentication yes`，各用一个不同的来源。

| 临时配置 | sshd 的结果 | v0.6 的函数 | v0.7 的函数 |
|---|---|---|---|
| 主配置依次包含：双引号括起、含空格的路径；用反斜杠转义空格的路径；单引号括起、含空格的通配路径，后面跟 `#` 和另一个路径；`Include = "…"`，路径含空格 | `sshd -t` 通过。`sshd -T -dd` 显示包含了四个文件，没有包含 `#` 之后的路径；四个块的来源得到 `passwordauthentication yes`，假定的连接和 `#` 之后那个文件中的来源为 `no` | 只列出主配置和 `#` 之后的那个文件：四个文件漏查，`sshd.match` 只报告后者，是误报 | 列出的文件与 sshd 包含的相同，`sshd.match` 报告这四个文件 |
| 主配置中有分别以 `"Match"` 和 `Ma"tch"` 开头的块 | 两个块的来源得到 `yes` | `sshd.match` 通过（漏查） | `sshd.match` 不符合 |
| 片段目录的 `Include` 带双引号 | `sshd -t` 通过 | `sshd.include` 不符合（误拒） | `sshd.include` 通过 |

VT-02 的新步骤（第 7.3 节）也在这台主机上用 `m1.sh` 中的函数运行过：三个块的 `MaxAuthTries` 标记依次为 2、3、4，假定的连接为 6；两次 `preflight` 的 `sshd.match` 都不符合，列出的文件与 VT-02 的判据相同，`sshd.include` 通过。`sshd.dropin-order` 不符合，因为这台主机已经应用，本工具的片段已存在，与本项无关。

**安装脚本（测试 VPS）。** 按 VT-72 本地部分的方式，从工作树生成发行版目录，把安装脚本的副本绑定到它。入口的版本仍为 0.1.0-rc.1，所以 `master` 上 v0.6 的安装脚本也能绑定同一个目录，作为对照。依次执行下表的情况，记录包括权限、属主、摘要和残留的临时文件；故障用 VT-72 的测试替身注入（第 7.3 节）。

| 情况 | v0.6 | v0.7 |
|---|---|---|
| 新机，入口改名失败 | 退出码 1，没有提示；留下没有入口的模块目录 | 退出码 1，提示"已恢复为安装前的状态"；不留下任何文件 |
| 正常安装，重复安装 | 安装完成；"未做变更" | 同左 |
| 依次把一个模块改为 0600、模块目录改为 0700、入口的属主改为 nobody，每次之后再安装 | 三次都输出"未做变更"，权限和属主保持被改后的样子 | 三次都重新安装，记录与正常安装后相同 |
| 本地改动一个已安装的模块后，新模块目录改名就位之后 SIGTERM | 退出码 1，没有提示；新模块已就位，原来的模块没有放回，旧目录残留为 `/usr/local/lib/.vps-hardening.old.<PID>` | 退出码 1，提示同上；记录与故障前相同 |
| 新模块目录改名失败；新入口改名失败；新入口改名就位之后 SIGTERM | 不能对照：上一种情况已留下与发行版相同的模块，这三种都输出"未做变更" | 退出码都为 1，提示同上；记录都与故障前相同 |
| 去掉测试替身后替换 | — | 安装完成，记录与正常安装后相同 |

第 9 节原来对第三个问题的描述是依据代码推断的，上表第一行和第四行的 v0.6 一列复现了它。

- 结论：四个问题已在 v0.7 中修复。检查 sshd 配置时，读取的文件和关键字与 sshd 一致，带引号的关键字和 `Include` 路径不再漏查，带引号的片段目录 `Include` 不再误拒；安装脚本只在属主、权限和摘要都相同时才"未做变更"；替换中途失败或被中断时，恢复为安装前的文件。
- 置信度：功能结论为高：CI 三个平台一次运行全部通过，新增用例的结果逐项符合第 7.3 节；测试 VPS 上用 v0.6 复现了问题，用 v0.7 确认了修复。与 sshd 读法的一致性只对三个 CI 镜像和测试 VPS 上的版本核对过源码和运行结果：Debian 12 的 openssh-server 1:9.2p1，Ubuntu 24.04 的 1:9.6p1，Debian 13 的 1:10.0p1（`sshd -V` 为 OpenSSH_10.0p2，源码按 V_10_0_P2 核对）。替换过程中的 SIGKILL 和断电不在测试范围（第 9 节）。

### 8.16 预发行版 v0.1.0-rc.2 和 VT-72 的公开部分

来源：2026-10-22 的发布，以及在本地电脑和测试 VPS 上从公开地址的回验。公开下载的比较是对真实发布文件的逐字节核对；从公开地址升级只在一台测试 VPS 上做过，这台主机不是新机，结果不能代替 M5 的验收。

- **发布。** 拉取请求 #15 只改版本号（入口的 `VH_VERSION`，安装脚本的 `INSTALLER_VERSION`、`RELEASE_TAG`）。它的 VM 运行 `39821720951` 的 12 个作业全部通过。运行记录的头提交是拉取请求的 `1da02c3`，作业检出的是 `refs/remotes/pull/15/merge`，即合并提交 `e3b13da`（`1da02c3` 合并到 `fb571e3`），它的树与之后 `master` 上的合并提交 `7dc83b1` 相同；静态检查运行 `39821720939` 通过。Debian 12 的 negative 作业第一次在 runner 下载云镜像时失败（约 270 秒后 `Network is unreachable`），客体还没有启动，重跑后通过。在 `7dc83b1` 上打附注标签 `v0.1.0-rc.2`，按第 2.12 节的发布步骤生成资产，以 Pre-release 发布，不设为 Latest，共 15 项。`SHA256SUMS` 的 SHA-256 为 `7e0b68b7a5502c6cb47463222637d53c65a860056aa3d4d89162c321beb867d4`，绑定后的 `install.sh` 为 `9c18d7c0fcb1b5532b659d05e1cdb6831acdb46484224fe94cb1670398aaf69b`，与仓库中的 `install.sh` 只差 `EXPECTED_MANIFEST_SHA256` 一行。
- **#14 合并后 `master` 上的运行。** VM 运行 `39821480293`（`fb571e3`）第一次有两个作业失败，重跑后 12 个作业全部通过：
  - Debian 13 的 negative 作业同样在下载云镜像时网络不可达，客体还没有启动。
  - Debian 12 的 negative 作业中，VT-23 的登录探测有一次和 1 秒后的重试都失败，第一次的错误是等待版本信息超时，VT-25 因此不成立。按 runner 日志和工具日志的时间推算：第一次尝试约从 17:22:43 开始，5 秒的超时覆盖应用失败后恢复重新加载 sshd 的时刻（工具日志为 17:22:44）；重试约在 17:22:49，落在紧接着的 VT-64 再次 `apply`（runner 日志中 17:22:48～17:22:55）之内，这次 `apply` 在第 3 步又重新加载 sshd。这次重新加载的确切时刻没有记录，所以重试失败的原因是推断（置信度中）。其余 5 次探测都成功，测试驱动在 17:22:46 的 root 和 debian 登录也成功。同一份代码在运行 `39811184450`（第 8.15 节）和 `39821720951` 中都没有出现这种情况（第 9 节）。
- **构建的一致性。** 本地构建的 `SHA256SUMS` 与运行 `39821720951` 中 VT-72 本地部分在三个平台的客体里生成的逐行相同。VT-72 本地部分 18 种情况的退出码和安装记录都与第 8.15 节相同，安装后的版本为 `0.1.0-rc.2`。
- **公开下载（本地电脑）。** 不带认证，从 `https://github.com/alieismy/vps-hardening/releases/download/v0.1.0-rc.2/` 下载 15 项，与构建逐字节相同（一项第一次下载时 TLS 握手失败，重试后成功）；13 个资产通过 `SHA256SUMS` 的校验；`install.sh` 中绑定的摘要等于下载的 `SHA256SUMS` 的 SHA-256。GitHub 为每个资产记录的 SHA-256 与此一致。
- **从公开地址升级（测试 VPS）。** 第 8.11、8.14 节的同一台主机，Debian 13.7、curl 8.14.1，服务器时间 2026-10-23 02:15（UTC）。起始状态与第 8.14 节结束时相同：安装的是 `v0.1.0-rc.1`，状态为已应用，3X-UI 在运行；此后只做过第 8.15 节的核对，没有改动主机上在用的配置和已安装的文件。没有执行 `preflight`、`apply`、`ports` 和 `rollback`。

| 步骤 | 操作 | 结果 |
|---|---|---|
| 1 | 从公开地址下载 `install.sh`，按发布说明核对 SHA-256 | 一致 |
| 2 | `bash install.sh` | 退出码为 0；从公开地址下载 `SHA256SUMS` 和 13 个资产，输出"安装完成……版本 0.1.0-rc.2"；结尾提示执行 `verify` 和 `status`（已应用的主机，第 2.12 节） |
| 3 | 核对已安装的文件 | 入口和 12 个模块与公开的 `SHA256SUMS` 逐个相同，模块目录中正好 12 项；入口和模块目录 0755、模块 0644，属主 root；没有残留的临时文件；状态目录中 9 个文件的摘要与安装前相同 |
| 4 | 再次 `bash install.sh` | 退出码为 0，输出"已安装 vps-hardening 0.1.0-rc.2，文件与发行版一致，未做变更" |
| 5 | `vps-hardening verify`（0.1.0-rc.2，只读） | 退出码为 0，40 项通过，没有不符合、警告和跳过，与第 8.14 节相同；状态目录不变 |

- 结论：公开地址上的资产与标签所在的提交一致；绑定的安装脚本能从公开地址把 `v0.1.0-rc.1` 换成 `v0.1.0-rc.2`，不改变已应用的配置和状态记录，重复安装不做变更。
- 置信度：公开下载的一致性为高（逐字节比较）。从公开地址升级为中：只在一台已应用的 Debian 13 主机上做过（第 9 节）。

### 8.17 推荐流程和预检待重启警告的运行结果

来源：GitHub Actions 运行 `40089460136`（2026-10-24）。运行记录的头提交是拉取请求 #17 的 `89559ff`，作业检出的是 `refs/remotes/pull/17/merge`，即合并提交 `65a0e9f`（`89559ff` 合并到 `c79f4d8`）。12 个 amd64 作业第一次尝试全部通过；同一 commit 的静态检查运行 `40089460199` 通过。这个拉取请求之后的提交只改文档。证据层次为"虚拟机生命周期"，arm64 没有运行（第 9 节）。matrix 和 hardened 的证据构件逐个用例核对；recovery 和 negative 的用例没有改动，只以作业结果为准，没有下载构件核对。

| 套件 | 平台 | 作业时长 | 结果 |
|---|---|---|---|
| matrix | Debian 12 / 13、Ubuntu 24.04，amd64 | 4 分 08 秒～4 分 22 秒 | 通过 |
| recovery | 同上 | 5 分 19 秒～5 分 28 秒 | 通过 |
| negative | 同上 | 4 分 19 秒～4 分 46 秒 | 通过 |
| hardened | 同上 | 15 分 37 秒～16 分 24 秒 | 通过 |

三个平台的结果相同：

- VT-01：放置待重启标记、不带 `--open` 的 `preflight` 退出码为 0，`reboot.required` 为警告，`inputs.open` 通过（"没有声明公开端口：UFW 只放行 22/tcp……"），前后状态摘要一致。原有的那次 `preflight` 中 `reboot.required` 通过。
- hardened 套件的 `apply` 不带 `--open`：预检全部通过，没有警告（Debian 18 项，Ubuntu 24.04 19 项）；变更计划为"放行 22/tcp；面板端口 2053 不放行"。确认后记录中没有公开端口，UFW 只有 22/tcp 的两条规则。
- 安装 3X-UI 后执行 `ports --add 443/tcp --add 2096/tcp`：变更前检查 5 项通过，输出"端口变更已生效，等待确认"。从新会话确认后，状态为"已应用"，声明为 `443/tcp/both 2096/tcp/both`，没有残留的自动恢复，UFW 规则与 22/tcp、443/tcp、2096/tcp 逐条一致；`verify` 41 项全部通过，前后摘要一致。之后经隧道打开面板、重启后核对，都通过。
- 以这块磁盘为底的覆盖层全部通过：VT-51 的 12 项漂移，以及 VT-61、VT-63、VT-64。VT-64 用 `--open 443/tcp --open 2096/tcp` 再次 `apply`，输出"已应用，全部通过，未做任何变更"。
- VT-25：hardened 主流程的探测为 101～107 次，没有在重启窗口外两次都失败的；第一次失败、1 秒后重试成功的有 1～2 次。

- 结论：推荐流程（需求 D41）在三个平台上可用。加固时只放行 22/tcp，安装 3X-UI 后用 `ports` 开放它的端口并确认，之后的状态、规则和 `verify` 与加固时就声明这两个端口相同。预检发现待重启时只警告（需求 D43）。
- 置信度：高。CI 三个平台一次运行全部通过，新步骤的结果逐项符合第 7.3 节。结论只到虚拟机层次：测试 VPS 和真实主机上没有按这个流程运行过。

### 8.18 预发行版 v0.1.0-rc.3 和 VT-72 的公开部分

来源：2026-10-24 的发布，以及在本地电脑上从公开地址的回验。从公开地址安装见第 8.19 节。

- **发布。** 拉取请求 #18 有三个提交：
  - `53b47c5` 记录评审通过（需求 U28、D44），并起草了 D45；
  - `7c6c174` 只改版本号（入口的 `VH_VERSION`，安装脚本的 `INSTALLER_VERSION`、`RELEASE_TAG`）；
  - `fb66011` 按用户的撤回（需求 U30）删去 D45，需求保持 v1.9。

  VM 运行 `40112254004` 的 12 个作业第一次尝试全部通过。运行记录的头提交是 `fb66011`，作业检出的是 `refs/remotes/pull/18/merge`，即合并提交 `d331dab`（`fb66011` 合并到 `71096d2`）。它的树（`3fbde94`）与之后 `master` 上的合并提交 `974d875` 相同。静态检查运行 `40112253972` 通过；`7c6c174` 的 VM 运行 `40112059173` 在这个提交被取代后取消。

  在 `974d875` 上打附注标签 `v0.1.0-rc.3`，按第 2.12 节的发布步骤生成资产，以 Pre-release 发布，不设为 Latest，共 15 项：
  - `SHA256SUMS` 的 SHA-256 为 `e0decc9f9adb1c14d34f8f84919cb2541318e6683415ca464d76a6a211da1a27`；
  - 绑定后的 `install.sh` 为 `2fc36c6f17a0103366df1916ee76951740fb343f7352df61c50796bb154516af`，与仓库中的 `install.sh` 只差 `EXPECTED_MANIFEST_SHA256` 一行。
- **CodeRabbit。** 它对 `7c6c174` 提了两条意见：
  - README 中 `apply` 一步的措辞：复核后它自己撤回；
  - 为 sshd 不在 22 端口的情形加虚拟机用例：针对的是 D45 中的一句话，D45 已撤回，没有采纳。

  `fb66011` 合并前没有经它复审（它的免费额度用完，要约 50 分钟后才恢复）。
- **构建的一致性。** 本地构建的 `SHA256SUMS` 与运行 `40112254004` 中 VT-72 本地部分在三个平台的客体里生成的逐行相同。VT-72 本地部分 20 种情况的退出码和安装记录都与第 8.15 节相同，安装后的版本为 `0.1.0-rc.3`。
- **公开下载（本地电脑）。** 不带认证，从 `https://github.com/alieismy/vps-hardening/releases/download/v0.1.0-rc.3/` 下载 15 项，与构建逐字节相同，没有重试：
  - 13 个资产通过 `SHA256SUMS` 的校验；
  - `install.sh` 中绑定的摘要等于下载的 `SHA256SUMS` 的 SHA-256；
  - GitHub 为每个资产记录的 SHA-256 与此一致。
- 结论：公开地址上的资产与标签所在的提交一致。
- 置信度：高。逐字节比较，构建与三个平台客体中生成的清单相同。

### 8.19 真实主机验收（M5）

来源：2026-10-24（UTC）在测试 VPS 上的验收（需求 D44），按验证计划第 5 节执行，有两处偏离：
- 准备步骤中的 apt 以非交互方式执行（步骤 1）；
- 端口仍从本地电脑探测，但本地的结果无效，可达性改以 VPS 上抓包看到的主机回应判定（见"端口探测的方法"）。

服务商名称和地址只记在私有记录中。

**主机。**
- 用户在服务商控制台把测试 VPS 重装为 Debian 13（需求 U29），绑定自己的公钥，又给 root 加了一把专用的测试公钥。主机密钥的指纹由用户在控制台核对。
- 用户确认服务商侧没有开启防火墙和安全组（R-8）。
- 重装后的主机：
  - KVM，x86_64，Debian 13.4，内核 6.12.74+deb13+1；
  - 没有全局 IPv6 地址；
  - cloud-init 的 `50-cloud-init.conf` 设置了 `PasswordAuthentication yes`，主配置为 `PermitRootLogin yes`；
  - 没有安装 UFW；
  - systemd-resolved 在所有地址上监听 5355（LLMNR）。

**操作方式。**
- 操作在本地电脑（Windows 11）上进行，SSH 都使用测试密钥。确认用 Windows 自带的 OpenSSH 9.5p2，每次在新开的 PowerShell 进程中建立新会话。
- 本地电脑的出口经过 mihomo 的 TUN 网卡。

**连续探测（VT-25 的判据）。** 从应用前到最后一次重启后，从本地电脑每 3 秒用 root 的密钥登录一次，失败后 1 秒重试。

| 步骤 | 操作 | 结果 |
|---|---|---|
| 1 | 按需求 D42 准备：`apt update`、`apt -s full-upgrade`、`apt full-upgrade -y`、`apt install -y` 需求 U27 的 15 个软件包、`apt autoremove`，然后重启。为避免 SSH 断开中断 apt，用 `systemd-run` 非交互执行（`DEBIAN_FRONTEND=noninteractive`，`--force-confdef --force-confold`），这一点与管理员交互执行不同 | 模拟升级列出 102 个安装项。升级 101 个、新装 1 个（内核 6.12.113+deb13），安装 23 个（15 个软件包及其依赖），清理 0 个；全部退出码为 0，用时约 2.5 分钟。之后出现 `/var/run/reboot-required`，`.pkgs` 中是新内核（需求 D43）；`/etc/kernel/postinst.d/` 中有 `unattended-upgrades`。重启后为 Debian 13.7、内核 6.12.113+deb13，标记消失，15 个软件包都已安装 |
| 2 | 从公开地址下载 `install.sh`，按发布说明核对 SHA-256，执行 `bash install.sh`；再执行一次 | 核对一致；退出码为 0，下载 `SHA256SUMS` 和 13 个资产，版本为 `0.1.0-rc.3`，已安装的文件与 `SHA256SUMS` 一致。第二次输出"文件与发行版一致，未做变更"。结尾提示的下一步是 `vps-hardening preflight --open <公开端口>`，与推荐流程不一致（第 9 节） |
| 3 | `vps-hardening preflight`（不声明公开端口） | 退出码为 0，20 项通过，没有警告；`inputs.open` 为"没有声明公开端口……"，`new-host.ufw` 为"UFW 已安装但未启用，没有已添加的规则"，`root.keys` 为 2 把；前后状态摘要一致 |
| 4 | `vps-hardening apply`，经伪终端回答 `yes` | 安装 fail2ban、nftables、python3-systemd；UFW 2 条规则；17:03:50 开始，17:04:04 进入待确认 |
| 5 | 新开 PowerShell 会话执行 `confirm` | 17:04:20 确认，"已确认，加固生效"；随后的 `verify` 39 项通过 |
| 6 | 从本地电脑探测 22、80、443、2053、2096，在 VPS 上抓包判定（见下文） | 22：回应 SYN-ACK；80、443、2053、2096：各收到 64 个 SYN，主机没有任何回应（归于 UFW 的依据见下文） |
| 7 | 重启，`verify` | 约 22 秒后恢复；ssh、ufw、fail2ban、unattended-upgrades 在运行；`verify` 39 项通过 |
| 8 | 按需求第 7.2 节的约定安装 3X-UI v3.10.2：安装脚本固定在 `608ef4e` 并核对摘要，非交互，`XUI_ENABLE_FAIL2BAN=false`，面板端口 2053；核对二进制文件的摘要；`x-ui setting -listenIP 127.0.0.1` | 4 个文件的摘要一致，版本 3.10.2，x-ui 已启用并在运行；面板监听 `127.0.0.1:2053`，订阅监听所有地址的 2096。`verify` 40 项通过，`boundary.panel-listen` 通过 |
| 9 | `vps-hardening ports --add 443/tcp --add 2096/tcp`，新开 PowerShell 会话执行 `confirm` | 变更前检查 5 项通过；17:08:38 开始，17:08:52 确认；`verify` 40 项通过，规则 6 条，与声明一致 |
| 10 | 再次探测这 5 个端口，抓包判定 | 22：SYN-ACK；443：回应 RST，即放行但没有服务监听（3X-UI 没有配置入站）；2096：SYN-ACK（订阅）；80、2053：各 46 个 SYN 没有回应。第一次执行时漏了端口列表，没有发出探测，重做 |
| 11 | 用 `status` 输出的隧道命令（`ssh -N -L 127.0.0.1:8443:127.0.0.1:2053 …`）访问面板的 WebBasePath | 不建隧道时本地端口没有应答；建隧道后返回 HTTP 200，标题为"Sign in" |
| 12 | 重启，`verify`，再经隧道访问面板 | 约 24 秒后恢复；x-ui 在运行，面板仍只监听回环地址；`verify` 40 项通过；sshd jail 的失败和封禁都为 0；经隧道访问同样返回 200 |

**端口探测的方法。**
- 本地电脑上的结果无效。mihomo 会在本地接受任何 TCP 连接，连文档保留地址 `192.0.2.1`、`198.51.100.7` 也显示"已连接"，随后被关闭（第 8.9 节同样遇到过）。
- UFW 的日志也不足以判定。`low` 级别的 LOG 规则为 `--limit 3/min --limit-burst 10`（主机上 `iptables -S ufw-logging-deny` 的输出），步骤 6 中来自探测来源的记录只有 1 条（目标为 80）。
- 所以改为在 VPS 上用 Python 的 `AF_PACKET` 套接字只读抓包，45 秒。只统计来源与本次 SSH 会话相同的 TCP 包，看主机对 SYN 的回应，判定如下：
  - SYN-ACK：开放；
  - RST：放行但没有服务监听；
  - 没有回应：SYN 在主机上被丢弃。

  步骤 10 中三种回应都出现了，抓包本身的判定得到验证（验证计划 VR-8）。
- 把"没有回应"归于 UFW 的依据：
  - 443 在步骤 6 没有回应，在步骤 10 回应 RST。按操作记录，两步之间对 netfilter 的改动只有 `ports` 添加的 UFW 规则，3X-UI 安装时设了 `XUI_ENABLE_FAIL2BAN=false`；
  - 步骤 6 中来自探测来源的那条日志带有 `[UFW BLOCK]` 前缀；
  - 验收结束后核对主机的 netfilter，只有三张表：
    - UFW 使用的 `ip filter` 和 `ip6 filter`：`INPUT` 默认 `DROP`，规则都转到 UFW 的链；
    - Fail2ban 的 `inet f2b-table`：只有一条规则，对封禁地址访问 22 端口回应 reject。

    `nftables.service` 未启用。
- 判定依据是主机的回应，不是外部路径。没有用不经代理的来源，也没有覆盖 IPv6。

**连续探测的结果。**
- 17:03:19～17:12:51 共 173 次。两次都失败的只有 1 次，在 17:06:51，即第一次重启的窗口内。
- 第一次失败、1 秒后重试成功的有 3 次：两次在重启窗口内；一次在 17:05:40，错误为"Connection closed"。
- 17:05:40 的那次，sshd 的日志显示这次登录已经被接受，会话也已经打开，当时正在经 mihomo 向被丢弃的端口发出大量 SYN（步骤 6）。断开更可能发生在本地代理一侧（推断，置信度中）。
- 按 VT-25 的判据，重启窗口外没有中断。

**Fail2ban 的被动观察。** 依据 `fail2ban.log` 和 Fail2ban 数据库中的封禁记录，地址不记录。
- **应用后的封禁。** 17:27:34～17:32:53，sshd jail 记录了同一个外部来源的 5 次失败，17:32:53 封禁，时长 86400 秒，与本工具的配置一致。
  - 这个来源不是管理员的出口：此后管理员的登录照常。
  - 这不是受控触发，来源和次数都不受控制。
- **应用时的短封禁。**
  - `apply` 安装 fail2ban 软件包后，服务先按软件包自带的配置启动（17:03:55）。它从日志中读到应用前 17:00:20～17:00:34 来自另一个外部来源的 5 次失败，随即封禁。
  - 数据库中这个封禁的时刻为 17:00:35，紧接最后一次失败；时长为 600 秒，是自带配置的值。
  - 17:03:59 写入本工具的配置，17:04:01 重启。之后这个封禁按原来的时长恢复，17:10:35 解封。本工具配置的 1 天只对之后的封禁生效。
  - 这一过渡状态第 8.8 节已有记录（第 9 节），这里是在新装的主机上再次观察到。

**没有覆盖的内容。**
- Fail2ban 的受控触发：没有一次性的测试来源，不从管理员的出口触发（R-3），以虚拟机证据 VT-33 为准。上面是被动观察。
- 外部 IPv6 路径：这台主机没有全局 IPv6 地址（验证计划 VR-5）。
- 3X-UI 的入站和代理客户端连接。
- 调优（VT-90）。
- 真正的无人值守升级。

- 结论：在这台全新安装的 Debian 13 主机上，验证计划第 5 节的判据逐项满足。apt 的执行方式和端口的判定方法与第 5 节不同，见上文。
  - 加固后只有 22/tcp 不被 UFW 拦截；
  - 用 `ports` 开放 443、2096 并确认之后，这两个端口放行，2053、80 仍被丢弃；
  - 面板只经隧道访问；
  - 每次重启后 `verify` 全部通过；
  - 重启窗口外的登录没有中断。

  发现一个新问题：安装脚本结尾的提示（第 9 节）。另外再次观察到第 8.8 节记录的 fail2ban 过渡状态。
- 置信度：
  - 这台主机上的结果为高，每一步都有工具输出和主机侧的证据；
  - 推广到其他主机为中：只有一台主机、一个服务商、一个平台，Debian 12 和 Ubuntu 24.04 只有虚拟机证据。

## 9. 已知限制与后续

- 已在 M2 解决的 M1 遗留项：
  - VT-02 和 VT-03 中"`apply` 被拒绝且不改变系统"的部分，已在 M2 补测（第 7.3 节）；
  - `confirm` 用审计会话编号区分新旧 root 会话的做法已核实（第 8.4 节，DR-11）。
- 已在 M3 解决的 M2 遗留项：`f2b.values` 和 `boundary.panel-listen` 已实现（第 4 节）；FR-09 的 dry-run 验证已完成（VT-40，第 8.7 节）。
- 已在 M4 解决的遗留项：
  - NFR-03：已应用的主机上再次 `apply` 只做核对，没有漂移时退出码为 0（第 2.5 节，VT-64）；
  - 应用在布置自动恢复之前被强制中断（例如断电）、状态停在"应用中"时，预检和 `status` 提示执行 `rollback`，回滚只恢复服务状态（第 2.10 节），不再需要手工删除状态目录。布置之后的中断仍由开机兜底单元处理。
- 3X-UI 的"安装防火墙"菜单在 UFW 已启用时不做任何改动，与需求 v1.4 第 7.2 节和 FR-10 验收的描述不符。VT-51 改用"停用后再安装"作为这项漂移，单独"安装防火墙"作为对照保留；需求 v1.5 据此更正（D29，已经用户确认，D30）。
- `boundary.panel-listen` 只核对应用时声明的面板端口。管理员之后在面板中改了端口时，这一项报告警告（端口上没有监听），不能判断新端口的监听地址。M4 的 `ports` 只增减公开端口，不改变记录中的面板端口（FR-14 不涉及面板端口），所以这种情况仍报告警告。
- `f2b.files` 把 `/etc/fail2ban` 下软件包和本工具以外的文件都判为不符合，包括管理员自己加的、与 sshd 无关的配置。这与 FR-02"不接管存量 Fail2ban 配置"的边界一致：只支持本工具写入的配置。
- `apply` 安装 fail2ban 软件包后，发行版默认的 sshd jail 会在本工具写入配置前运行几秒，期间可能按最近 10 分钟的失败记录封禁来源 10 分钟（第 8.8 节）。管理员只用密钥登录时不受影响，所以不修改。
- VT-34 只覆盖测试中的三种客户端行为（多密钥的 ssh-agent、`IdentitiesOnly`、认证前断开），不能证明任何客户端配置都不会被计为失败。被封过的来源再次失败时计数加重（需求第 10.1 节），管理出口一旦被封，30 天内更容易再次被封。
- sshd 重新加载的瞬间新建的 SSH 连接可能失败：研究中 Debian 12 上被重置，VT-23 中 Debian 12、13 上等待版本信息超时（第 8.4、8.5 节）。重试即可，不影响已建立的会话。M2 的测试用"失败后 1 秒重试一次"区分这种情况与登录路径中断（VT-25）。测试 VPS 上另有几次连接约 6 秒后被断开、重试即成功，原因未查明（第 8.6 节）。#14 合并后 `master` 上的一次运行中，Debian 12 的一次探测和它的重试先后落在两次相隔约 5 秒的重新加载上（应用失败后的恢复，紧接着的 VT-64 `apply`），VT-25 不成立，重跑后通过（第 8.16 节，推断）。如果再次出现，再考虑在测试中把重新加载 sshd 的时刻记为允许失败的窗口，或者拉开两次 `apply` 的间隔。
- 恢复后保留已安装的软件包（方案设计第 4.4 节）。开机恢复只恢复单元的启用状态，所以应用前启用、但当时没有运行的服务，开机后会运行。真实的新机上，受管单元一般不处于这种状态；测试环境中的两个 APT 定时器正是这种状态（第 7.2 节：测试在运行期停止了它们），开机恢复后照常运行，所以 VT-22 只比较启用状态。
- `confirm` 的检查防的是误操作，不防有意绕过的 root（方案设计第 7.5 节）。
- 测试中 `apt-daily-upgrade.service` 被替换为空操作（第 7.2 节），因此没有覆盖真正的无人值守升级；FR-09 只有 dry-run 的证据（VT-40）。
- arm64 只作参考（需求 D26）：按需手动运行，覆盖 matrix、recovery 和 hardened 套件，结果见附录 A；negative 套件只在 amd64 上运行（验证计划第 3.1 节的"三平台"范围）。hardened 套件还没有在 arm64 上运行过：TCG 下 M2 的主流程就要 14～19 分钟，加上 M3 的用例、12 个漂移覆盖层和 M4 的 3 个覆盖层，可能超过 60 分钟的作业上限（推断，未测量）。
- 真实主机验收（M5）只在一台重装的 Debian 13 测试 VPS 上做过（第 8.19 节）。Debian 12 和 Ubuntu 24.04 只有 CI 虚拟机的证据。第 8.6、8.8、8.9、8.11 节是此前在同一台测试 VPS 上的试运行和核对。M5 没有覆盖：Fail2ban 的受控触发（没有一次性来源，以 VT-33 为准；被动观察见第 8.19 节）；外部 IPv6 路径（这台主机没有全局 IPv6 地址）；3X-UI 的入站。
- 外部连通测试不能从出口经过代理的电脑直接做：代理会在本地接受任何 TCP 连接（第 8.9 节）。M5 改为在 VPS 上抓包，按主机对 SYN 的回应判定（第 8.19 节）。UFW 的日志不足以判定：`low` 级别每分钟最多记 3 条（突发 10 条），公网的背景扫描会占用额度；M5 中 4 个被丢弃的端口，来自探测来源的记录只有 1 条。
- M5 发现：在没有应用过的主机上，安装脚本完成后提示"下一步：vps-hardening preflight --open <公开端口>"。这是需求 D41 之前的推荐做法，第 2.12 节写的是提示执行 `preflight`。按推荐流程，应提示不带 `--open` 的 `preflight`。`--open` 仍然支持，所以不影响使用。尚未修复，修复后要随下一个预发行版发布。
- M5 在新装的主机上再次观察到上面 fail2ban 的过渡状态（第 8.19 节）：数据库中这个封禁的时长为 600 秒，本工具的配置生效、服务重启之后，仍按 600 秒恢复。
- `ports` 核实规则时，只放行一个地址族的端口按 `ufw status` 的格式判定（第 2.11 节）。这一判定依据 ufw 的源码；VT-63 只增减了两个地址族都放行的端口，单一地址族的增减没有在虚拟机中运行过。`apply` 写入的单一地址族规则由 M2 的 VT-14 覆盖。
- `rollback` 恢复应用前的 SSH 配置，包括密码认证：应用前允许密码登录的主机，回滚后密码猜测随即开始，`rollback.password` 只作警告。测试 VPS 上没有执行 `rollback`，也没有执行 `ports`，两者只有虚拟机中的证据（第 8.10、8.11 节）。
- `reboot.required`（预检和 `verify`）只看 `/var/run/reboot-required`。这个标记由软件包的钩子创建：CI 中三个平台的镜像和测试 VPS 的 Debian 13 镜像都预装了 unattended-upgrades，测试 VPS 上由它的 `/etc/kernel/postinst.d/unattended-upgrades` 在安装内核时创建。没有预装 unattended-upgrades 的 Debian 镜像上，更新内核后可能没有这个标记，预检和 `verify` 都不会警告（推断，需求 D43）；遇到这样的镜像时，再考虑比对正在运行的内核与 `/boot` 中的内核。
- 已在 v0.6 解决：安装脚本完成后原来总是提示"下一步：vps-hardening preflight"，在已应用的主机上不适用（第 8.11 节）；现在按状态提示（第 2.12 节）。
- 已在发布后解决：VT-72 的公开部分（从发行版的公开地址下载并校验）在 `v0.1.0-rc.1` 发布后完成（第 8.14 节），`v0.1.0-rc.2` 发布后又做了一次（第 8.16 节）。从公开地址安装和升级只在一台已应用的 Debian 13 测试 VPS 上做过；新机上的首次安装和另外两个平台只有本地模式的证据（VT-72 的本地部分，同一个安装脚本，只是资产的来源不同）。
- 已在 v0.7 修复，随 `v0.1.0-rc.2` 发布（第 8.16 节）：`v0.1.0-rc.1` 发布后核实的四个问题（需求 D40，第 1 节；三个来自 CodeRabbit 对 #10、#11 的意见，一个是修复时发现的，2026-10-22 逐条核实，第 8.15 节）。`v0.1.0-rc.1` 的发布说明在"已知问题"一节中列出了它们（需求 D39）。
  - `sshd.match`、`ssh.match` 漏查含空格、带引号或转义空格的 `Include` 路径：`sshd_includes` 按空白拆分参数，`Include "/etc/ssh/override dir/99.conf"` 被拆成两个不存在的路径，那个文件不被检查。sshd 接受这一行，文件中的 `Match Address` 块对匹配的来源给出 `passwordauthentication yes`，按假定的连接求值仍为 `no`，所以这样的配置能通过预检和 `verify`，与需求 D36 不符。`sshd.include` 遇到带引号的片段目录则会误拒，方向是安全的。
  - 同一原因，修复时发现：sshd 取关键字时去掉双引号，`"Match" Address …` 与 `Match Address …` 相同；原来的检查按 awk 的第一个字段取关键字，得到带引号的 `"match"`，同样漏查。
  - 安装脚本的"未做变更"只比较文件类型、数量和内容，不检查属主和权限：已安装的文件被改了权限后，重复安装不会修复。
  - 安装脚本把新模块目录换上之后、换入口之前失败或被信号中断时，`cleanup` 看到模块目录存在，就不再放回旧模块，结果是旧入口配新模块，旧目录留作 `/usr/local/lib/.vps-hardening.old.<PID>`；新机上则留下没有入口的模块目录。
- 以 `~` 开头的 `Include` 路径：sshd 既不加 `/etc/ssh`，也不展开 `~`（`glob()` 的标志为 0），按 sshd 进程的当前目录解析；本工具仍把它接在 `/etc/ssh` 之后，两者不一致。这种写法罕见，没有处理。
- 安装脚本被 `SIGKILL` 或断电打断时不能恢复，临时文件和旧副本要手工删除（第 2.12 节）。
- 需求 v1.6 草案的评审发现的三处缺口（第 1 节）自 M2 起就存在。第 8.5、8.7、8.10 节的用例中没有 `Match` 块、UFW 未启用时已添加的规则和被改动的框架文件，那些结论在各自覆盖的情况下仍然成立，只是没有覆盖这三种情况。
- `sshd.match`、`ssh.match` 拒绝任何 `Match` 块，包括与认证无关的（例如只对某个来源关闭 `X11Forwarding`）。这是需求 D36 的取舍：按一个连接求值无法确认所有来源都只允许密钥登录。有这类配置的主机要先去掉 `Match` 块才能应用；应用后加入的，`verify` 报告不符合。
- 框架文件以 `/usr/share/ufw` 中的模板为准。依据测试 VPS 上 ufw 0.36.2-9 的 `postinst`（2026-10-22 只读核对）：
  - 四个 `.rules` 文件由 ucf 管理，模板为 `/usr/share/ufw/iptables/<名称>`，`/usr/share/ufw/<名称>` 是指向它的符号链接。未改动的副本在软件包升级时随模板更新，升级后仍相同。
  - `before.init`、`after.init` 只在 `/etc/ufw` 中不存在时复制，升级不更新。今后的 ufw 版本如果改了这两个模板，未改动的旧副本也会与新模板不同，`ufw.framework` 报告不符合，属于误报（推断，目前没有观察到）。这时比较差异，确认只来自模板的变化后，可以把模板复制到 `/etc/ufw`。
  - Debian 12、Ubuntu 24.04 的 `postinst` 没有逐一核对；CI 中三个平台上 6 个文件都与模板相同（第 8.13 节）。
- `ufw status` 和 `ufw show added` 只列出 `user.rules`、`user6.rules` 中带 `### tuple ###` 注释的规则，而 UFW 启动和重新加载时用 `iptables-restore` 载入整个文件（ufw 0.36.2 的 `backend_iptables.py` 中的 `_read_rules` 和 `ufw-init-functions`）。直接编辑这两个文件加入的、没有 tuple 注释的规则因此会生效，却不显示：
  - `apply` 之前加入的不会生效：`apply` 的 `ufw allow` 按已解析的规则重写两个文件（`_write_rules`），这样的行被丢弃（依据源码，没有在虚拟机中运行）。
  - `apply` 之后直接编辑的，由 `ufw.userrules` 发现（需求 D37，第 4 节）；`ports` 先以 `ports.userrules` 拒绝，避免改写文件后把这一行洗掉（第 2.11 节）。
  - 直接编辑后又执行 `ufw reload` 或 `ufw enable` 的，仍然发现不了：两者先执行 `ufw-init start` 载入整个文件，再按已解析的规则重写两个文件（`frontend.py` 的 `set_enabled`，`backend_iptables.py` 的 `start_firewall` 调用 `update_logging`，2026-10-22 在测试 VPS 上的 0.36.2-9 只读核对）。结果是规则生效，文件恢复原样，摘要一致，`ufw status` 也不显示；UFW 下次启动（例如重启）时这一行不再载入。要发现这种情况得比较内核中生效的规则，其中还有 Fail2ban 等其他来源的链，没有实现。
  - `ufw logging` 改日志级别时也会重写两个文件（文件中的 `### LOGGING ###` 一节随级别变化），`ufw.userrules` 报告不符合，虽然规则没有变化。改回原来的级别（默认 `low`）后文件应当恢复原样（推断：重写的结果由规则和级别决定，VT-63 中恢复后的摘要等于确认后的，没有对日志级别单独测试）。
  - ufw 软件包升级如果改变了重写文件的格式，下一次 `ufw reload`、`ufw enable` 或增删规则后 `ufw.userrules` 会报告不符合（推断，目前没有观察到）。

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
