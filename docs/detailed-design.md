# VPS Hardening 详细设计

| 项目 | 内容 |
|---|---|
| 状态 | 草稿 v0.1：只覆盖里程碑 M1 已实现的部分（命令骨架、`preflight`、`verify`、测试框架）。M2～M4 实现时增补 |
| 日期 | 2026-10-13 |
| 上游 | [需求规格说明 v1.2](requirements.md)、[方案设计 v1.0](solution-design.md)、[验证计划 v1.0](verification-plan.md)（均已批准） |
| 下游 | 实现、测试 |
| 深度 | 命令契约、检查项目录、模块划分、实现约束和测试框架；不重复上游已有的决策理由 |

**证据状态。** 第 2～6 节描述的是仓库中的实现，第 7 节描述的是测试框架。运行证据见第 8 节，只来自 CI 虚拟机，不代表真实主机。

## 1. 范围

M1 只实现只读部分（方案设计第 10 节）：

- `preflight`：只读预检，包括存量主机判定（FR-01、FR-02）；
- `verify`：只读验证（FR-10）。依赖应用记录的检查项在 M1 报告"跳过"，应用记录从 M2 起由 `apply` 写入；
- `apply` 只实现到参数校验和交互终端检查，然后报告"尚未实现"；`confirm`、`status`、`rollback`、`ports` 直接报告"尚未实现"。

## 2. 命令契约

### 2.1 调用与环境

- 入口为 `bin/vps-hardening`，模块在 `lib/vps-hardening/`。入口用 `readlink -f` 定位自身，按"上两级目录下的 `lib/vps-hardening`"找模块，所以安装后（`/usr/local/bin` 和 `/usr/local/lib`，方案设计第 7.2 节）和在仓库中运行使用同一套相对布局。
- 入口固定 `PATH`、`LC_ALL=C`（被解析的工具输出保持英文格式）和 `umask 077`，并启用 `set -Eeuo pipefail`。
- 输出中的说明文字为中文；检查项编号为英文，保持稳定，测试按编号判定。

### 2.2 退出码

| 退出码 | 含义 |
|---|---|
| 0 | 检查全部通过（允许有警告和跳过） |
| 1 | 至少一项不符合 |
| 2 | 用法或输入错误：未知命令或参数、参数取值不合法、公钥文件无效、`apply` 不在交互终端中运行、命令尚未实现 |
| 3 | 内部错误：命令意外失败。由 ERR 陷阱统一转换，避免被误读为"不符合"（退出码 1） |

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

### 2.4 输入参数

`preflight` 和 `apply` 共用同一个解析器（`lib/vps-hardening/inputs.sh`），支持 `--选项 值` 和 `--选项=值` 两种写法。任何一项不合法都以退出码 2 结束，不做主机检查。

| 参数 | 规则 |
|---|---|
| `--user` | 必填；`^[a-z][a-z0-9_-]{0,31}$`，不能是 `root` |
| `--pubkey-file` | 必填，可重复；单个文件不超过 64 KiB。只接受"类型 密钥 [注释]"格式的行，带选项（如 `command=`）的行整体拒绝；含 `PRIVATE KEY` 的文件按私钥拒绝；逐行用 `ssh-keygen -l -E sha256` 解析，按指纹去重，最多 20 把；允许 CRLF 和注释行 |
| `--panel-port` | 默认 2053（需求 D20）；1～65535，不能是 22 |
| `--open` | 可重复，最多 16 个；`端口/tcp|udp[/both|ipv4|ipv6]`，地址族默认 `both`；端口不能是 22 或面板端口，同一端口和协议不能重复 |
| `--maxretry` | 3 或 6，默认 6 |
| `--confirm-timeout` | 3～60 的整数分钟，默认 10（需求 D18） |

`apply` 先检查标准输入是否为终端（方案设计第 7.1 节），再解析参数。

## 3. preflight 检查项

前两项是门槛：不满足时立即结束，后续检查不执行。

| 编号 | 检查 | 不符合的条件 |
|---|---|---|
| `root` | 运行权限 | 不是 root |
| `platform` | 平台 | 不是 Debian 12/13 或 Ubuntu 24.04（x86_64/aarch64）；PID 1 不是 systemd；运行在容器中 |
| `inputs.*` | 输入摘要 | `inputs.user-free`：同名账户或用户组已存在。其余各项只回显已校验的输入；没有公开端口时 `inputs.open` 为警告 |
| `new-host.xui` | 存量判定 S1 | 存在 `x-ui.service` 或 `/usr/local/x-ui` |
| `new-host.container` | 存量判定 S4 | 存在 Docker（命令或 `docker.service`）或 Podman |
| `new-host.ufw` | 存量判定 S2 | UFW 已启用 |
| `new-host.fail2ban` | 存量判定 S3 | 有 `*.local`；`jail.d`、`fail2ban.d` 中有发行版 `defaults-debian.conf` 以外的文件；或 `dpkg --verify fail2ban` 报告改动 |
| `new-host.state` | 是否执行过 | 存在 `/var/lib/vps-hardening` |
| `sshd.config` | sshd 配置 | `sshd -t` 失败，或 `sshd -T` 读不出生效配置 |
| `sshd.include` | 片段能否生效 | 主配置在 `Include /etc/ssh/sshd_config.d/*.conf` 之前已设置受管选项或打开了 `Match` |
| `sshd.dropin-order` | 片段排序 | 排在 `00-vps-hardening.conf` 之前的片段设置了受管选项或 `Match`，或本工具的片段已存在 |
| `sshd.key-types` | 公钥算法 | 有公钥的算法不在 `pubkeyacceptedalgorithms` 中（`ssh-rsa` 密钥以 `rsa-sha2-*` 判定） |
| `sudo.present`、`sudo.group` | 提权条件 | 没有 sudo；没有 `sudo` 组或 `%sudo ALL=(ALL:ALL) ALL` 规则；`sudo` 组免密 |
| `sudo.nopasswd-accounts` | 免密账户 | 只报告（`INFO`）：有 SSH 密钥且免密 sudo 的账户，应用时将被禁止 SSH 登录（需求 D13） |
| `apt.idle` | 包管理器 | dpkg、apt 或 unattended-upgrades 的锁被持有，或 apt、dpkg 进程在运行 |
| `apt.candidates` | 软件包来源 | `ufw`、`fail2ban`、`nftables`、`python3-systemd`、`unattended-upgrades` 中有没有候选版本的 |
| `apt.fail2ban-version` | Ubuntu 的 fail2ban | 候选版本低于 `1.0.2-3ubuntu0.1` |

受管的 sshd 选项：`permitrootlogin`、`passwordauthentication`、`kbdinteractiveauthentication`、`pubkeyauthentication`、`denyusers`。

## 4. verify 检查项

区域和判定依据见方案设计第 7.6 节。M1 中的实现范围：

| 编号 | 判定 | M1 状态 |
|---|---|---|
| `root`、`platform` | 同 preflight 的门槛 | 已实现 |
| `state` | 应用记录存在且为"已应用" | 没有记录时为不符合；记录格式在 M2 确定 |
| `admin.user`、`ssh.admin`、`ssh.dropin`、`ufw.rules`、`ufw.panel`、`f2b.values`、`boundary.panel-listen` | 需要应用记录中的声明值 | 跳过（`boundary.panel-listen` 在未安装 3X-UI 时为 `INFO`） |
| `accounts.nopasswd` | 有密钥、免密 sudo、又不在 `DenyUsers` 中的登录账户 | 已实现 |
| `ssh.permitrootlogin`、`ssh.passwordauthentication`、`ssh.kbdinteractive`、`ssh.pubkey`、`ssh.forwarding`、`ssh.port` | 以 root 身份执行 `sshd -T -C` 的生效值：`no`、`no`、`no`、`yes`、`yes` 或 `local`、`22` | 已实现；以管理用户和被禁用户执行的部分在 M2 补充 |
| `ssh.listen` | 22 端口在 IPv4 上监听为必需；没有 IPv6 时为警告 | 已实现 |
| `ufw.installed`、`ufw.active`、`ufw.defaults`、`ufw.ipv6`、`ufw.port80` | 已安装并启用；默认拒绝入站、允许出站、拒绝转发；`IPV6=yes`；没有放行 80 端口的入站规则 | 已实现 |
| `f2b.installed`、`f2b.service`、`f2b.jails`、`f2b.mainconf` | 已安装；服务启用且运行；jail 只有 `sshd`；`jail.conf`、`fail2ban.conf` 未改动 | 已实现；生效值和配置检查在 M3 补充 |
| `nft.service` | `nftables.service` 未启用 | 已实现 |
| `uu.installed`、`uu.periodic`、`uu.reboot`、`uu.origins`、`uu.timers` | 已安装；两个 `APT::Periodic` 值为 1；不自动重启；来源列表与 FR-09 一致；两个 APT 定时器启用且运行 | 已实现 |
| `boundary.container`、`boundary.xui-bbr` | 没有 Docker 或 Podman；没有 `/etc/sysctl.d/99-bbr-x-ui.conf` | 已实现 |
| `reboot.required` | 存在 `/var/run/reboot-required` | 警告 |

`uu.origins` 的期望集合（从 `apt-config dump` 读取，`${distro_*}` 占位符原样比较）：

- Debian：`Origins-Pattern` 为发行版默认的三项（`label=Debian`、两项 `Debian-Security`），`Allowed-Origins` 为空；
- Ubuntu：`Allowed-Origins` 为 `${distro_id}:${distro_codename}-security` 和两项 ESM 安全来源，`Origins-Pattern` 为空。

## 5. 模块划分

| 文件 | 职责 |
|---|---|
| `bin/vps-hardening` | 环境、加载模块、ERR 陷阱、子命令分派、帮助 |
| `lib/vps-hardening/common.sh` | 常量、退出码、`report` 和汇总、临时目录、通用小函数 |
| `lib/vps-hardening/platform.sh` | 解析 `/etc/os-release`（按数据解析，不执行）、平台判定、systemd 和容器判断 |
| `lib/vps-hardening/inputs.sh` | 参数解析和校验、公钥加载 |
| `lib/vps-hardening/probe.sh` | 只读探测：软件包、单元、sshd 生效配置、账户和密钥、sudo、监听端口、UFW、apt 配置、包管理器锁 |
| `lib/vps-hardening/preflight.sh` | preflight 检查 |
| `lib/vps-hardening/verify.sh` | verify 检查 |

## 6. 实现约束

- **只读。** preflight 和 verify 只调用读取类命令；临时文件只写在 `mktemp -d` 创建的私有目录中，退出时删除。测试在每个用例前后比较状态摘要（第 7.4 节）。
- **有界。** 可能被服务阻塞的读取命令（`sshd`、`ufw`、`fail2ban-client`、`apt-config`、`apt-cache`、`sudo -l`）加 30 秒超时。
- **管道与 `pipefail`。** 读取端不提前退出（不用 `head`、`grep -q` 截断长输出），否则写入端会因 SIGPIPE 失败，在 `pipefail` 下被误判。`apt-config dump` 的输出缓存后复用。
- **sshd 生效值。** 用 `sshd -T -C user=<用户>,host=vps-hardening.invalid,addr=192.0.2.1,laddr=192.0.2.2,lport=22` 按用户求值，结果按用户缓存。地址取自文档保留地址，使 `Match Address` 块按"普通外部来源"求值。
- **包管理器是否在运行。** 以锁的持有者（`lslocks`）为准，再加 apt、dpkg 进程名。进程名逐个交给 `pgrep -x`：整个模式超过 15 个字符时 pgrep 不匹配任何进程，用 `|` 拼接的模式会静默失效。不能用进程名判断 unattended-upgrades：它的关机辅助进程常驻，进程名截断后与升级进程相同。
- **ERR 陷阱。** 只在主 shell 中把意外失败转换为退出码 3。`$(...)` 和管道中的命令也会触发陷阱，其中包括预期的非零状态（如查询未安装的单元），所以子 shell 中不处理；真正的失败经退出状态回到主 shell 后再判定。
- **启发式判定。** `sudo.group` 只识别 sudoers 中的标准写法，`new-host.fail2ban` 以文件存在为准。两者在不确定时都判为不符合或拒绝，宁可误拒，不会误放行。

## 7. 测试框架

### 7.1 组成

| 文件 | 作用 |
|---|---|
| `tests/vm.py` | 运行器侧：下载并校验官方云镜像，生成 cloud-init 种子，启动 QEMU，按阶段在客体中执行测试，收集证据。改编自 vps-tuning 的 `tests/platform-vm.py` |
| `tests/guest/m1.sh` | 客体侧：各阶段的准备、用例和判定 |
| `tests/platform-images.json` | 镜像 URL 和摘要，与 vps-tuning 同源 |
| `tests/static.sh` | 不需要虚拟机的检查：shell 和 Python 语法、LF 行尾、通用秘密特征 |
| `.github/workflows/static.yml` | 运行 `tests/static.sh` 和 ShellCheck 0.11.0（固定容器镜像）。ShellCheck 只报告命令行列出的文件，不报告经 `-x` 跟随的文件，所以列出全部模块 |
| `.github/workflows/vm.yml` | matrix 和 negative 两组作业，证据作为构件保存 14 天 |

### 7.2 客体初始状态

按验证计划第 3.2 节，由 cloud-init user-data 显式写入：

- `disable_root: false`，root 和镜像默认用户使用同一把测试驱动的密钥；默认用户由镜像的 cloud-init 配置赋予免密 sudo，测试开始前逐项核实（`check_profile`）；
- root 密码由 `runcmd` 经 `chpasswd` 设置，每次运行随机生成，同时作为泄露扫描的标记；
- `write_files` 写入 `/etc/ssh/sshd_config.d/50-cloud-init.conf`，内容为 `PasswordAuthentication yes`。

测试环境与"典型新机"的两处差异，都只为排除干扰：

- 每次启动后在运行期停止 `apt-daily.timer` 和 `apt-daily-upgrade.timer`（不改变启用状态），并等待包管理器空闲；
- 准备阶段用精简的 `apt-get update`：不下载翻译、AppStream 和 command-not-found 索引。

### 7.3 套件与用例

| 套件 | 平台 | 内容 |
|---|---|---|
| matrix | 6 组 | 准备；核实转发连接在客体中的来源地址；VT-01；VT-50 的未加固部分；sshd 探测研究 |
| negative | 三平台 amd64 | 准备；VT-02、VT-04；关机后以准备好的磁盘为底，S1～S4 各用一个覆盖层磁盘启动（VT-03）；S2 中检查 UFW 是否过滤转发连接 |

判定要点：

- VT-01：`preflight` 退出码为 0，前后状态摘要一致；
- VT-50（未加固）：`verify` 退出码为 1；`state`、`ssh.permitrootlogin`、`ssh.passwordauthentication`、`accounts.nopasswd`、`f2b.installed` 为不符合，Debian 上 `ufw.installed`、Ubuntu 上 `ufw.active` 为不符合；`ssh.pubkey`、`ssh.port`、`nft.service`、`boundary.container`、`boundary.xui-bbr` 为通过；前后摘要一致；所有证据中没有测试密码；
- VT-02：非 root（`runuser -u nobody`）、不支持的版本（在私有挂载命名空间中覆盖 `/etc/os-release`）、缺少公钥、dpkg 前端锁被占用、有不持锁的 `dpkg` 进程，分别得到对应的不符合项或退出码 2；
- VT-03：S1～S4 各自得到 `new-host.xui`、`new-host.ufw`、`new-host.fail2ban`、`new-host.container` 不符合，并提示"存量主机不在支持范围内"，`preflight` 前后摘要一致；
- VT-04：第 2.4 节的各类非法输入退出码为 2（已有账户、同名用户组为不符合，退出码 1）；Ed25519 和 RSA 公钥被接受；时限 3 和 60 被接受；标准输入不是终端时 `apply` 被拒绝。

### 7.4 状态摘要

每个用例前后各采集一次，逐行比较：

- `/etc` 下每个对象的类型、权限、属主和链接目标，以及每个普通文件的 SHA-256；
- root 和 `/home` 下各账户 `.ssh` 中的文件摘要；
- `nft -s list ruleset`，以及去掉注释和计数器的 `iptables-save`、`ip6tables-save`；
- `ufw status verbose`；
- 全部单元文件的启用状态（不含会话 scope），以及相关服务和定时器的启用、运行状态；
- 软件包列表；工具状态目录是否存在。

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

待 CI 完成后填写。

## 9. 已知限制与后续

- VT-02 和 VT-03 中"`apply` 被拒绝且不改变系统"的部分：M1 的 `apply` 在参数校验后即报告"尚未实现"，不执行预检，因此只能证明它不改变系统。`apply` 执行预检并拒绝存量主机，在 M2 中补测。
- `verify` 中依赖应用记录的检查项在 M1 报告"跳过"，在 M2、M3 中随应用记录补全。
