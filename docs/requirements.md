# VPS Hardening 需求规格说明

| 项目 | 内容 |
|---|---|
| 状态 | v1.4 草稿，待评审：按用户 2026-10-20 的决定（U14，D26），正式支持和验收的架构改为 x86_64，aarch64 改为按需运行的参考；涉及 NFR-04 和第 2、9、11～13 节。同一草稿按用户 2026-10-20 的提问（U15）定下加固、调优和 3X-UI 的执行顺序（D27），涉及 FR-02 的说明和第 7.3 节。v1.3 已批准：按用户 2026-10-20 的决定（U12，D22～D24）改为 root 只用密钥登录、不创建管理用户，Fail2ban 改用普通过滤模式、`maxretry` 取 5，并写明加固前的升级顺序；涉及 FR-01、FR-03～FR-05、FR-07、FR-08、FR-12、NFR-01、NFR-06 和第 1、3、6～10、12 节，用户于同日评审通过（U13、D25）。此前的版本：v1.0 于 2026-10-13 评审确认（D17）；v1.1 按方案设计第 11 节的建议修改 FR-05、FR-09 和第 6 节（D18～D20）；v1.2 在第 7.2 节补登 3X-UI 的安装约定（D21），两次修改都经用户于同日确认。作为详细设计和实现的依据；修改需重新评审 |
| 日期 | 2026-10-20（v1.2 为 2026-10-13） |
| 上游依据 | [README](../README.md) 中已确认的范围（2026-10-10），以及第 2 节列出的用户原话和决定 |
| 下游 | [方案设计](solution-design.md)（v1.2 草稿）、[详细设计](detailed-design.md)、[验证计划](verification-plan.md)（v1.2 草稿） |

优先级：**P0** 必须，缺少则首版不成立；**P1** 应有，可以放到下一迭代；**P2** 可选；**P3** 明确不做。

## 1. 目的与范围

为**全新安装**的 Debian/Ubuntu VPS 做基础安全加固：在不明显增加日常管理负担的前提下缩小暴露面，同时保证管理员不会被锁在服务器外。

范围内：

- SSH 认证收紧：只允许密钥登录，root 是管理账户（D22）；
- 镜像默认用户的免密 sudo 处理（D13）；
- UFW 入站最小化，面板端口不对外开放，只经 SSH 隧道访问；
- Fail2ban（只保护 SSH）；
- 自动安全更新；
- 防锁死、确认和回滚；
- 与 vps-tuning、vps-proxy-setup 的边界约定。

范围外的事项见第 8 节。

**关于"防止互联网扫描 VPS"。** 扫描本身无法阻止。Fail2ban 要等服务日志里出现认证失败才会封禁来源，扫描未开放的端口不会留下这类日志。真正缩小暴露面的是：UFW 默认拒绝入站、只开放必要端口、面板不对外开放、SSH 只允许密钥登录。Fail2ban 的作用是减少针对 SSH 的反复尝试和日志噪声，属于补充防线。本文按这个理解把 U2 中的"防止互联网扫描"落实为 FR-04、FR-06、FR-07 和 FR-08。

## 2. 需求来源与已确认决定

### 2.1 用户原话

| 编号 | 日期 | 原话（摘录） |
|---|---|---|
| U1 | 2026-10-10 | 第一仓库的目的是为VPS进行安全加固，比如防火墙设置、密钥登录（禁root登录）、Fail2ban等 |
| U2 | 2026-10-10 | 安全加固只做基本的安全加固，要满足一定的便利性，3X-UI面板管理使用ADMIN_CIDRS，不要修改SSH端口22，禁止root登录，需要密钥登录，开启UFW，只开放必要的端口，对Fail2ban进行定制设置，防止互联网扫描VPS |
| U3 | 2026-10-10 | 同意使用 SSH 隧道：ssh -L 8443:127.0.0.1:<面板端口> user@vps；sudo 要输入密码，SSH 22 端口对所有来源开放，Fail2ban 建议配置等后续配置时候我提供一个样例你来分析，纳入自动安全更新 |
| U4 | 2026-10-13 | VPS 代理服务器安装配置（以 3X-UI 3.7.0 为例） |
| U5 | 2026-10-13 | 用户现行的新机操作流程（命令摘要，已去掉真实地址）：用 SSH 密钥以 root 登录 → UFW 默认拒绝入站、允许出站、拒绝转发，放行 `22/tcp` 后启用 → 放行 `80/tcp`（证书）、`443/tcp`（REALITY）、`2096/tcp`（订阅），面板端口只放行几个来源地址（目前是用户其他 VPS 的出口 IP）→ `apt install fail2ban` → 写入 `jail.d/99-vps.local`（`maxretry = 6`，其余同 D8）和 `fail2ban.local` → 按 11 步验证（语法、服务、通信、jail、参数、过滤器、手工封禁、nftables、解封） |
| U6 | 2026-10-13 | 待决事项1和2按你的建议，3选择禁止这个账户用 SSH 登录，4 设计阶段再给具体数值；5 端口约定参考我前面提供的信息，80端口按你的建议不开放，用 Cloudflare API Token 签证书 |
| U7 | 2026-10-13 | 面板只走SSH 隧道 |
| U8 | 2026-10-13 | 需求已经评审，确认；现网机器不受影响 |
| U9 | 2026-10-13 | 确认上面5项，请你继续执行后续任务（"5项"指方案设计第 11 节对 OD-4、OI-1～OI-4 的建议） |
| U10 | 2026-10-13 | 1. 写入 2.已评审验证计划 3.M4 之后再定（依次指验证计划的 VO-3、验证计划评审、VO-4） |
| U11 | 2026-10-19 | 用户提供的现网操作文档（2026-10-17，本地文件，含真实地址，未入库）。摘要：新机先 `apt full-upgrade` 并重启；SSH 的最终状态是 root 只能用密钥登录（`PermitRootLogin prohibit-password`），密码和键盘交互认证全部关闭；Fail2ban 曾在 `mode = aggressive`、`maxretry = 3` 下封掉管理出口（MobaXterm 的附加连接在认证完成前断开，被计为失败），之后改为 `mode = normal`、`maxretry = 5` |
| U12 | 2026-10-20 | 建议在 M2 的使用说明中写明推荐顺序：apt update && apt full-upgrade → 重启 → 加固，root+密钥登录，Fail2ban 用normal过滤模式、maxretry 取5 |
| U13 | 2026-10-20 | 确认以上4项，评审通过，合并后开始M2（"4项"依次指：`maxretry` 固定为 5、不再作为参数；本工具不管理 root 的 `authorized_keys`，预检要求 root 至少有一把可用的公钥；保留 D13；`confirm` 用审计会话编号区分新旧 root 会话） |
| U14 | 2026-10-20 | 1.VPS主要是amd64的机器，arm64可以作为附录供参考执行 2.VPS厂商都在管理页面提供了绑定SSH密钥的功能，仓库是否需要提供先检查是否已经配置好SSH密钥，如果已经配置好，就不需要再次配置了，只需补充禁止root+密码登录，只允许root+密钥登录（随后选择：aarch64 作为按需运行的参考；在 README 中写明本工具只检查、不写入公钥） |
| U15 | 2026-10-20 | 我之前关于VPS调优、加固、安装设置3X-UI的顺序是否有问题？是不是应该先加固，再优化，最后安装配置3X-UI？ 还是先加固，再安装配置3X-UI，最后优化？请你分析评估给出一个最佳的顺序，然后调整需求和设计文档。 |

### 2.2 已确认决定

| 编号 | 决定 | 日期 | 来源 |
|---|---|---|---|
| D1 | SSH 保持 22 端口，对所有来源开放 | 2026-10-10 | U2、U3 |
| D2 | 只允许密钥登录；禁止 root 经 SSH 登录；日常使用普通 sudo 用户，sudo 需要输入密码。**后两项已被 D22 替代**，只允许密钥登录不变 | 2026-10-10 | U2、U3 |
| D3 | 启用 UFW，只开放必要端口 | 2026-10-10 | U2 |
| D4 | 面板端口只允许 `ADMIN_CIDRS` 访问；管理员 IP 变化时改用 SSH 隧道。**已被 D16 替代** | 2026-10-10 | U2、U3 |
| D5 | 纳入自动安全更新 | 2026-10-10 | U3 |
| D6 | 只支持新机。已经运行 3X-UI 的存量主机不在范围内；需要加固时，先备份业务，重装系统后按新机流程执行 | 2026-10-13 | 用户选择 |
| D7 | 交付形态：在 VPS 本机运行的单命令工具，提供预检、应用、验证和回滚，不依赖控制端 | 2026-10-13 | 用户选择 |
| D8 | Fail2ban 原样采用用户现网 3X-UI 配置方案（V1.15）第 16.1 节的 SSH 配置：`ignoreip` 只含回环地址，管理出口不豁免。**过滤模式已被 D23 修改** | 2026-10-13 | 用户选择 |
| D9 | 与代理仓库的共存，以 3X-UI v3.7.0 为验证基线 | 2026-10-13 | U4 |
| D10 | 只做基础加固，不做 CIS 全量合规、入侵检测、AppArmor/SELinux 策略或审计系统；不安装代理，不做网络调优 | 2026-10-10 | README |
| D11 | 平台范围与 vps-tuning 一致：Debian 12、Debian 13、Ubuntu 24.04 LTS，x86_64 和 aarch64。**架构部分已被 D26 修改** | 2026-10-13 | U6（原 OD-1） |
| D12 | 自动安全更新后不自动重启，由验证报告待重启状态 | 2026-10-13 | U6（原 OD-2） |
| D13 | 镜像默认用户有免密 sudo 时，禁止该账户经 SSH 登录 | 2026-10-13 | U6（原 OD-3） |
| D14 | 端口约定以 U5 的现行流程为准，但 80/tcp 不开放；证书由 vps-proxy-setup 用 Cloudflare API Token 走 DNS-01 签发。面板端口按 D16 处理 | 2026-10-13 | U5、U6（原 OD-5） |
| D15 | Fail2ban 的 `maxretry` 默认取 6（U5 新机流程的值），3 作为允许的参数值。**已被 D23 替代** | 2026-10-13 | U5、D8 |
| D16 | 面板只经 SSH 隧道访问：UFW 不放行面板端口，面板只监听 127.0.0.1（由 vps-proxy-setup 设置）；首版不提供 `ADMIN_CIDRS` 直连。替代 D4 | 2026-10-13 | U7（原 OD-6），评估见第 11.1 节 |
| D17 | 本需求规格说明 v1.0 经用户评审确认。OD-4 留到设计阶段给出具体数值；现网主机保持原有配置，不受本文约束（与 D6 一致） | 2026-10-13 | U8 |
| D18 | 确认时限默认 10 分钟，允许 3～60 分钟 | 2026-10-13 | U9（原 OD-4），依据见方案设计第 7.5 节 |
| D19 | Debian 上的自动更新同时安装稳定版小版本更新（`label=Debian`，与 Debian 默认一致），以便自动获得标为 `no-dsa` 的低危修复；Ubuntu 仍只装 `-security` 和 ESM 的安全来源。修改 FR-09 | 2026-10-13 | U9（方案设计 OI-3） |
| D20 | 面板端口默认 2053，可以修改 | 2026-10-13 | U9（方案设计 OI-1） |
| D21 | vps-proxy-setup 安装 3X-UI v3.7.0 时带版本参数 `v3.7.0`，并在安装后用 tag 中已校验的 `x-ui.sh` 替换 `/usr/bin/x-ui`。写入第 7.2 节 | 2026-10-13 | U10（验证计划 VO-3） |
| D22 | root 是管理账户，只能用 SSH 密钥登录（`PermitRootLogin prohibit-password`）。本工具不创建普通管理用户，不修改 sudo 配置，也不修改 root 的 `authorized_keys`。替代 D2 中"禁止 root 经 SSH 登录"和"日常使用普通 sudo 用户"两项 | 2026-10-20 | U11、U12 |
| D23 | Fail2ban 的 sshd jail 使用普通过滤模式（`mode = normal`），`maxretry` 固定为 5，不再作为参数。修改 D8 的过滤模式，替代 D15 | 2026-10-20 | U11、U12 |
| D24 | 加固前由管理员执行 `apt update && apt full-upgrade` 并重启，本工具不执行全量升级；M2 的使用说明写明这一顺序 | 2026-10-20 | U11、U12 |
| D25 | 本需求规格说明 v1.3、方案设计 v1.1、验证计划 v1.1 和详细设计 v0.2 经用户评审通过，U13 列出的四项解释确认。用审计会话编号区分新旧会话的做法仍须在 M2 核实（方案设计 DR-11） | 2026-10-20 | U13 |
| D26 | 正式支持和验收的架构为 x86_64。aarch64 作为参考：工具仍允许在 aarch64 上运行；它的虚拟机测试按需手动执行，发布前至少执行一次，结果放在附录，不作为验收和里程碑出口的条件。修改 D11 的架构部分 | 2026-10-20 | U14 |
| D27 | 执行顺序：全量升级并重启 → 加固并确认 → 调优（应用、重启、验证）→ 安装并配置 3X-UI → 调优的严格验证 → 重启后复核。调优的应用和重启在加固确认之后进行。理由和其他顺序的比较见第 7.3 节 | 2026-10-20 | U15 |

## 3. 角色与场景

| 角色 | 说明 |
|---|---|
| 管理员 | 唯一的操作者，熟练工程师，持有 SSH 私钥，以 root 登录（D22）。可能从固定管理出口登录，也可能从其他网络登录 |
| 服务商控制台 | 网页 VNC、串口控制台或救援模式，不经过 SSH 和 UFW，是最后的恢复入口 |
| 代理客户端 | 通过代理入站端口和订阅端口访问，来源 IP 不固定 |
| 互联网扫描者和攻击者 | 扫描公网端口，反复尝试 SSH 登录 |
| 配套仓库 | vps-tuning（网络调优）、vps-proxy-setup（以 3X-UI 为例部署代理） |

| 编号 | 场景 | 相关需求 |
|---|---|---|
| SC1 | 新机首次加固：管理员拿到新 VPS，先全量升级并重启（D24），再以 root 用密钥登录，在安装 3X-UI 之前执行加固 | FR-01～FR-10 |
| SC2 | 加固后部署代理：按约定安装 3X-UI 3.7.0，安装后加固状态仍然成立 | FR-07、FR-10、FR-11、第 7.2 节 |
| SC3 | 访问面板：管理员从任何网络先开 SSH 隧道，再在本机浏览器打开面板 | FR-07 |
| SC4 | 日常运维：以 root 用密钥登录，运行调优工具，系统自动安装安全更新 | FR-03、FR-09、第 7.3 节 |
| SC5 | 定期核对：只读检查配置有没有漂移 | FR-10 |
| SC6 | 失败与回退：应用中途失败、确认超时，或需要撤销加固 | FR-05、FR-12 |
| SC7 | 端口变化：增加或撤销代理入站、订阅端口 | FR-14 |

## 4. 功能需求

### FR-01 只读预检（P0）

应用变更前先做只读预检，任何一项不满足就不做变更，并以非零状态退出。至少检查：

- 平台在支持范围内：操作系统、版本、架构，PID 1 是 systemd（范围见 A-1）；
- 以 root 权限运行；
- 主机符合 FR-02 的新机定义；
- root 至少有一把可用的公钥（FR-03）；
- 第 6 节的输入格式有效，且互不冲突；
- 能读取 sshd 当前的生效配置；
- 包管理器没有被占用，能从官方仓库安装所需软件包。

验收：

- 已知前提：支持的新机，输入有效。执行预检后，退出码为 0；系统文件、服务状态和防火墙规则与执行前一致（比对前后文件摘要、`ufw status` 和相关服务状态）。
- 已知前提：任一检查不满足。执行预检或应用时，输出具体原因，退出码非零，系统没有任何变更。

### FR-02 新机判定（P0）

新机同时满足以下条件：

- 没有安装 3X-UI 或 Xray（没有 `x-ui.service`，也没有 `/usr/local/x-ui`）；
- 没有安装 Docker 等会绕过 UFW 的容器运行时；
- UFW 未安装或未启用；
- Fail2ban 未安装，或者只有发行版默认配置；
- 本工具没有在这台主机上执行过，或者已经完全回滚。

已经安装 vps-tuning 不影响判定，因为它不修改 SSH、UFW 和 Fail2ban。它在应用时预先创建 `x-ui.service` 的 drop-in（`/etc/systemd/system/x-ui.service.d/`）；只有 drop-in、没有单元文件时，systemd 认为该单元不存在，所以不算安装了 3X-UI（Debian 13 的 systemd 257 已核实，见详细设计第 8.6 节；另两个平台在 VT-90 中核实）。不满足条件时拒绝执行，并提示"存量主机不在支持范围内"（D6）。

验收：分别准备以下四种主机，应用均被拒绝且没有任何变更：已安装 3X-UI；UFW 已启用且有自定义规则；存在自定义 Fail2ban jail；已安装 Docker。

### FR-03 管理账户与免密 sudo 账户（P0）

- 管理账户是 root，只能用 SSH 密钥登录（D22）。本工具不创建账户，不修改 sudo 配置，也不修改 root 的 `authorized_keys`。
- 应用前，root 的 `authorized_keys` 中至少有一把可用的公钥：是不带选项的单纯公钥行，能被 `ssh-keygen` 解析，算法被 sshd 接受。带选项的行不计入，例如 cloud-init 禁用 root 登录时写入的 `command=` 前缀，带这种前缀的密钥无法登录。不满足时预检失败，提示管理员先为 root 配置公钥。
- 除 root 外，任何可以经 SSH 登录的账户都不得拥有免密 sudo（`NOPASSWD`）。如果镜像自带默认用户（例如 cloud-init 写入了免密 sudo 规则），预检要报告出来；应用时禁止该账户经 SSH 登录，它的 sudo 规则不改动（D13）。

验收：

- 应用前后，root 的 `authorized_keys` 和 sudoers 文件的摘要都不变。
- 对每个有有效登录 shell 且有 `authorized_keys` 的非 root 账户执行 `sudo -l -U`；有免密规则的账户，从外部用它的密钥登录会失败。
- root 的 `authorized_keys` 中没有公钥，或者只有带选项的行时，预检失败，系统没有任何变更。

证据状态：前两条来自 D22。D13 原本是为了防止密钥被盗后直接拿到 root；D22 之后，它的作用是只保留 root 这一条特权登录路径，因为镜像默认用户的密钥可能与 root 的不同，例如由服务商注入（推断）。处置方式仍按 D13。

### FR-04 SSH 认证收紧（P0）

最终生效值以 `sshd -T` 的输出为准。要用 `-C` 分别以 root 和被禁止登录的账户（D13）的身份评估，才能覆盖 `Match` 块：

| 选项 | 最终值 |
|---|---|
| `permitrootlogin` | `prohibit-password`，`sshd -T` 显示为 `without-password`（D22） |
| `passwordauthentication` | `no` |
| `kbdinteractiveauthentication` | `no` |
| `pubkeyauthentication` | `yes` |
| `port` | `22`，IPv4/IPv6 监听不变 |
| `allowtcpforwarding` | `yes` 或 `local`，保证 SSH 隧道可用（FR-07） |

- sshd 对同一个关键字只取第一个读到的值。镜像自带的 `sshd_config.d` 片段（例如 cloud-init 写入的 `PasswordAuthentication yes`）不得让最终值偏离上表。
- 修改后先用 `sshd -t` 检查语法，通过后再重新加载；检查失败时不重新加载，并恢复原配置。
- 上表以外的 sshd 选项保持发行版默认，不额外收紧（D10、NFR-06）。

验收：

- 上表各项的 `sshd -T` 输出符合要求。
- 在测试镜像中预置 `sshd_config.d/50-cloud-init.conf`，写入 `PasswordAuthentication yes`。加固后 `passwordauthentication` 仍为 `no`。
- 从外部用 root 密码、其他账户的密码登录，以及被禁止登录的账户用它的密钥登录，全部失败；用 root 密钥登录成功。

### FR-05 防锁死与确认（P0）

- 应用开始前，管理员必须明确确认两件事：已经保留当前 SSH 会话；服务商控制台或救援模式可用。
- 启用防火墙之前，必须已经放行 22/tcp。
- SSH 和防火墙变更后进入"待确认"状态。确认必须在一个**新的** SSH 会话中完成：以 root 的密钥登录后执行确认。这样确认就证明了新配置下 root 的密钥登录可用。在发起应用的会话中执行的确认，以及从其他账户经 sudo 或 su 执行的确认，都要拒绝。
- 在确认时限内没有完成确认，SSH、UFW 以及本次的其他变更自动恢复到应用前的状态。时限可以配置：默认 10 分钟，允许 3～60 分钟（D18）。
- 自动恢复不得依赖发起应用的那个 SSH 会话；该会话断开不影响恢复。
- 待确认期间如果主机重启，重启后管理员仍能用应用前的方式或新方式之一登录（P1）。
- 不锁定 root 账户，不修改 root 密码，不禁用控制台登录，保留服务商控制台这个救援入口。

验收：

- 应用完成后，在时限内从新会话完成确认：状态变为"已应用"，恢复计划被取消。
- 应用完成后不确认：时限到达后自动恢复；原登录方式可用；`sshd -T` 输出和 UFW 状态回到应用前。
- 应用完成后断开发起会话：未确认时仍按时限恢复；已确认时不恢复。
- 应用中途任一步失败：已做的变更全部回退，退出码非零。

### FR-06 UFW 入站最小化（P0）

- 默认策略：拒绝入站，允许出站，拒绝转发；启用 IPv6 支持（`/etc/default/ufw` 中 `IPV6=yes`）。
- 入站规则集合与声明完全一致：
  - 22/tcp：所有来源，IPv4 和 IPv6；
  - 代理入站端口：所有来源，协议和地址族按声明；
  - 订阅端口（有声明时）：所有来源，地址族按声明；
  - 面板端口：不放行（D16）；
  - 不存在其他 allow 规则。80/tcp 不开放（D14）。
- 地址族以声明为准。按 D14，代理入站和订阅端口与现行流程的 `ufw allow <端口>/tcp` 一致，同时放行 IPv4 和 IPv6。

验收：

- `ufw status verbose` 中的默认策略和规则与声明逐项一致，没有多余规则。
- 用临时程序监听 `0.0.0.0:<面板端口>`，从外部任何来源连接都失败。这验证的是 UFW 这一层；面板只监听回环地址是另一层，由 vps-proxy-setup 负责。
- 从任意来源连接 22/tcp 成功。
- 未声明的端口即使有进程在监听，从外部也连不上。

### FR-07 面板访问路径（P0）

- 面板端口在安装 3X-UI 之前确定，作为约定值交给 vps-proxy-setup，由它通过 3X-UI 安装器的 `XUI_PANEL_PORT` 传入（第 7.2 节）。
- 面板只有一条访问路径：经 SSH 隧道 `ssh -L 8443:127.0.0.1:<面板端口> root@<VPS>` 访问 VPS 的本机回环地址（D16）。
- 隧道到达 VPS 后访问的是本机回环地址，UFW 无条件放行回环流量，所以不需要任何面板端口规则。
- 面板只监听 127.0.0.1、是否给面板配证书，由 vps-proxy-setup 负责（第 11.1 节）。

验收：在测试环境中用临时程序监听 `127.0.0.1:<面板端口>`，从任意外部网络经隧道都能访问；不开隧道时，从外部无法连接面板端口。

### FR-08 Fail2ban（只保护 SSH）（P0）

按 D8 的样例、U5 的新机流程和 D23，最终生效值如下：

| 项 | 值 |
|---|---|
| sshd jail | 启用 |
| `port` / `protocol` | `22` / `tcp` |
| `backend` | `systemd` |
| `journalmatch` | `_SYSTEMD_UNIT=ssh.service + _COMM=sshd + _COMM=sshd-session` |
| `mode` | `normal`（D23） |
| `banaction` / `banaction_allports` | `nftables` / `nftables[type=allports]` |
| `bantime` / `findtime` / `maxretry` | `1d` / `10m` / `5`（D23） |
| `bantime.increment` / `bantime.maxtime` / `bantime.rndtime` | `true` / `4w` / `10m` |
| `ignoreself` / `ignoreip` | `true` / `127.0.0.1/8 ::1` |
| `usedns` | `no` |
| `dbpurgeage`（fail2ban.local） | `30d` |

- 只写本工具自己的配置文件（`jail.d/` 下的独立文件和 `fail2ban.local`），不修改发行版的 `jail.conf`、`fail2ban.conf`。
- 不给代理入站、订阅或面板端口设 jail；不启用 3X-UI 的 IP Limit（`3x-ipl`）。
- 过滤模式取 `normal`（D23）。上游的 sshd 过滤器在 `normal` 模式下，把认证完成前断开的连接（`Connection closed/reset … [preauth]`、`Disconnected … [preauth]`）标为不计数，`ddos` 和 `aggressive` 模式则计为失败（已核实 fail2ban 1.0.2 和 1.1.0 的 `filter.d/sshd.conf`）。U11 中管理出口被封，就是这类断开造成的。代价是：密码登录关闭后，只针对 root 的扫描大多只留下这类断开日志，`normal` 模式基本不计数，主要封禁的是尝试不存在用户名的来源（推断，M3 实测）。这与第 1 节对 Fail2ban 的定位一致：它是补充防线。
- 显式安装 `nftables` 和 `python3-systemd`，不依赖软件包的推荐依赖。只执行 `apt install fail2ban` 时：Debian 12 上 `python3-systemd` 只是推荐依赖；`nftables` 在 Debian 12 和 13 上都是 `nftables | iptables` 二选一的推荐依赖，而 UFW 已经装上了 `iptables`，所以 `nftables` 可能不会被安装。
- 必须处理以下平台差异（证据见第 10.1 节）：
  - Debian 12 可能没有 rsyslog 和 `/var/log/auth.log`，发行版默认的 sshd jail 没有设置 `backend`；
  - Ubuntu 24.04 初始版本中的 fail2ban 1.0.2-3 在 Python 3.12 下会报错，需要 noble-updates 中的 1.0.2-3ubuntu0.1 或更新版本；
  - Debian 13 发行版默认的 `journalmatch` 不含 `sshd-session`。

验收（沿用 U5 的 11 步验证顺序）：

- `fail2ban-client -t` 通过；fail2ban 服务为 enabled 且 active；`fail2ban-client ping` 有响应；`fail2ban-client status sshd` 显示 jail 在运行。
- `fail2ban-client get sshd` 读到的 `bantime`、`findtime`、`maxretry`、`ignoreip`、`journalmatch` 与上表一致。
- 运行 `fail2ban-regex systemd-journal 'sshd[mode=normal]'`（`--journalmatch` 与上表相同）。要结合 journal 里有没有失败登录样本来判断结果，不能只因为匹配数为 0 就断定成功或失败。
- 执行 `fail2ban-client set sshd banip 203.0.113.123`（文档保留地址）后，`nft list table inet f2b-table` 的对应集合含该地址；unban 后地址消失。测试中途失败或被中断时，也要确保测试地址被解封。整个过程中第二个 SSH 会话都能登录。
- 在测试环境中，从测试来源制造超过 `maxretry` 次的失败登录，该来源被封禁，封禁时长符合 `bantime`。这一条是真实触发的证据，上一条只证明动作链可用。
- root 用正确密钥正常登录，不会被计为失败；ssh-agent 中有多把密钥时，以及客户端在认证完成前断开附加连接时（U11 的情形），也都不计为失败。证据状态：过滤器在 `normal` 模式下不计数认证前断开，已对照上游源码核实；实际计数仍需实测（见 R-3）。

### FR-09 自动安全更新（P0）

- 安装并启用 unattended-upgrades，只自动安装以下来源的软件包（D19）：
  - Debian：安全仓库，以及稳定版小版本更新（`label=Debian`，与 Debian 默认一致）；
  - Ubuntu：`-security`，以及 ESM 的安全来源（未附加 Ubuntu Pro 时不起作用）。
- 启用 APT 周期任务：每天更新索引，每天执行无人值守升级。
- 不自动重启（D12）；需要重启时由 FR-10 报告。
- 不改动其他软件源配置。

验收：

- `apt-config dump` 中 `APT::Periodic::Update-Package-Lists` 和 `APT::Periodic::Unattended-Upgrade` 都是 `"1"`。
- `apt-daily.timer` 和 `apt-daily-upgrade.timer` 均为 enabled 且 active。
- `unattended-upgrade --dry-run --debug` 输出的允许来源与上述来源一致，不含 `-updates`、`-backports` 或其他来源。
- `Unattended-Upgrade::Automatic-Reboot` 为 `false`。

证据状态：v1.0 规定只装安全来源，D19 为 Debian 增加了稳定版小版本更新。Debian 和 Ubuntu 的默认来源、`no-dsa` 的含义见第 10.1 节。

### FR-10 只读验证（P0）

- 逐项核对 FR-03 至 FR-09 的最终状态，以及第 7 节约定的边界，例如 UFW 没有多余规则、不存在 `3x-ipl` jail、`jail.conf` 没有被修改。
- 只读：不修改任何文件、服务或规则。
- 输出逐项结果，不输出秘密。全部通过时退出码为 0，有不符合项时非零。
- 安装 3X-UI 后可以重复执行，用来发现漂移，例如误用 3X-UI 防火墙菜单新增了 2053、2096、80、443 的规则。
- 存在待重启标记（`/var/run/reboot-required`）时，以警告级别报告。

验收：

- 加固后立即执行，通过；重启后执行，通过。
- 按第 7.2 节安装 3X-UI 3.7.0 后执行，通过。
- 人为执行 3X-UI 防火墙菜单的"安装防火墙"，或启用 IP Limit，之后执行：报告具体漂移项，退出码非零。
- 执行前后系统状态摘要一致。

### FR-11 与 3X-UI v3.7.0 共存（P0）

- 按第 7.2 节约定的方式安装 3X-UI v3.7.0 后，FR-04、FR-06、FR-08 的最终状态不变。约定方式是：带版本参数安装，并替换 main 分支的菜单脚本（D21）；设置 `XUI_ENABLE_FAIL2BAN=false`，预先指定 `XUI_PANEL_PORT`；不使用 3X-UI 的防火墙菜单和 BBR 菜单。
- 其他 3X-UI 版本要重新验证后，才能说兼容（R-2）。

验收：在隔离环境中依次执行"加固 → 安装 3X-UI v3.7.0（固定 commit `f727d04`）→ 验证 → 重启 → 验证"，全部通过。

### FR-12 手工回滚（P1）

- 把本工具修改过的文件和规则恢复到应用前的内容，并恢复相关服务的状态。
- 回滚不涉及 root 的 `authorized_keys`（本工具不修改它），回滚后 root 仍能用密钥登录。
- 回滚前同样执行防锁死检查：22/tcp 可达，恢复后的登录方式可用。
- 只处理本工具拥有的对象，不碰 3X-UI 和 vps-tuning 的文件。

验收：依次执行"应用 → 确认 → 回滚"后，SSH 生效配置、UFW 状态、Fail2ban 和 unattended-upgrades 的配置都与应用前一致（比对前后摘要）；root 仍能用密钥登录。

### FR-13 状态与变更记录（P1）

记录每次应用的时间、工具版本、修改过的文件及其前后摘要、输入参数（不含秘密），供验证和回滚使用。状态文件只有 root 可读。

验收：检查状态文件的内容和权限，不含密码和私钥。

### FR-14 端口变更（P1）

代理入站或订阅端口变化时（增加或撤销），通过本工具更新规则，并同样执行防锁死流程。不提供开放面板端口的操作（D16）。

验收：变更后 FR-06 的验收全部通过；变更过程中 SSH 不中断；声明的公开端口与面板端口或 22 相同时，拒绝变更。

## 5. 非功能需求

| 编号 | 优先级 | 要求 | 验收或评估方法 |
|---|---|---|---|
| NFR-01 | P0 | 秘密处理：不接收、不生成、不保存私钥和密码；公钥只记录指纹。输出、日志和状态文件中不出现秘密 | 静态检查；执行后扫描日志和状态文件 |
| NFR-02 | P0 | 防锁死：任何时刻至少保留一条可用的 SSH 登录路径 | 应用、确认、回滚、端口变更的全部测试用例中，从外部持续探测 22/tcp，始终可达 |
| NFR-03 | P1 | 幂等：在已经符合要求的主机上再次应用，不产生变更；验证可以反复执行 | 再次应用前后的文件摘要一致 |
| NFR-04 | P0 | 平台：Debian 12、Debian 13、Ubuntu 24.04 LTS；x86_64；原生 systemd 主机（A-1）。aarch64 作为参考（D26） | x86_64 上 3 组隔离虚拟机完整生命周期测试通过；aarch64 的 3 组按需执行，结果只作参考 |
| NFR-05 | P0 | 依赖：只使用目标系统官方仓库的软件包，不添加第三方软件源 | 检查执行前后的 APT 源配置 |
| NFR-06 | P0 | 便利性：日常管理方式与加固前相同，仍以 root 用密钥登录（D22），只是不能再用密码登录。不改 SSH 端口，不要求 SSH 来源固定，不引入 SSH 二次验证；从任何网络都能经隧道访问面板，不需要维护来源地址清单 | 按 SC3、SC4 逐步走查 |
| NFR-07 | P1 | 发布完整性：发布资产附带 SHA-256，安装前校验（沿用 vps-tuning 的做法） | 公开下载回验 |
| NFR-08 | P0 | 不越界：不写入 vps-tuning 管理的 17 项 sysctl 和 qdisc；不修改 3X-UI 的文件；不修改发行版的 Fail2ban 主配置文件 | 应用前后对这些对象做摘要比对 |

## 6. 输入数据

| 输入 | 说明 | 校验 |
|---|---|---|
| 面板端口 | 3X-UI 面板端口，默认 2053（D20），安装 3X-UI 前确定；只用于约定和校验，不开放（D16） | 1–65535；不等于 22；不与公开端口重复 |
| 代理入站端口 | 端口、协议（tcp/udp）、地址族 | 1–65535；不等于 22；不与面板端口重复 |
| 订阅端口 | 可选 | 同代理入站端口 |
| 确认时限 | 默认 10 分钟（D18） | 整数分钟，3～60 |

root 的公钥不是输入：预检读取 root 现有的 `authorized_keys`（FR-03）。Fail2ban 的 `maxretry` 固定为 5，不是输入（D23）。

## 7. 跨仓库约定

### 7.1 对象归属

| 对象 | 归属仓库 | 其他仓库的限制 |
|---|---|---|
| SSH 服务配置 | vps-hardening | 其他仓库不修改 |
| UFW 规则 | vps-hardening | vps-proxy-setup 只声明端口，不直接改规则；不使用 3X-UI 防火墙菜单 |
| Fail2ban | vps-hardening | 安装 3X-UI 时设 `XUI_ENABLE_FAIL2BAN=false`；不启用 IP Limit |
| 自动安全更新 | vps-hardening | — |
| 网络 sysctl、qdisc、BBR | vps-tuning | 不使用 3X-UI 的 BBR 菜单。它写入的 `/etc/sysctl.d/99-bbr-x-ui.conf` 排在调优配置之后，会覆盖调优值 |
| 3X-UI/Xray 安装、面板 TLS、订阅、代理入站 | vps-proxy-setup | — |

### 7.2 与 vps-proxy-setup 的约定（3X-UI v3.7.0）

下表左列来自上游 v3.7.0 源码（证据见第 10.1 节）：

| 3X-UI v3.7.0 的行为 | 约定 |
|---|---|
| 运行 `install.sh` 时不带版本参数，会解析上游的 latest 发布，安装最新版 | 带版本参数 `v3.7.0`（D21） |
| 无论带不带版本参数，`install.sh` 都从上游 main 分支下载 `x-ui.sh`，安装为 `/usr/bin/x-ui`（管理菜单脚本）。菜单的行为因此取决于安装当天的 main 分支 | 安装后用 tag `v3.7.0` 中按第 10.1 节摘要校验过的 `x-ui.sh` 替换 `/usr/bin/x-ui`（D21） |
| 没有设置 `XUI_ENABLE_FAIL2BAN` 时，`install.sh` 会调用 `x-ui setup-fail2ban`：安装 fail2ban 和 nftables；用 sed 修改 `/etc/fail2ban/jail.conf` 默认段的 `backend`，以及 `fail2ban.conf` 的 `allowipv6`；写入 `3x-ipl` jail；最后重启 fail2ban | 安装时设 `XUI_ENABLE_FAIL2BAN=false` |
| 没有设置 `XUI_PANEL_PORT` 时，在 1024–62000 中随机选面板端口 | 设为加固时约定的面板端口 |
| 防火墙菜单的"安装防火墙"会放行 ssh、80、443、2053、2096，并执行 `ufw --force enable` | 不使用；端口变更按 FR-14 处理 |
| BBR 菜单写入 `/etc/sysctl.d/99-bbr-x-ui.conf` | 不使用（归 vps-tuning） |
| `3x-ipl` 的封禁动作基于 iptables，只豁免 SSH 端口和面板端口；SSH 端口只从 `/etc/ssh/sshd_config` 主文件读取，读不到时按 22 处理 | 不启用 IP Limit。因为 SSH 保持 22（D1），端口读取偏差在本约定下不会发生 |

端口约定（D14）：

| 端口 | 允许来源 | 地址族 |
|---|---|---|
| 22/tcp | 所有来源 | IPv4 + IPv6 |
| 443/tcp（VLESS + REALITY） | 所有来源 | IPv4 + IPv6 |
| 订阅端口/tcp（3X-UI 默认 2096） | 所有来源 | IPv4 + IPv6 |
| 面板端口/tcp | 不开放，只经 SSH 隧道访问；面板只监听 127.0.0.1，由 vps-proxy-setup 设置（D16） | — |
| 80/tcp | 不开放。证书由 vps-proxy-setup 用 Cloudflare API Token 走 DNS-01 签发；REALITY 本身不需要证书 | — |
| REALITY 回落等本机端口 | 不开放，只监听 127.0.0.1 | — |

下面一条属于 vps-proxy-setup，登记在这里以免遗漏：Cloudflare API Token 会保存在 VPS 上，VPS 一旦被攻破，攻击者就能用它修改 DNS 记录。因此 Token 只授予签发证书所需的最小权限，例如只能编辑单个 Zone 的 DNS。

### 7.3 与 vps-tuning 的约定

- root 仍以密钥登录（D22），运行 `dvt` 的方式不变。v1.2 中"禁止 root 登录后要先执行 `sudo -i`"的文档更新事项不再需要；如果 vps-tuning 的项目备忘里记着这一项，应一并撤销。
- UFW 自带的 `/etc/ufw/sysctl.conf` 会设置 `rp_filter`、`accept_redirects` 等参数，与 vps-tuning 的 17 项受管 sysctl 没有重叠（已核对 Debian 12 的 ufw 0.36.2-1 和 Debian 13 的 0.36.2-9）。本仓库不得修改该文件，以免与那 17 项重叠。
- 执行顺序（D27）如下，理由见其后各条：

  ```text
  apt update && apt full-upgrade → 重启
  → 加固：vps-hardening preflight → apply → 从新会话 confirm
  → 调优：dvt preflight → dvt apply → 重启 → dvt verify
  → 安装并配置 3X-UI（vps-proxy-setup，第 7.2 节）
  → 调优的严格验证：env REQUIRE_PROXY_SERVICE=1 PROXY_SERVICE_UNITS='x-ui.service' dvt verify
  → 重启后复核：vps-hardening verify、调优的严格验证、代理客户端连接
  ```

- 全量升级和重启由管理员在加固前执行，本工具不执行（D24）：这超出基础加固的范围（D10），而且耗时不可控，放进应用流程会挤占确认时限。
- 调优的应用和重启要在加固确认之后进行：待确认期间重启会自动恢复（FR-05），加固随之撤销。
- 加固在前：D6 要求加固在安装 3X-UI 之前完成；而且越早加固，密码登录开放的时间越短。测试 VPS 重装后密码登录是开启的，到全量升级前的约 8 小时内有 467 次密码失败；场景 A 恢复密码认证后约 6 秒就出现密码尝试（详细设计第 8.6 节）。
- 调优在 3X-UI 之前：这是 vps-tuning 文档中的正常路径，也是它每台 VPS 的验收顺序。调优应用时预先创建 `x-ui.service` 的 `LimitNOFILE` drop-in，之后安装的 3X-UI 直接按这个限制启动，不需要额外重启（vps-tuning 的 `docs/usage.md`、`docs/design-scope.md`、`docs/validation.md`）。代理在不再变动的基础上安装和验收，出了问题容易定位。
- 3X-UI 在最后：安装时 UFW 已经启用，`install.sh` 在非交互模式下让面板监听所有地址（第 10.1 节），面板端口在改为只监听 127.0.0.1 之前也不对外开放（D16）。
- 另外两种顺序都可行，但不推荐：
  - 加固 → 3X-UI → 调优：vps-tuning 写明，应用时 x-ui 已在运行的，重启服务或主机后再做严格验证，而调优本来就要重启。缺点是代理上线后又改网络配置，代理要验收两次，出了问题难以分清是调优还是代理配置。只在需要比较调优前后的代理性能时才值得这样做；这属于测量研究，不是默认步骤。
  - 调优 → 加固 → 3X-UI：两者互不修改对方的对象（NFR-08），调优预先创建的 drop-in 也不影响新机判定（FR-02）。缺点是密码登录多开放一次调优和一次重启的时间。
- 置信度：加固在前、3X-UI 在最后为高，依据是 D6 的硬约束和测试 VPS 上的扫描证据；调优在 3X-UI 之前为中，依据是 vps-tuning 的文档和验收顺序，三个仓库按这个顺序的组合尚未实测（VT-90）。

## 8. 范围外（P3）

| 事项 | 理由 | 重新纳入的条件 |
|---|---|---|
| 接管存量主机 | D6 | 用户另行决定 |
| 修改 SSH 端口，限制 SSH 来源 | D1 | — |
| 面板经 `ADMIN_CIDRS` 直连 | D16；见第 11.1 节和 R-10 | 用户提出直连需要，并重新评估 R-10 |
| SSH 二次验证、`AllowUsers` 等额外的 sshd 收紧 | 用户没有要求，而且会增加日常负担 | 用户提出 |
| 创建普通管理用户、要求 sudo 密码 | D22 | 用户另行决定 |
| 系统全量升级和重启 | 由管理员在加固前执行（D24） | — |
| 给代理、REALITY、订阅或面板端口设 Fail2ban jail | REALITY 会把未通过认证的探测转发给伪装目标，不产生可靠的失败日志，加规则只会误封（推断） | 出现可复现的滥用证据 |
| 基于 UFW 拦截日志封禁端口扫描来源 | 扫描器会频繁更换 IP，作用有限 | 同上 |
| 3X-UI IP Limit（`3x-ipl`） | D8 要求保持关闭；v3.7.0 启用时会修改 `jail.conf`（见 R-6） | 用户决定启用，并完成共存评估 |
| CrowdSec 等替代方案 | 用户没有要求 | — |
| CIS 全量合规、入侵检测、AppArmor/SELinux 策略、审计系统 | D10 | — |
| 额外的内核 sysctl 加固 | 用户没有要求；网络 sysctl 归 vps-tuning | 用户提出 |
| Docker 或其他容器主机 | Docker 会绕过 UFW | — |
| 云服务商的安全组或防火墙 | 在 VPS 外面，本工具管不到 | 只在文档中提醒 |
| 从控制端远程批量执行 | D7 | — |
| Ubuntu 26.04 及其他平台 | 与 vps-tuning 保持一致（A-1） | vps-tuning 纳入后 |

## 9. 假设

| 编号 | 假设 | 状态 |
|---|---|---|
| A-1 | 发行版范围与 vps-tuning 一致：Debian 12/13、Ubuntu 24.04 LTS。架构为 x86_64，aarch64 作为参考（D26）；用户的 VPS 主要是 x86_64（U14）。Ubuntu 26.04 LTS 已于 2026-04-23 发布，首版不纳入 | 已确认（D11）；架构部分待评审（D26） |
| A-2 | 管理员在自己的电脑上生成密钥对，只把公钥交给工具 | 假设 |
| A-3 | 服务商提供控制台或救援模式，并且 root 密码可以在控制台使用 | 假设，应用前由管理员确认（FR-05） |
| A-4 | 应用前 root 已经能用 SSH 密钥登录 | U5、U11 证实了这种情况，预检检查 root 的公钥（FR-03）。用户使用的服务商都在管理页面提供绑定 SSH 密钥的功能（U14）。只能用带 sudo 的镜像默认用户登录的主机，要先手工为 root 配置公钥 |
| A-5 | 只有一名管理员 | 假设 |
| A-6 | 自动安全更新后不自动重启 | 已确认（D12） |
| A-7 | 端口约定见第 7.2 节 | 已确认（D14、D16） |

## 10. 证据与风险

### 10.1 已核实的事实（2026-10-13）

| 事实 | 来源 |
|---|---|
| 3X-UI v3.7.0 的 tag 指向 commit `f727d04f6522bb94a8fb52e8352fdcafb51c11e1`，Release 发布于 2026-08-24T13:08:28Z。`install.sh` 的 SHA-256 为 `a7f4fedcea3abe8987508d00f29834b8872e4e4e5059159eb19460d474b37cdc`，`x-ui.sh` 的 SHA-256 为 `cfabcd4af35a3646c374ea0ccba5178f4c0d3135f699277fc8d8b810158e85c0` | GitHub API；该 tag 的 raw 文件 |
| 第 7.2 节列出的 v3.7.0 行为 | v3.7.0 的 `install.sh`（`setup_fail2ban`、面板端口选择）和 `x-ui.sh`（`setup_fail2ban_iplimit`、`create_iplimit_jails`、`install_firewall`、`enable_bbr`） |
| 3X-UI 最新版是 v3.10.0（2026-10-12）。从 v3.9.0 起，IP Limit 改为写入 `jail.d/3x-ipl-backend.conf`，不再用 sed 修改 `jail.conf` | GitHub Releases；v3.9.0 和 v3.10.0 的 `x-ui.sh` |
| OpenSSH 版本：Debian 12 为 9.2p1，Debian 13 为 10.0p1，Ubuntu 24.04 为 9.6p1 | sources.debian.org；Launchpad |
| OpenSSH 从 9.8 起默认启用 `PerSourcePenalties`，三个平台中只有 Debian 13 具备 | [OpenSSH 9.8 发布说明](https://www.openssh.org/txt/release-9.8) |
| fail2ban 默认配置：Debian 12（1.0.2-2）的 `defaults-debian.conf` 只启用 sshd jail，没有设置 `backend`。Debian 13（1.1.0-8）默认使用 nftables，sshd jail 的 `backend=systemd`，`journalmatch` 为 `_SYSTEMD_UNIT=ssh.service + _COMM=sshd` | Debian 源码包 |
| Ubuntu 24.04 初始版本的 fail2ban 1.0.2-3 在 Python 3.12 下报错，noble-updates 中的 1.0.2-3ubuntu0.1 修复了这个问题（LP #2055114） | Ubuntu 软件包变更日志 |
| 如果某个软件包升级时会出现配置文件提示，unattended-upgrades 会跳过它，并记录 "needs to be upgraded manually"（设置了 `--force-confold` 或 `--force-confnew` 时例外） | unattended-upgrades 2.12 源码 |
| UFW 默认的 `sysctl.conf` 不包含 vps-tuning 的 17 项受管键 | Debian ufw 0.36.2-1、0.36.2-9 源码 |
| UFW 的 `before.rules` 无条件放行回环接口（`-A ufw-before-input -i lo -j ACCEPT`），所以经 SSH 隧道访问本机端口不受 UFW 入站规则影响 | Debian ufw 0.36.2-9 源码 |
| fail2ban 的依赖：Debian 12（1.0.2-2）把 `python3-systemd` 和 `nftables \| iptables` 都列为推荐依赖；Debian 13（1.1.0-8）把 `python3-systemd` 列为必需依赖，`nftables \| iptables` 仍是推荐依赖 | Debian 源码包 `debian/control` |
| 3X-UI v3.7.0 的 `x-ui.sh` 自带"SSH 端口转发"菜单：用 `x-ui setting -listenIP 127.0.0.1` 让面板只监听回环地址，并提示用 `ssh -L` 访问。面板已经配置证书时，这个菜单直接认定面板是安全的。也就是说，上游把"配置证书"和"只监听回环 + 隧道"当作保护面板的两种并列方式 | v3.7.0 `x-ui.sh` 的 `SSH_port_forwarding` |
| 3X-UI v3.7.0 的会话 Cookie 名固定为 `3x-ui`，`Path` 是面板的 WebBasePath。多台面板只要 WebBasePath 不同，同时经 localhost 隧道访问也不会互相覆盖登录状态 | v3.7.0 `internal/web/web.go` |
| unattended-upgrades 的默认来源：Debian 12（2.9.1+nmu3）和 Debian 13（2.12）为 `label=Debian`（稳定版小版本更新）和两条 `Debian-Security` 来源；Ubuntu 为发布仓库、`-security` 和两条 ESM 安全来源。apt 配置中的列表只能用 `#clear` 清空，后读到的文件只会追加 | unattended-upgrades 源码包的 `data/50unattended-upgrades.*`；apt.conf(5) |
| Debian 安全团队把低危漏洞标为 `no-dsa`，不发安全公告，这类修复可能随稳定版小版本更新发布 | Debian 安全追踪器说明 |
| Ubuntu 24.04 的 fail2ban 属于 universe 仓库，1.0.2-3ubuntu0.1 发布在 noble-updates，不在 noble-security。Canonical 只对附加 Ubuntu Pro 的主机承诺 universe 软件包的安全维护 | Launchpad 发布记录；Ubuntu ESM 页面 |
| 3X-UI v3.7.0 的 `install.sh`：不带版本参数时解析 latest 发布；无论带不带版本参数，都从 main 分支下载 `x-ui.sh` 并安装为 `/usr/bin/x-ui`；非交互模式下 `XUI_SSL_MODE` 默认为 `none`，并强制面板监听所有地址 | v3.7.0 `install.sh` |

### 10.2 风险

| 编号 | 风险 | 影响 | 处理 |
|---|---|---|---|
| R-1 | 把管理员锁在服务器外 | 失去管理权 | FR-05、NFR-02；服务商控制台兜底 |
| R-2 | 3X-UI 版本漂移：基线 v3.7.0 已落后最新版 v3.10.0 三个版本，Fail2ban 的处理方式在 v3.9.0 已经改变 | 共存结论对新版本不成立 | FR-11 限定版本；安装时固定版本并替换菜单脚本（D21）；升级 3X-UI 前重新验证 |
| R-3 | 管理员封到自己：按 D8，`ignoreip` 只含回环地址。U11 中已经发生过一次：在 `aggressive` 模式、`maxretry = 3` 下，客户端在认证完成前断开的附加连接被计为失败。客户端配置错误时，管理出口也可能被封 1 天，并逐次延长 | 一段时间内无法经 SSH 登录，面板隧道也同时不可用（D16） | 改用 `normal` 模式、`maxretry = 5`（D23），认证前断开不再计数；用服务商控制台解封；按 FR-08 实测正常登录不会被计为失败（尚未实测） |
| R-4 | 镜像默认用户拥有免密 sudo | 多出一条 root 级的登录路径，它的密钥可能与 root 的不同 | FR-03；D13 |
| R-5 | 内核更新要重启才生效，不自动重启时待重启状态会一直累积 | 补丁装了但没有生效 | FR-10 报告待重启状态；管理员安排重启（D12） |
| R-6 | 如果在 v3.7.0 上启用 IP Limit，它会修改 `jail.conf`。以后 fail2ban 软件包更新若也改动这个文件，unattended-upgrades 会跳过 fail2ban 的更新 | Fail2ban 的安全更新停滞 | 列为范围外；FR-10 检测漂移 |
| R-7 | Ubuntu 上 fail2ban 属于 universe 仓库，修复版本发布在 noble-updates；Canonical 只对附加 Ubuntu Pro 的主机承诺 universe 的安全维护（已核实，第 10.1 节） | 自动安全更新覆盖不到 fail2ban 的后续修复 | 首版不处理（U9）；是否附加 Ubuntu Pro 由用户自行决定 |
| R-8 | 云服务商的安全组或防火墙在 VPS 外面 | 端口的实际可达性可能与 UFW 规则不一致 | 做外部连通测试；文档中提醒 |
| R-9 | 一个人维护三个仓库 | 发布和验证滞后 | 分阶段推进 |
| R-10 | 如果面板保留直连，而 `ADMIN_CIDRS` 填的是自己其他 VPS 的出口 IP（U5 的现行做法）：经这些 VPS 出网的任何流量都能连到面板端口；代理出故障时，面板也跟着连不上；VPS 退订后，IP 可能分配给别人，旧条目就成了漏洞 | 面板暴露给不该信任的来源 | 已由 D16 消除：面板只走 SSH 隧道 |
| R-11 | root 私钥泄露即失去整台主机：D22 之后，没有 sudo 密码这一层 | 主机被完全控制 | 用户接受（D22）。私钥在管理员自己的电脑上生成并设口令（A-2）；UFW 和 Fail2ban 不能缓解这一项 |

## 11. 待决事项

| 编号 | 事项 | 状态或建议 | 影响 |
|---|---|---|---|
| OD-1 | 平台范围 | 已决定（D11）；架构部分由 D26 修改，待评审 | NFR-04 |
| OD-2 | 自动安全更新后是否自动重启 | 已决定（D12） | FR-09 |
| OD-3 | 镜像默认用户有免密 sudo 时怎么处理 | 已决定（D13） | FR-03 |
| OD-4 | 确认时限的默认值 | 已决定（D18） | FR-05 |
| OD-5 | 端口约定 | 已决定（D14） | FR-06、第 7.2 节 |
| OD-6 | 面板的访问方式 | 已决定（D16），评估见第 11.1 节 | FR-06、FR-07、第 7.2 节 |

### 11.1 OD-6 评估：SSH 隧道还是"域名:面板端口"

| 维度 | 只走 SSH 隧道（推荐） | 域名:面板端口 + `ADMIN_CIDRS` |
|---|---|---|
| 暴露面 | 面板端口不出现在公网上；面板只监听回环地址、UFW 不放行，形成两层保护 | 面板端口对 `ADMIN_CIDRS` 开放；所有经这些地址出网的流量都算"可信来源"（R-10） |
| 认证 | 先过 SSH 密钥，再过面板密码和 2FA | 只有面板密码和 2FA |
| 加密 | SSH 加密，面板可以不配证书 | 必须给面板配域名证书，否则登录凭据以明文传输 |
| 管理出口变化 | 不受影响，从任何网络都能用 | 要先改 UFW 规则；改规则又得先登录 SSH |
| 依赖 | 只依赖 22/tcp 可达 | 依赖代理链路正常；代理坏了，面板也连不上，而这恰恰是最需要面板的时候 |
| 维护 | 没有地址清单要维护 | VPS 增购、退订时要维护地址清单 |
| 便利性 | 每次使用前先开隧道（一条命令，或写进 `~/.ssh/config`） | 直接在浏览器打开 |
| 上游支持 | 3X-UI v3.7.0 自带"SSH 端口转发"菜单（第 10.1 节） | 默认做法 |

结论（置信度：高）：面板只走 SSH 隧道。这样更安全，也不用维护 `ADMIN_CIDRS`，额外代价只是"先开隧道"这一步。用户已于 2026-10-13 确认（D16），首版不提供 `ADMIN_CIDRS` 直连（第 8 节）。以下两点属于 vps-proxy-setup 的设计：

- 面板只经隧道访问时，可以不给面板配证书，在 `http://127.0.0.1:<本地端口>/<WebBasePath>` 上访问。如果面板仍用域名证书，经 `127.0.0.1` 访问时浏览器会提示证书名称不匹配。
- 订阅端口仍然对公网开放，需要用 DNS-01 证书提供 HTTPS。

## 12. 验证方法

- **隔离虚拟机：** x86_64 上 3 组（每个平台一组）跑完整生命周期；aarch64 的 3 组按需执行，只作参考（D26）。完整生命周期：预检 → 应用 → 新会话确认 → 验证 → 重启 → 验证 → 按第 7.2 节安装 3X-UI v3.7.0 → 验证 → 回滚（P1）。
- **负面用例：** 不确认时自动恢复；发起会话断开；root 没有可用公钥；公开端口与面板端口或 22 冲突；不是新机；cloud-init 预置 `PasswordAuthentication yes`；误用 3X-UI 防火墙菜单造成漂移。
- **外部连通测试：** 从外部确认面板端口不可达、经隧道可达；测试期间持续探测 22/tcp。
- **真实 VPS：** 在真实 VPS 上验收需要用户单独授权。CI 和虚拟机的证据不能代替真实主机验收。

## 13. 追踪矩阵

| 来源 | 对应需求 |
|---|---|
| U1 | FR-04、FR-06、FR-08 |
| U2 | FR-04、FR-06、FR-07、FR-08、NFR-06 |
| U3 | FR-03、FR-07、FR-08、FR-09 |
| U4、D9 | FR-11，第 7.2 节 |
| U5 | FR-06、FR-08，第 7.2 节，R-10 |
| U6 | D11～D14，OD-4 |
| D6 | FR-02，第 8 节 |
| D7 | FR-01、FR-05、FR-10、FR-12 |
| D8、D15、D23 | FR-08 |
| D10 | 第 8 节 |
| D11、D26 | NFR-04 |
| D12 | FR-09、FR-10 |
| D13 | FR-03 |
| D14 | FR-06，第 7.2 节 |
| U7、D16 | FR-06、FR-07、FR-14，第 7.2 节，第 8 节 |
| U8、D17 | 文档状态（已批准 v1.0），D6 |
| U9、D18～D20 | 文档状态（已批准 v1.1），FR-05、FR-09，第 6 节，R-7 |
| U10、D21 | 文档状态（已批准 v1.2），FR-11，第 7.2 节，R-2 |
| U11、U12、D22～D24 | FR-01、FR-03～FR-05、FR-07、FR-08、FR-12、NFR-01、NFR-06，第 6 节、第 7.3 节、第 8 节，A-4，R-3、R-4、R-11 |
| U13、D25 | 文档状态（已批准 v1.3） |
| U14、D26 | 文档状态（v1.4 草稿），NFR-04，第 9 节（A-1、A-4），第 12 节 |
| U15、D27 | 文档状态（v1.4 草稿），FR-02，第 7.3 节 |
