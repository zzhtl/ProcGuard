# ProcGuard

Linux 桌面上的轻量进程管理器（Rust + egui）：按内存、CPU、磁盘 I/O 查看进程，结束、强制结束或重启它们。重点是不误杀：

- **核心进程运行时判定**：依据进程所属的 systemd unit、logind 会话是否在线、X11 窗口归属等事实，判断结束它是否会影响系统运行、在用的登录会话或对本机的远程访问。判定为核心的进程在界面上锁定，任何操作都不可用。
- **目标身份锁定**：进程以 `(pid, starttime)` 标识，发信号前先打开 pidfd 再核对身份，PID 被复用时信号不会落到新进程上。
- **执行前可见**：确认框列出将执行的每一步和风险提示；重启按进程来源选择 systemctl、docker、kubelet、snap / flatpak，或按原命令行重放。
- **按需提权**：只在目标需要 root 时逐次调用 `sudo -n` 或 `pkexec`，程序本身不接触密码。

## 运行环境

- **系统**：Linux，内核 ≥ 5.3（结束和重启依赖 `pidfd_open(2)`）。开发与测试环境为 Ubuntu 24.04、内核 7.0。
- **systemd 与 cgroup v2**：分类、保护和重启策略依据 cgroup 路径中的 unit 名和 `/run/systemd/sessions` 下的 logind 会话。非 systemd 系统上可以运行，但这部分规则不生效，保护范围会小很多。
- **图形**：X11 或 Wayland，需要 OpenGL（Mesa llvmpipe 软件渲染即可）。GL、X11、Wayland、xkbcommon 库都在运行时 dlopen，二进制只动态链接 libc、libm 和 libgcc_s。
- **中文字体**：通过 `fc-match :lang=zh-cn` 查找系统 CJK 字体，失败时尝试 Noto Sans CJK、文泉驿、Droid Sans Fallback 的常见路径。都找不到时中文显示为方框，状态栏会提示；Debian / Ubuntu 可安装 `fonts-noto-cjk`。
- **可选命令**（仅在对应操作时调用）：提权用 `sudo`（需免密）或 `pkexec`（需 polkit 认证代理）；重启用 `systemctl`、`systemd-run`、`docker`、`snap`、`flatpak`。

## 构建与运行

```bash
cargo build --release
./target/release/procguard
```

- 工具链由 `rust-toolchain.toml` 固定为 1.98.1（edition 2024），rustup 会自动安装；编译不需要任何系统 `-dev` 包。
- release 配置启用 fat LTO、`codegen-units = 1`、`panic = "abort"` 和 strip，x86_64 产物约 7.8 MiB。
- 渲染后端选 glow（OpenGL）而不是 eframe 默认的 wgpu，前者在 llvmpipe 等软件 GL 上轻得多；同时关闭了 eframe 的 `accesskit` 和 `links` 特性。

以普通桌面用户身份运行，需要 root 的单个操作会按需提权（见[提权](#提权)）。

## 使用

### 界面

- **搜索**：对名称、命令行、用户做不区分大小写的子串匹配，输入数字时也按 PID 前缀匹配。
- **分类**：左栏按分类筛选，每类显示进程数和私有内存合计。
- **排序**：点击表头；名称、PID、用户、类型首次点击升序，其余列降序。默认按"内存"降序。
- **详情**：单击一行，底部面板显示命令行、状态、线程数、已运行时长、是否依附终端、内存构成、cgroup、保护原因和重启方式。
- **操作**：详情面板或右键菜单中的"结束"（SIGTERM）、"强制结束"（SIGKILL）、"重启"。按钮不可用时，鼠标悬停显示原因；受保护进程的名称前有 🔒 并灰显。
- **状态栏**：进程数、整机 CPU、内存、交换、ProcGuard 自身的 CPU 与内存（悬停显示单轮采集耗时）、数据新鲜度、上次操作的结果。

每 2 秒采样一次，可暂停。右键菜单或确认框打开期间列表冻结，避免重新排序把光标下的行换成另一个进程；窗口最小化或被完全遮挡时停止采样。

### 列的口径

| 列 | 含义 |
|---|---|
| 内存 | 私有常驻内存 `RssAnon`：进程独占、未换出的物理内存，不含共享库和文件缓存，最接近结束该进程能释放的量 |
| 交换 | `VmSwap`，已换出到交换区的部分 |
| RSS | `VmRSS`，含共享库和共享内存，与 `top` 的 RES 一致；共享部分会在多个进程上重复计算 |
| CPU | 占**整机**的百分比（所有核心合计为 100%），而 `top` 默认按单核计；第二次采样后才有值 |
| 磁盘 I/O | `/proc/<pid>/io` 中 `read_bytes + write_bytes` 的速率（块设备层）。其他用户的进程读不到这个文件，若它属于系统服务或容器，改用该 cgroup 的 `io.stat`（只计物理设备，避免 dm、zram 等叠加设备重复计算），显示在该 unit 最早启动的进程上并以 `≈` 标注；`—` 表示无法获取 |

### 无界面模式

```bash
procguard --dump [--passes N]
```

采样 N 次（默认 2，间隔 1 秒；CPU 和 I/O 至少需要 2 次）后，把全部进程按分类排列、同类按私有内存降序，以 TSV 写到 stdout，列为 `pid ppid user category protect restart mem swap rss cpu io name cgroup cmdline`（cmdline 截断到 80 个字符）；每轮的进程数、采集耗时以及窗口检测是否可用写到 stderr。适合在某台机器上核对分类与保护结果：

```bash
# 列出受保护的用户态进程及原因
procguard --dump 2>/dev/null | awk -F'\t' 'NR==1 || ($5 != "-" && $4 != "内核线程")' | cut -f1,4,5,12
```

## 进程分类

按顺序判定，命中即止：

| 分类 | 规则 |
|---|---|
| 内核线程 | `stat` 的 flags 含 `PF_KTHREAD` |
| 核心系统 | 命中[核心进程保护](#核心进程保护)中任一规则 |
| 容器 | cgroup 路径属于 kubepods、`machine.slice`、docker 或 LXC，或 unit 为 `docker-*`、`libpod-*`、`cri-containerd-*` 开头的 `.scope` |
| 系统服务 | 不属于真人账号：位于 `system.slice` 或 `init.scope`；或所在 `user-<uid>.slice` 的 uid 小于 `UID_MIN`（如 gdm 登录界面）；或不在任何用户 slice 中且进程 uid 小于 `UID_MIN` |
| 应用程序 | 拥有顶层 X11 窗口（dock、desktop 类型除外），或位于 `app-*`、`snap.*` unit 中；Chromium / Electron（`--type=`）与 Firefox（`-contentproc`）的辅助进程随父进程归入应用程序 |
| 用户服务 | 用户 systemd 管理器（`user@<uid>.service`）下的 `.service` |
| 用户进程 | 其余 |

`UID_MIN` 取自 `/etc/login.defs`，缺省 1000。窗口归属优先使用 X-Resource 扩展（由 X server 根据客户端连接得出 PID），没有该扩展时退回客户端自报的 `_NET_WM_PID`。

## 核心进程保护

判定标准：结束后会让系统无法正常运行、注销仍在使用的登录会话，或切断对本机的访问。命中以下任一条即为"核心系统"：

1. **PID 1 与内核线程**。
2. **关键系统服务**，下列 system unit 中的全部进程：
   - 基础：`systemd-journald`、`systemd-udevd`、`systemd-logind`、`elogind`、`polkit`
   - 显示管理器：`display-manager`、`gdm`、`gdm3`、`sddm`、`lightdm`、`lxdm`、`greetd`
   - 网络：`NetworkManager`、`systemd-networkd`、`systemd-resolved`、`wpa_supplicant`、`iwd`、`connman`
   - 远程接入：`ssh`、`sshd`、`sshd@`（每个连接一个实例）、`xrdp`、`xrdp-sesman`、`rustdesk`、`teamviewerd`、`anydesk`、`x11vnc`、`vncserver@`、`gnome-remote-desktop`（它也匹配用户级 unit）
3. **用户 systemd 管理器**：`user@<uid>.service/init.scope` 中的 `systemd --user` 与 `(sd-pam)`。
4. **D-Bus 总线守护进程**：`dbus.service`、`dbus-broker.service` 中的 `dbus-daemon`、`dbus-broker`、`dbus-broker-launch`。
5. **在线登录会话**（logind 状态为 `active` 或 `online`）中的：
   - 会话首进程，以及首进程派生的同名连接进程（如 SSH 的每连接 sshd）；
   - 显示服务（Xorg、Xwayland、Xvnc）、合成器（gnome-shell、kwin_wayland、sway、Hyprland、weston 等）、会话管理器（gnome-session、ksmserver、xfce4-session、lxqt-session、mate-session、cinnamon-session 等）和会话 D-Bus。
6. **startx 会话主进程**：父进程为 `xinit` 的进程。

ProcGuard 自身同样不可操作（分类不变）。

有意不保护的：

- 已注销（`closing`）会话残留的进程，例如断开的 SSH 会话泄漏的 dbus-daemon；
- SSH 会话里的 shell：结束它仍是结束一个会话的正常途径；
- 结束后会话仍在的桌面组件，如窗口管理器、面板（xfwm4、xfce4-panel）；
- 用户在会话里自己启动的远程桌面客户端（系统级的 `rustdesk.service` 仍受保护）；
- 与总线同处 `dbus.service` cgroup、由 D-Bus 按需激活的辅助进程（xfconfd、goa-daemon 等）：结束后由总线按需重新拉起；
- ProcGuard 的祖先进程（如启动它的终端）：可以结束但会警告，不能重启。

补充说明：

- `comm` 被内核截断为 15 字节，按名称匹配时会把 `gnome-session-b` 当作 `gnome-session-binary`。
- 关键 unit 内的所有进程都受保护，包括它们临时派生的 `sh`、`sudo` 等子进程。
- 点击操作时用最新的 `/proc` 数据重新分类，不依赖可能已过去 2 秒的列表。
- 规则清单在 `src/classify.rs` 的 `CORE_UNITS` 和 `SESSION_INFRA`。新增远程接入工具或桌面环境时，在 `golden_host_classification` 测试里补上实际观察到的样本。

## 操作

### 结束与强制结束

- **结束**：通过 pidfd 发送 SIGTERM，等待 3 秒，未退出则提示可以强制结束。目标处于停止状态（`T`、`t`）时随后补发 SIGCONT，否则它要等被继续后才会处理 SIGTERM。
- **强制结束**：发送 SIGKILL，等待 1 秒；仍未退出通常是卡在不可中断睡眠（`D`）。
- 僵尸进程不可操作：它已经退出，需要结束其父进程才能回收。
- 目标属于 systemd 服务时会提示：按服务的 `Restart=` 配置，它可能被自动拉起。

### 身份校验

- 进程以 `(pid, starttime)` 标识。starttime 是 `/proc/<pid>/stat` 的第 22 个字段（开机以来的时钟滴答数），同一 pid 被复用后必然不同。
- 发信号前先 `pidfd_open`，再核对 starttime。此后 pidfd 固定指向核对过的进程，即使它随即退出、pid 被复用，信号也不会落到新进程上。
- 确认框打开期间，如果目标的 uid 或 cgroup 发生变化（setuid、被移入其他 cgroup），放弃执行。

### 提权

- 目标属于其他用户且 ProcGuard 不是 root 时需要提权；本用户的进程若已 setuid，发信号返回 `EPERM` 时同样转为提权。
- 优先使用 `sudo -n`（仅在免密可用时），否则使用 `pkexec`（需要会话中运行 polkit 认证代理，没有时会失败并提示）。ProcGuard 不接触密码。
- 提权后执行的是一段固定的 `sh` 脚本：在 root 侧 `kill` 之前再核对一次 starttime；pid、starttime 和信号名作为 argv 传入，不拼接进脚本。
- 系统服务的 `systemctl restart` 走同一提权途径。

### 重启

按进程所在的 cgroup 判断来源，选择重启方式：

| 来源 | 方式 |
|---|---|
| systemd 服务（`.service`，`app-*`、`run-*` 除外） | `systemctl [--user] restart <unit>`，系统服务通过提权执行。执行前用 `systemctl show` 查询：目标不是 `MainPID`（或 systemd 未记录主进程）时提示将重启整个服务；`KillMode=process` 时提示服务内其他进程会保留；`Transient=yes` 的临时单元无法 restart，本用户进程改为按原命令行重放 |
| D-Bus 按需激活的辅助进程 | 不提供重启，也不会为此重启总线 |
| Docker 容器（systemd cgroup 驱动下的 `docker-<id>.scope`） | `docker restart <id>`，整个容器重启。直接调用 `docker` 而不提权，需要当前用户能访问 Docker daemon |
| Kubernetes 容器（kubepods） | 向容器 init（该 cgroup 中最早启动的进程）发 SIGTERM，等待 kubelet 在同一 pod 内重建，最多 30 秒；`restartPolicy: Never` 时不会重建。目标是 pause 容器时提示将重建整个 pod |
| 其他容器（podman、LXC、systemd-nspawn 等） | 不提供重启 |
| snap 应用（`snap.<snap>.<app>-<uuid>.scope`） | SIGTERM 并等其退出，再 `snap run <snap>.<app>` |
| Flatpak 应用（`app-flatpak-<id>-<n>.scope`） | SIGTERM 并等其退出，再 `flatpak run <id>` |
| 本用户的其他进程 | 按原命令行、工作目录和环境变量重放 |
| 其他用户的非服务进程 | 不提供重启，只能结束 |

按原命令行重放的规则：

- 浏览器、Electron 的辅助进程无法单独启动，自动改为重启其主进程：沿父进程向上，找到同一可执行文件且不带辅助参数的进程。
- 以下情况拒绝重启：
  - 标准输入、输出或错误连着终端：脱离终端后多数程序会退出或空转，应回到终端里重启；
  - `argv[0]` 解析出的文件与正在运行的可执行文件不是同一个 inode，说明命令行已被进程改写（如 `sshd: user@pts/0`、postgres 的进程标题），重放会运行别的东西。例外是可执行文件已被升级替换（`/proc/<pid>/exe` 带 `(deleted)` 且路径一致），此时提示并启动新版本；
  - 读不到可执行文件、工作目录或环境变量（权限不足或进程已退出）；
  - 目标是 ProcGuard 的祖先进程。
- 环境变量沿用原进程的 environ。缺少 `PATH`、`HOME`（应用程序还要求有 `DISPLAY` 或 `WAYLAND_DISPLAY`）时改用 ProcGuard 自身的环境并提示，例如 Chrome 会用进程标题覆盖 environ 区域。原工作目录已不存在时改用 `HOME`。
- 新进程的放置跟随原进程：原进程在用户 systemd 管理器下时，通过 `systemd-run --user --scope` 放入独立 scope（应用程序命名为 `app-procguard-<名称>-<随机数>.scope`，仍能被识别为应用），以免改变它在 systemd-oomd 等按 cgroup 生效的策略下的待遇；否则以独立进程组直接启动（位于 ProcGuard 所在的 cgroup），标准输入输出指向 `/dev/null`。
- 旧进程只收到 SIGTERM，最多等 5 秒，不会自动升级为 SIGKILL：忽略 SIGTERM 的进程可能正在保存状态。超时则放弃重启，原进程保持运行。
- 旧进程退出后观察 0.8 秒：若同一父进程下已出现同一可执行文件的新进程（被会话管理器或守护进程自动拉起），不再重复启动。
- 新进程在 1 秒内以非 0 状态退出时报告启动失败。

## 采集与性能

直接读 `/proc` 而不用 `sysinfo`：分类、保护和身份校验需要 cgroup、`PF_KTHREAD`、`RssAnon` 和 starttime，`sysinfo` 提供不全。

- `stat` 中的 rss 在内核 6.2 及以后是 per-CPU 计数器的近似值，误差可达几百 KiB，只用来判断是否变化；显示值取自 `status`，变化时用 `statm` 的 resident − shared 快速更新私有内存。
- 每个进程每轮只读一次 `stat`：fd 保持打开，用 `pread` 重读，省去路径解析和 open / close；保持打开的 fd 数不超过 `RLIMIT_NOFILE` 减 256。进程退出后该 fd 的读取返回 `ESRCH`，不会读到复用同一 pid 的新进程。
- `status`、`cmdline`、`cgroup` 只在新进程、启动不足 10 秒的进程、`comm` 变化（exec）或约每 15 轮一次的轮转刷新时重读；轮转按 pid 错开，使每轮开销均匀。
- 上一轮没有 CPU 占用且 I/O 为 0 的进程跳过 `io` 读取；计数是累计值，跳过后算出的速率仍然准确。
- logind 会话目录只在 mtime 变化时重读。整机 CPU 不重复计入已包含在 user、nice 中的 guest 时间。
- `comm` 截断在 15 字节；若它是 `argv[0]` 文件名的前缀，列表显示完整文件名（`gnome-session-b` → `gnome-session-binary`）。

界面针对无 GPU 的软件渲染（Mesa llvmpipe）优化：只在有输入或新快照时重绘，每次刷新只画一帧；表格只渲染可见行，过滤和排序只在数据或视图设置变化时执行；去掉表格斑马纹，面板背景统一交给清屏色，减少整窗 alpha 混合。中文字体直接 mmap 系统字体文件（仅当文件属 root 且他人不可写），只有用到的字形页常驻内存；不内嵌字体，否则二进制会增加约 20 MB。

开发机实测（Ubuntu 24.04 KVM 虚拟机，8 vCPU，无 GPU，Mesa llvmpipe，约 530 个进程）：

| 指标 | 数值 |
|---|---|
| 单轮采集 CPU 时间 | 8–9 ms，2 秒间隔下约为单核的 0.4% |
| 界面空闲时整个进程的 CPU | 约单核 1%（Xvfb 上 60 秒平均 1.03%） |
| 私有内存（RssAnon） | 约 39 MiB |

在自己的机器上，状态栏的"本程序"一项和 `--dump` 的 stderr 可以看到对应的数字。

## 开发与测试

```bash
cargo test                  # 单元测试与集成测试，不需要特权
cargo clippy --all-targets
cargo fmt --check
```

- 解析器用开发机上采集的真实 `/proc` 样本测试。分类和重启策略是纯函数，`classify.rs` 的 golden 测试覆盖实际观察到的进程：xrdp 下的 XFCE 会话、gdm 登录界面、SSH 会话、已关闭会话的残留、k3s 与 docker 容器等。
- `tests/actions.rs` 针对真实进程验证：结束、拒绝已复用的 PID、对停止的进程补发 SIGCONT、重启后 argv / 工作目录 / 环境变量不变、可执行文件被替换后启动新版本、拒绝重启祖先进程和受保护进程。目标都是测试自己用 `setsid` 启动的私有 `sleep` 副本，不会向测试之外的进程发信号。

标记为 `#[ignore]` 的测试会改动真实系统状态，需要显式运行：

```bash
cargo test -- --ignored     # 只跑这些；--include-ignored 则全部运行
```

| 测试 | 前提 | 副作用 |
|---|---|---|
| `privileged_script_refuses_mismatched_start_time`（`src/actions.rs`） | `sudo -n` | 以 root 启动并结束一个 `sleep` |
| `restart_inside_user_manager_goes_through_systemd_run`（`tests/actions.rs`） | systemd 用户管理器 | 创建并清理一个临时 scope |
| `terminates_a_root_process_through_sudo`（`tests/privileged.rs`，下同） | `sudo -n` | 以 root 启动并结束一个 `sleep` |
| `restarts_a_system_service` | `sudo -n`，`kerneloops.service` 正在运行 | 重启该服务 |
| `restarts_a_docker_container` | Docker，能拉取 `alpine:3.21` | 创建、重启并删除一个临时容器 |
| `never_restarts_the_bus_for_a_dbus_activated_helper` | 用户 D-Bus | 无，只检查总线的 MainPID 未变 |

## 代码结构

| 路径 | 职责 |
|---|---|
| `src/main.rs` | 入口：启动界面或 `--dump` |
| `src/app.rs` | egui 界面；采集在独立线程进行，只把最新快照交给界面 |
| `src/collector.rs` | 增量采集，生成快照 |
| `src/procfs.rs` | `/proc` 与 cgroup 文件解析。纯函数，畸形输入返回 `None` 而不 panic（release 为 `panic = "abort"`） |
| `src/classify.rs` | 分类、核心进程判定、重启策略，全部是纯函数 |
| `src/session.rs` | logind 会话、`/etc/passwd`、`UID_MIN`、X11 窗口归属 |
| `src/actions.rs` | 结束与重启：`prepare` 生成确认框里的计划，`execute` 复核身份后执行 |
| `src/fonts.rs` | 查找并加载系统中文字体 |
| `src/format.rs` | 单位格式化（二进制单位，保留三位有效数字） |
| `tests/` | 针对真实进程的集成测试；`privileged.rs` 默认忽略 |

## 已知限制

- 仅支持 Linux，界面只有中文。
- 窗口归属检测基于 X11 的 `_NET_CLIENT_LIST`，检测不到原生 Wayland 窗口；这类程序只有位于 `app-*`、`snap.*` unit 中才会归为"应用程序"（GNOME、KDE 通常这样启动应用）。
- 核心进程规则包含 unit 名和进程名清单，清单之外的远程接入工具、桌面环境组件不受保护。
- 非 systemd 系统上，基于 unit 和 logind 会话的规则不生效；非纯 cgroup v2 环境下，磁盘 I/O 无法回退到按 cgroup 统计。
- 提权依赖免密 `sudo` 或 `pkexec` 加 polkit 认证代理；两者都不可用时，涉及其他用户进程和系统服务的操作会失败并给出原因。
- 容器只有 Docker（systemd cgroup 驱动）和 Kubernetes 支持重启。
- 未启用 AccessKit，不支持屏幕阅读器；排序、筛选等界面状态不跨次保存。
