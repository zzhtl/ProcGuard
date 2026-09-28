//! Process categories, the "core process" judgment and restart strategy selection.
//!
//! A process is core when killing it would break the OS, a live login session, or access to the
//! machine. Everything here is a pure function of facts the collector gathered, so each rule is
//! pinned by table tests built from what was observed on real hosts.

use std::collections::HashSet;

use crate::session::LogindSession;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    Kernel,
    Core,
    SystemService,
    Container,
    App,
    UserService,
    UserProcess,
}

impl Category {
    /// Sidebar order: what users act on first.
    pub const ALL: [Category; 7] = [
        Category::App,
        Category::UserProcess,
        Category::UserService,
        Category::Container,
        Category::SystemService,
        Category::Core,
        Category::Kernel,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Category::Kernel => "内核线程",
            Category::Core => "核心系统",
            Category::SystemService => "系统服务",
            Category::Container => "容器",
            Category::App => "应用程序",
            Category::UserService => "用户服务",
            Category::UserProcess => "用户进程",
        }
    }
}

/// What the classifier needs to know about one process.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    pub pid: u32,
    pub ppid: u32,
    pub comm: &'a str,
    /// Arguments joined by spaces.
    pub cmdline: &'a str,
    pub uid: u32,
    pub cgroup: &'a str,
    pub kthread: bool,
    pub state: u8,
    pub has_window: bool,
    pub parent_comm: Option<&'a str>,
    /// Killing or restarting an ancestor of ProcGuard takes ProcGuard down mid-action.
    pub self_ancestor: bool,
}

/// System-wide context shared by all processes of one collection pass.
pub struct Env<'a> {
    pub self_pid: u32,
    pub my_uid: u32,
    pub uid_min: u32,
    pub sessions: &'a [LogindSession],
    pub live_leaders: HashSet<u32>,
}

impl<'a> Env<'a> {
    pub fn new(self_pid: u32, my_uid: u32, uid_min: u32, sessions: &'a [LogindSession]) -> Self {
        let live_leaders = sessions
            .iter()
            .filter(|s| s.is_live())
            .filter_map(|s| s.leader)
            .collect();
        Self {
            self_pid,
            my_uid,
            uid_min,
            sessions,
            live_leaders,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Class {
    pub category: Category,
    /// `Some(reason)` means the process must not be killed or restarted.
    pub protect: Option<&'static str>,
}

pub const KTHREAD_REASON: &str = "内核线程：不接受用户态信号，由内核管理";
pub const SELF_REASON: &str = "ProcGuard 自身";

/// Units whose death breaks the system or cuts off access to it. All their processes are core.
const CORE_UNITS: &[(&str, &str)] = &[
    ("init.scope", "init 进程：终止会导致内核崩溃"),
    (
        "systemd-journald.service",
        "系统日志服务：终止会中断全系统日志并可能断开服务输出流",
    ),
    (
        "systemd-udevd.service",
        "设备管理服务：终止后设备热插拔和驱动事件无人处理",
    ),
    (
        "systemd-logind.service",
        "登录与会话管理：终止会影响所有登录会话",
    ),
    (
        "polkit.service",
        "系统授权服务：终止后所有需要授权的操作都会失败",
    ),
    ("elogind.service", "登录与会话管理：终止会影响所有登录会话"),
    (
        "display-manager.service",
        "显示管理器：终止会结束本机图形登录",
    ),
    ("gdm.service", "显示管理器：终止会结束本机图形登录"),
    ("gdm3.service", "显示管理器：终止会结束本机图形登录"),
    ("sddm.service", "显示管理器：终止会结束本机图形登录"),
    ("lightdm.service", "显示管理器：终止会结束本机图形登录"),
    ("lxdm.service", "显示管理器：终止会结束本机图形登录"),
    ("greetd.service", "显示管理器：终止会结束本机图形登录"),
    ("NetworkManager.service", "网络服务：终止会断开本机网络"),
    ("systemd-networkd.service", "网络服务：终止会断开本机网络"),
    (
        "systemd-resolved.service",
        "域名解析服务：终止后本机域名解析失败",
    ),
    ("wpa_supplicant.service", "无线网络服务：终止会断开无线网络"),
    ("iwd.service", "无线网络服务：终止会断开无线网络"),
    ("connman.service", "网络服务：终止会断开本机网络"),
    ("ssh.service", "远程接入服务：终止会切断对本机的远程访问"),
    ("sshd.service", "远程接入服务：终止会切断对本机的远程访问"),
    ("sshd@.service", "远程接入连接：终止会断开该 SSH 连接"),
    ("xrdp.service", "远程接入服务：终止会切断对本机的远程访问"),
    (
        "xrdp-sesman.service",
        "远程接入服务：终止会切断对本机的远程访问",
    ),
    (
        "rustdesk.service",
        "远程接入服务：终止会切断对本机的远程访问",
    ),
    (
        "teamviewerd.service",
        "远程接入服务：终止会切断对本机的远程访问",
    ),
    (
        "anydesk.service",
        "远程接入服务：终止会切断对本机的远程访问",
    ),
    ("x11vnc.service", "远程接入服务：终止会切断对本机的远程访问"),
    (
        "vncserver@.service",
        "远程接入服务：终止会切断对本机的远程访问",
    ),
    (
        "gnome-remote-desktop.service",
        "远程接入服务：终止会切断对本机的远程访问",
    ),
];

/// Bus units also host D-Bus-activated helpers (xfconfd, goa-daemon, software-properties-dbus...),
/// so only the bus daemon itself is core there.
const BUS_UNITS: &[&str] = &["dbus.service", "dbus-broker.service"];
const BUS_DAEMONS: &[&str] = &["dbus-daemon", "dbus-broker", "dbus-broker-launch"];

/// Session infrastructure recognised by comm inside a live session: killing any of these ends
/// the graphical session (or the login screen) it belongs to.
const SESSION_INFRA: &[(&[&str], &str)] = &[
    (
        &["Xorg", "X", "Xwayland", "Xvnc"],
        "显示服务：终止会关闭该图形会话的所有窗口",
    ),
    (
        &[
            "gnome-shell",
            "kwin_wayland",
            "kwin_wayland_wrapper",
            "sway",
            "Hyprland",
            "weston",
            "wayfire",
            "labwc",
            "river",
            "niri",
            "cosmic-comp",
        ],
        "桌面合成器：终止会结束该图形会话",
    ),
    (
        &[
            "gnome-session-binary",
            "gnome-session-ctl",
            "gdm-x-session",
            "gdm-wayland-session",
            "ksmserver",
            "plasma_session",
            "startplasma-x11",
            "startplasma-wayland",
            "xfce4-session",
            "lxqt-session",
            "lxsession",
            "mate-session",
            "cinnamon-session",
            "cinnamon-session-binary",
        ],
        "会话管理器：终止会注销该图形会话",
    ),
];

pub fn classify(f: &Facts, env: &Env) -> Class {
    if f.kthread {
        return Class {
            category: Category::Kernel,
            protect: Some(KTHREAD_REASON),
        };
    }
    if let Some(reason) = core_reason(f, env) {
        return Class {
            category: Category::Core,
            protect: Some(reason),
        };
    }
    let unit = unit_of(f.cgroup);
    let category = if is_container(f.cgroup) {
        Category::Container
    } else if !is_human(f, env) {
        Category::SystemService
    } else if f.has_window || unit.is_some_and(|u| u.starts_with("app-") || u.starts_with("snap."))
    {
        Category::App
    } else if in_user_manager(f.cgroup) && unit.is_some_and(|u| u.ends_with(".service")) {
        Category::UserService
    } else {
        Category::UserProcess
    };
    let protect = (f.pid == env.self_pid).then_some(SELF_REASON);
    Class { category, protect }
}

fn core_reason(f: &Facts, env: &Env) -> Option<&'static str> {
    if f.pid == 1 {
        return Some("init 进程：终止会导致内核崩溃");
    }
    let unit = unit_of(f.cgroup);
    if let Some(unit) = unit {
        if unit == "init.scope" && in_user_manager(f.cgroup) {
            return Some("用户 systemd 管理器：终止会结束该用户的全部会话与服务");
        }
        if BUS_UNITS.contains(&unit) {
            if BUS_DAEMONS.iter().any(|d| comm_is(f.comm, d)) {
                return Some("消息总线（D-Bus）：终止会使依赖总线的系统与桌面组件全部失效");
            }
        } else if let Some((_, reason)) = CORE_UNITS.iter().find(|(u, _)| *u == template_of(unit)) {
            // User units never match: CORE_UNITS describe system services.
            if !in_user_manager(f.cgroup) || unit == "gnome-remote-desktop.service" {
                return Some(reason);
            }
        }
    }
    if env.live_leaders.contains(&f.pid) {
        return Some("登录会话首进程：终止会注销整个会话");
    }
    if env.live_leaders.contains(&f.ppid) && f.parent_comm == Some(f.comm) {
        return Some("登录会话连接进程（如 SSH 连接）：终止会断开该会话");
    }
    if f.parent_comm == Some("xinit") {
        return Some("startx 会话主进程：退出即结束 X 会话");
    }
    if in_live_session(f.cgroup, env) {
        if let Some((_, reason)) = SESSION_INFRA
            .iter()
            .find(|(names, _)| names.iter().any(|n| comm_is(f.comm, n)))
        {
            return Some(reason);
        }
        let bus = comm_is(f.comm, "dbus-broker")
            || comm_is(f.comm, "dbus-broker-launch")
            || (comm_is(f.comm, "dbus-daemon")
                && (f.cmdline.contains("--session") || f.cmdline.contains("--system")));
        if bus {
            return Some("会话消息总线（D-Bus）：终止会使该会话的桌面组件全部失效");
        }
    }
    None
}

/// comm is truncated to 15 bytes (TASK_COMM_LEN - 1), e.g. `gnome-session-binary` shows as
/// `gnome-session-b`.
fn comm_is(comm: &str, name: &str) -> bool {
    comm == name || (comm.len() == 15 && name.len() > 15 && name.starts_with(comm))
}

/// The innermost `.service`/`.scope` unit of a cgroup path; udevd for example lives in
/// `/system.slice/systemd-udevd.service/udev`.
pub fn unit_of(cgroup: &str) -> Option<&str> {
    cgroup
        .rsplit('/')
        .find(|c| c.ends_with(".service") || c.ends_with(".scope"))
}

/// `sshd@3-10.0.0.1:22-10.0.0.2:5555.service` → `sshd@.service`.
fn template_of(unit: &str) -> &str {
    match (unit.find('@'), unit.rfind('.')) {
        (Some(at), Some(dot)) if at < dot => {
            // Only the shape matters for matching; the CORE_UNITS entries are written that way.
            const KNOWN: &[&str] = &["sshd@.service", "vncserver@.service"];
            let prefix = &unit[..=at];
            KNOWN
                .iter()
                .find(|k| k.starts_with(prefix))
                .copied()
                .unwrap_or(unit)
        }
        _ => unit,
    }
}

pub fn in_user_manager(cgroup: &str) -> bool {
    cgroup
        .split('/')
        .any(|c| c.starts_with("user@") && c.ends_with(".service"))
}

/// uid encoded in a `user-<uid>.slice` component.
fn user_slice_uid(cgroup: &str) -> Option<u32> {
    cgroup.split('/').find_map(|c| {
        c.strip_prefix("user-")?
            .strip_suffix(".slice")?
            .parse()
            .ok()
    })
}

/// Human accounts own `user-<uid>.slice` with uid ≥ UID_MIN; system accounts (the gdm greeter,
/// ...) and everything under system.slice are system-level.
fn is_human(f: &Facts, env: &Env) -> bool {
    if f.cgroup.starts_with("/system.slice/") || f.cgroup.starts_with("/init.scope") {
        return false;
    }
    match user_slice_uid(f.cgroup) {
        Some(uid) => uid >= env.uid_min,
        None => f.uid >= env.uid_min,
    }
}

pub fn is_container(cgroup: &str) -> bool {
    cgroup.contains("/kubepods")
        || cgroup.starts_with("/machine.slice/")
        || cgroup.contains("/docker/")
        || cgroup.contains("/lxc.payload")
        || cgroup.split('/').any(|c| {
            (c.starts_with("docker-")
                || c.starts_with("libpod-")
                || c.starts_with("cri-containerd-"))
                && c.ends_with(".scope")
        })
}

/// Whether the process's session is still logged in. Processes outside logind session scopes
/// (user managers, non-systemd hosts) count as live.
fn in_live_session(cgroup: &str, env: &Env) -> bool {
    match cgroup
        .rsplit('/')
        .find(|c| c.starts_with("session-") && c.ends_with(".scope"))
    {
        Some(scope) => env
            .sessions
            .iter()
            .find(|s| s.scope.as_deref() == Some(scope))
            .is_some_and(LogindSession::is_live),
        None => true,
    }
}

/// Chromium/Electron (`--type=`) and Firefox (`-contentproc`) helper processes belong to the
/// application of their parent.
pub fn is_app_helper(cmdline: &str) -> bool {
    cmdline.contains(" --type=") || cmdline.contains(" -contentproc")
}

/// How a restart would be carried out, decided from collector facts alone. The action layer
/// re-validates against live /proc data before doing anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Restart {
    Unavailable(&'static str),
    /// `systemctl [--user] restart <unit>`; the action layer checks MainPID and transience.
    Unit {
        unit: Box<str>,
        user: bool,
    },
    Docker {
        id: Box<str>,
    },
    /// Kill the container's init and let kubelet recreate it.
    Kube,
    Snap {
        app: Box<str>,
    },
    Flatpak {
        app: Box<str>,
    },
    /// Own plain process: terminate and start the same command line again.
    Relaunch,
}

impl Restart {
    pub fn describe(&self) -> String {
        match self {
            Restart::Unavailable(r) => format!("不可重启：{r}"),
            Restart::Unit { unit, user: false } => format!("systemctl restart {unit}"),
            Restart::Unit { unit, user: true } => format!("systemctl --user restart {unit}"),
            Restart::Docker { id } => format!("docker restart {}", &id[..id.len().min(12)]),
            Restart::Kube => "结束容器主进程，由 kubelet 重建".to_owned(),
            Restart::Snap { app } => format!("snap run {app}"),
            Restart::Flatpak { app } => format!("flatpak run {app}"),
            Restart::Relaunch => "以原命令行、工作目录和环境变量重新启动".to_owned(),
        }
    }
}

pub fn restart_kind(f: &Facts, class: &Class, env: &Env) -> Restart {
    if class.protect.is_some() {
        return Restart::Unavailable("受保护进程");
    }
    if f.state == b'Z' {
        return Restart::Unavailable("僵尸进程：已退出，等待父进程回收");
    }
    if f.self_ancestor {
        return Restart::Unavailable("ProcGuard 的祖先进程：重启会中断本程序");
    }
    let unit = unit_of(f.cgroup).unwrap_or("");
    if class.category == Category::Container {
        if let Some(id) = unit
            .strip_prefix("docker-")
            .and_then(|u| u.strip_suffix(".scope"))
        {
            return Restart::Docker { id: id.into() };
        }
        if f.cgroup.contains("/kubepods") {
            return Restart::Kube;
        }
        return Restart::Unavailable("容器进程：请使用对应的容器运行时重启");
    }
    if unit.ends_with(".service") && !unit.starts_with("app-") && !unit.starts_with("run-") {
        if BUS_UNITS.contains(&unit) {
            return Restart::Unavailable("D-Bus 按需激活的辅助进程：结束后由总线按需重新拉起");
        }
        return Restart::Unit {
            unit: unit.into(),
            user: in_user_manager(f.cgroup),
        };
    }
    if let Some(app) = snap_app(unit) {
        return Restart::Snap { app: app.into() };
    }
    if let Some(app) = unit
        .strip_prefix("app-flatpak-")
        .and_then(|u| u.strip_suffix(".scope"))
        .and_then(|u| u.rsplit_once('-'))
        .map(|(app, _)| app)
    {
        return Restart::Flatpak { app: app.into() };
    }
    if f.uid != env.my_uid {
        return Restart::Unavailable("非本用户的非服务进程：只能结束");
    }
    Restart::Relaunch
}

/// `snap.<snap>.<app>-<uuid>.scope` → `<snap>.<app>`.
fn snap_app(unit: &str) -> Option<&str> {
    let body = unit.strip_prefix("snap.")?.strip_suffix(".scope")?;
    // The uuid suffix is 36 characters of hex and dashes, preceded by '-'.
    let cut = body.len().checked_sub(37)?;
    let (app, uuid) = body.split_at(cut);
    let uuid = uuid.strip_prefix('-')?;
    (uuid.len() == 36 && uuid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')).then_some(app)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(
        id: &str,
        uid: u32,
        state: &str,
        kind: &str,
        class: &str,
        leader: u32,
    ) -> LogindSession {
        LogindSession {
            id: id.into(),
            uid,
            state: state.into(),
            kind: kind.into(),
            class: class.into(),
            leader: Some(leader),
            scope: Some(format!("session-{id}.scope").into()),
        }
    }

    /// Sessions observed on the development host: an xrdp XFCE session, the gdm greeter, a live
    /// ssh session and an abandoned (closing) ssh session that leaked a dbus-daemon.
    fn host_sessions() -> Vec<LogindSession> {
        vec![
            session("c14", 1000, "active", "x11", "user", 239850),
            session("c13", 120, "active", "x11", "greeter", 238435),
            session("8125", 1000, "active", "tty", "user", 2175173),
            session("9", 1000, "closing", "tty", "user", 49111),
        ]
    }

    fn facts<'a>(pid: u32, comm: &'a str, uid: u32, cgroup: &'a str) -> Facts<'a> {
        Facts {
            pid,
            ppid: 1,
            comm,
            cmdline: comm,
            uid,
            cgroup,
            kthread: false,
            state: b'S',
            has_window: false,
            parent_comm: None,
            self_ancestor: false,
        }
    }

    const U: &str = "/user.slice/user-1000.slice";

    #[test]
    fn golden_host_classification() {
        let sessions = host_sessions();
        let env = Env::new(4242, 1000, 1000, &sessions);
        let c14 = format!("{U}/session-c14.scope");
        let s9 = format!("{U}/session-9.scope");
        let umgr = format!("{U}/user@1000.service");
        let umgr_init = format!("{umgr}/init.scope");
        let user_bus = format!("{umgr}/session.slice/dbus.service");
        let pipewire = format!("{umgr}/session.slice/pipewire.service");
        let app_scope = format!("{umgr}/app.slice/app-gnome-pipewire\\x2dxrdp-43921.scope");

        let cases: Vec<(Facts, Category, bool)> = vec![
            (facts(1, "systemd", 0, "/init.scope"), Category::Core, true),
            (
                facts(3563, "systemd", 1000, &umgr_init),
                Category::Core,
                true,
            ),
            (
                facts(3567, "(sd-pam)", 1000, &umgr_init),
                Category::Core,
                true,
            ),
            (
                facts(
                    780,
                    "systemd-journal",
                    0,
                    "/system.slice/systemd-journald.service",
                ),
                Category::Core,
                true,
            ),
            (
                facts(
                    900,
                    "systemd-udevd",
                    0,
                    "/system.slice/systemd-udevd.service/udev",
                ),
                Category::Core,
                true,
            ),
            (
                facts(66019, "dbus-daemon", 1000, &user_bus),
                Category::Core,
                true,
            ),
            (
                facts(700, "dbus-daemon", 101, "/system.slice/dbus.service"),
                Category::Core,
                true,
            ),
            // D-Bus-activated helpers share the bus cgroup but are not the bus.
            (
                facts(70001, "xfconfd", 1000, &user_bus),
                Category::UserService,
                false,
            ),
            (
                facts(2520226, "software-proper", 0, "/system.slice/dbus.service"),
                Category::SystemService,
                false,
            ),
            // xrdp XFCE session.
            (facts(239850, "xrdp-sesman", 0, &c14), Category::Core, true),
            (
                facts(239853, "xfce4-session", 1000, &c14),
                Category::Core,
                true,
            ),
            (facts(239854, "Xorg", 1000, &c14), Category::Core, true),
            (
                facts(240000, "xfwm4", 1000, &c14),
                Category::UserProcess,
                false,
            ),
            (
                facts(240079, "xfce4-panel", 1000, &c14),
                Category::UserProcess,
                false,
            ),
            (
                facts(239884, "xrdp-chansrv", 1000, &c14),
                Category::UserProcess,
                false,
            ),
            // Remote access and the user's own rustdesk client.
            (
                facts(1200, "sshd", 0, "/system.slice/ssh.service"),
                Category::Core,
                true,
            ),
            (
                facts(1300, "xrdp", 123, "/system.slice/xrdp.service"),
                Category::Core,
                true,
            ),
            (
                facts(1400, "rustdesk", 0, "/system.slice/rustdesk.service"),
                Category::Core,
                true,
            ),
            (
                facts(4032971, "rustdesk", 1000, &c14),
                Category::UserProcess,
                false,
            ),
            // Leaked processes of the closing ssh session are not protected.
            (
                facts(66889, "dbus-daemon", 1000, &s9),
                Category::UserProcess,
                false,
            ),
            (
                facts(66898, "gvfsd", 1000, &s9),
                Category::UserProcess,
                false,
            ),
            // gdm greeter (system account).
            (
                facts(
                    238496,
                    "Xorg",
                    120,
                    "/user.slice/user-120.slice/session-c13.scope",
                ),
                Category::Core,
                true,
            ),
            (
                facts(
                    238698,
                    "gnome-shell",
                    120,
                    "/user.slice/user-120.slice/session-c13.scope",
                ),
                Category::Core,
                true,
            ),
            (
                facts(
                    238807,
                    "mutter-x11-fram",
                    120,
                    "/user.slice/user-120.slice/session-c13.scope",
                ),
                Category::SystemService,
                false,
            ),
            // Ordinary system services and containers.
            (
                facts(2000, "cron", 0, "/system.slice/cron.service"),
                Category::SystemService,
                false,
            ),
            (
                facts(2001, "containerd-shim", 0, "/system.slice/k3s.service"),
                Category::SystemService,
                false,
            ),
            (
                facts(
                    2002,
                    "postgres",
                    70,
                    "/system.slice/docker-102ea8f6d7ae5f65a04dccae7f44f7d6cfabb80a34696e3517505c5f7d960c6b.scope",
                ),
                Category::Container,
                false,
            ),
            (
                facts(
                    2003,
                    "metrics-server",
                    1000,
                    "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod4c279ea8_ca42_41b6_a5bd_36dd2ce08590.slice/cri-containerd-6d5e0db557b60ecc94b3cc8929a40f44d95457af70df20d6c2454cd4b4ca08d3.scope",
                ),
                Category::Container,
                false,
            ),
            // User services and apps.
            (
                facts(3584, "pipewire", 1000, &pipewire),
                Category::UserService,
                false,
            ),
            (
                facts(44118, "pw-cli", 1000, &app_scope),
                Category::App,
                false,
            ),
        ];
        for (f, want_cat, want_protected) in cases {
            let c = classify(&f, &env);
            assert_eq!(
                (c.category, c.protect.is_some()),
                (want_cat, want_protected),
                "{} (pid {})",
                f.comm,
                f.pid
            );
        }
    }

    #[test]
    fn session_leaders_and_their_connection_process() {
        let sessions = host_sessions();
        let env = Env::new(4242, 1000, 1000, &sessions);
        let ssh = format!("{U}/session-8125.scope");
        let leader = facts(2175173, "sshd", 0, &ssh);
        assert!(classify(&leader, &env).protect.is_some());

        let conn = Facts {
            ppid: 2175173,
            parent_comm: Some("sshd"),
            ..facts(2175180, "sshd", 1000, &ssh)
        };
        assert_eq!(classify(&conn, &env).category, Category::Core);

        // The shell inside the ssh session stays killable, so a session can still be ended.
        let shell = Facts {
            ppid: 2175180,
            parent_comm: Some("sshd"),
            ..facts(2175181, "bash", 1000, &ssh)
        };
        assert_eq!(
            classify(&shell, &env),
            Class {
                category: Category::UserProcess,
                protect: None
            }
        );

        // Leader of the closing session is no longer protected.
        let s9 = format!("{U}/session-9.scope");
        let stale = facts(49111, "sshd", 0, &s9);
        assert!(classify(&stale, &env).protect.is_none());
    }

    #[test]
    fn windows_helpers_self_and_kernel() {
        let sessions = host_sessions();
        let env = Env::new(4242, 1000, 1000, &sessions);
        let c14 = format!("{U}/session-c14.scope");

        let chrome = Facts {
            has_window: true,
            ..facts(2240476, "chrome", 1000, &c14)
        };
        assert_eq!(classify(&chrome, &env).category, Category::App);
        assert!(is_app_helper(
            "/opt/google/chrome/chrome --type=renderer --lang=zh-CN"
        ));
        assert!(is_app_helper(
            "/snap/firefox/1/usr/lib/firefox/firefox -contentproc -isForBrowser"
        ));
        assert!(!is_app_helper("/usr/bin/foo --typed"));

        let me = facts(4242, "procguard", 1000, &c14);
        assert_eq!(classify(&me, &env).protect, Some(SELF_REASON));

        let kt = Facts {
            kthread: true,
            ..facts(2, "kthreadd", 0, "/")
        };
        assert_eq!(
            classify(&kt, &env),
            Class {
                category: Category::Kernel,
                protect: Some(KTHREAD_REASON)
            }
        );

        let startx = Facts {
            parent_comm: Some("xinit"),
            ..facts(
                5000,
                "i3",
                1000,
                "/user.slice/user-1000.slice/session-3.scope",
            )
        };
        assert_eq!(classify(&startx, &env).category, Category::Core);
    }

    #[test]
    fn comm_truncation() {
        assert!(comm_is("gnome-session-b", "gnome-session-binary"));
        assert!(comm_is("dbus-broker-lau", "dbus-broker-launch"));
        assert!(!comm_is("gnome-session", "gnome-session-binary"));
        assert!(!comm_is("X", "Xorg"));
    }

    #[test]
    fn restart_strategies() {
        let sessions = host_sessions();
        let env = Env::new(4242, 1000, 1000, &sessions);
        let umgr = format!("{U}/user@1000.service");
        let c14 = format!("{U}/session-c14.scope");
        let plan = |f: &Facts| restart_kind(f, &classify(f, &env), &env);

        assert_eq!(
            plan(&facts(1, "systemd", 0, "/init.scope")),
            Restart::Unavailable("受保护进程")
        );
        assert_eq!(
            plan(&facts(
                3584,
                "pipewire",
                1000,
                &format!("{umgr}/session.slice/pipewire.service")
            )),
            Restart::Unit {
                unit: "pipewire.service".into(),
                user: true
            }
        );
        assert_eq!(
            plan(&facts(2000, "cron", 0, "/system.slice/cron.service")),
            Restart::Unit {
                unit: "cron.service".into(),
                user: false
            }
        );
        // Never restart a bus to "restart" one of its activated helpers.
        assert!(matches!(
            plan(&facts(
                70001,
                "xfconfd",
                1000,
                &format!("{umgr}/session.slice/dbus.service")
            )),
            Restart::Unavailable(_)
        ));
        assert_eq!(
            plan(&facts(
                2002,
                "postgres",
                70,
                "/system.slice/docker-102ea8f6d7ae5f65a04dccae7f44f7d6cfabb80a34696e3517505c5f7d960c6b.scope"
            )),
            Restart::Docker {
                id: "102ea8f6d7ae5f65a04dccae7f44f7d6cfabb80a34696e3517505c5f7d960c6b".into()
            }
        );
        assert_eq!(
            plan(&facts(
                2003,
                "metrics-server",
                1000,
                "/kubepods.slice/kubepods-burstable.slice/x.slice/cri-containerd-6d5e.scope"
            )),
            Restart::Kube
        );
        assert_eq!(plan(&facts(240000, "xfwm4", 1000, &c14)), Restart::Relaunch);
        assert!(matches!(
            plan(&facts(5001, "sudo", 0, &c14)),
            Restart::Unavailable(_)
        ));
        assert!(matches!(
            plan(&Facts {
                state: b'Z',
                ..facts(5002, "defunct", 1000, &c14)
            }),
            Restart::Unavailable(_)
        ));
        assert!(matches!(
            plan(&Facts {
                self_ancestor: true,
                ..facts(5003, "xfce4-terminal", 1000, &c14)
            }),
            Restart::Unavailable(_)
        ));
        // Transient app units are relaunched rather than restarted through systemctl.
        assert_eq!(
            plan(&facts(
                5004,
                "dolphin",
                1000,
                &format!("{umgr}/app.slice/app-org.kde.dolphin@abc.service")
            )),
            Restart::Relaunch
        );
        assert_eq!(
            plan(&facts(
                5005,
                "firefox",
                1000,
                &format!(
                    "{umgr}/app.slice/snap.firefox.firefox-0bb6bd33-6a5f-4a7f-9b2e-4d1e9d2cd0a1.scope"
                )
            )),
            Restart::Snap {
                app: "firefox.firefox".into()
            }
        );
        assert_eq!(
            plan(&facts(
                5006,
                "app",
                1000,
                &format!("{umgr}/app.slice/app-flatpak-org.gnome.Calculator-4242.scope")
            )),
            Restart::Flatpak {
                app: "org.gnome.Calculator".into()
            }
        );
    }

    #[test]
    fn unit_helpers() {
        assert_eq!(
            unit_of("/system.slice/systemd-udevd.service/udev"),
            Some("systemd-udevd.service")
        );
        assert_eq!(unit_of("/"), None);
        assert_eq!(
            template_of("sshd@3-10.0.0.1:22-10.0.0.2:5555.service"),
            "sshd@.service"
        );
        assert_eq!(template_of("getty@tty1.service"), "getty@tty1.service");
        assert!(in_user_manager(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope"
        ));
        assert!(!in_user_manager(
            "/user.slice/user-1000.slice/session-2.scope"
        ));
        assert_eq!(
            snap_app("snap.firefox.firefox-0bb6bd33-6a5f-4a7f-9b2e-4d1e9d2cd0a1.scope"),
            Some("firefox.firefox")
        );
        assert_eq!(snap_app("snap.firefox.firefox.scope"), None);
    }
}
