//! Executing terminate / kill / restart.
//!
//! Both steps are blocking and meant for worker threads: [`prepare`] re-reads the target from
//! /proc, re-classifies it and works out exactly what would happen (shown in the confirmation
//! dialog); [`execute`] re-verifies the target's identity and carries the plan out. A process is
//! always addressed by (pid, starttime), and signals go through a pidfd opened *before* the
//! identity check, so a recycled pid can never receive a signal meant for its predecessor.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::process::{Pid, PidfdFlags, Signal};

use crate::classify::{self, Category, Env, Facts, Restart};
use crate::collector::{ProcKey, Row};
use crate::procfs;
use crate::session::Sessions;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// SIGTERM: ask the process to exit.
    Terminate,
    /// SIGKILL: force it.
    Kill,
    Restart,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Terminate => "结束",
            Kind::Kill => "强制结束",
            Kind::Restart => "重启",
        }
    }
}

/// The outcome of [`prepare`]: what the confirmation dialog shows and [`execute`] runs.
#[derive(Debug)]
pub struct Prepared {
    pub kind: Kind,
    pub key: ProcKey,
    pub name: String,
    pub user: String,
    pub category: Category,
    pub cmdline: String,
    /// What will be done, one step per line.
    pub steps: Vec<String>,
    pub warnings: Vec<String>,
    /// `Err(reason)` when the action is not possible; the dialog then only explains why.
    pub plan: Result<Plan, String>,
    /// uid and cgroup at prepare time; execution aborts if either changed meanwhile.
    uid: u32,
    cgroup: String,
}

#[derive(Debug)]
pub enum Plan {
    Signal {
        sig: Signal,
        privileged: bool,
        cont: bool,
    },
    Unit {
        unit: String,
        user: bool,
    },
    Docker {
        id: String,
    },
    Kube {
        init: ProcKey,
        pod_slice: String,
        privileged: bool,
    },
    /// Terminate the process, then run a launcher (`snap run`, `flatpak run`).
    Launcher {
        key: ProcKey,
        cont: bool,
        program: &'static str,
        args: Vec<String>,
    },
    Relaunch(Box<Relaunch>),
}

#[derive(Debug)]
pub struct Relaunch {
    /// The process actually restarted (a browser helper redirects to its main process).
    key: ProcKey,
    /// Its parent: a supervisor that respawns the program is the parent of the new instance too.
    ppid: u32,
    cont: bool,
    exe_path: PathBuf,
    program: PathBuf,
    argv0: OsString,
    args: Vec<OsString>,
    cwd: PathBuf,
    env: Vec<(OsString, OsString)>,
    systemd_run: Option<PathBuf>,
    unit_name: Option<String>,
}

const TERM_WAIT: Duration = Duration::from_secs(3);
const KILL_WAIT: Duration = Duration::from_secs(1);
const RESTART_EXIT_WAIT: Duration = Duration::from_secs(5);
const RESPAWN_WINDOW: Duration = Duration::from_millis(800);
const KUBE_RECREATE_WAIT: Duration = Duration::from_secs(30);

/// Current facts about a process, read fresh from /proc.
struct Live {
    comm: String,
    cmdline: String,
    argv: Vec<OsString>,
    uid: u32,
    cgroup: String,
    state: u8,
    ppid: u32,
    kthread: bool,
}

fn read_live(key: ProcKey) -> Result<Live, String> {
    let stat = fs::read(format!("/proc/{}/stat", key.pid)).map_err(|_| gone())?;
    let s = procfs::parse_stat(&stat).ok_or_else(gone)?;
    if s.starttime != key.start {
        return Err(reused());
    }
    let status = fs::read(format!("/proc/{}/status", key.pid)).map_err(|_| gone())?;
    let uid = procfs::parse_status(&status).ok_or_else(gone)?.uid;
    let cgroup = fs::read(format!("/proc/{}/cgroup", key.pid)).map_err(|_| gone())?;
    let cgroup = procfs::parse_cgroup(&cgroup).unwrap_or("").to_owned();
    let raw = fs::read(format!("/proc/{}/cmdline", key.pid)).unwrap_or_default();
    let argv: Vec<OsString> = procfs::split_nul(&raw)
        .map(|a| OsStr::from_bytes(a).to_owned())
        .collect();
    let cmdline = argv
        .iter()
        .map(|a| a.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    Ok(Live {
        comm: String::from_utf8_lossy(s.comm).into_owned(),
        cmdline,
        argv,
        uid,
        cgroup,
        state: s.state,
        ppid: s.ppid,
        kthread: s.flags & procfs::PF_KTHREAD != 0,
    })
}

fn gone() -> String {
    "进程已退出".to_owned()
}

fn reused() -> String {
    "该 PID 已被另一个进程复用，原进程已退出".to_owned()
}

fn my_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// Works out what `kind` would do to the process `row` described. Blocking (reads /proc, may run
/// `systemctl show`); call from a worker thread.
pub fn prepare(row: &Row, kind: Kind) -> Prepared {
    let key = row.key;
    let mut p = Prepared {
        kind,
        key,
        name: row.info.name.to_string(),
        user: row.info.user.to_string(),
        category: row.class.category,
        cmdline: row.info.cmdline.to_string(),
        steps: Vec::new(),
        warnings: Vec::new(),
        plan: Err(String::new()),
        uid: row.info.uid,
        cgroup: row.info.cgroup.to_string(),
    };
    let live = match read_live(key) {
        Ok(l) => l,
        Err(e) => {
            p.plan = Err(e);
            return p;
        }
    };
    p.cmdline.clone_from(&live.cmdline);
    p.uid = live.uid;
    p.cgroup.clone_from(&live.cgroup);

    // Re-classify with fresh facts: the snapshot the user clicked on can be seconds old.
    let mut sessions = Sessions::default();
    sessions.refresh();
    let env = Env::new(
        std::process::id(),
        my_uid(),
        crate::session::uid_min(),
        &sessions.list,
    );
    let parent_comm = read_comm(live.ppid);
    let self_ancestor = ancestors_of_self().contains(&key.pid);
    let facts = Facts {
        pid: key.pid,
        ppid: live.ppid,
        comm: &live.comm,
        cmdline: &live.cmdline,
        uid: live.uid,
        cgroup: &live.cgroup,
        kthread: live.kthread,
        state: live.state,
        has_window: row.class.category == Category::App,
        parent_comm: parent_comm.as_deref(),
        self_ancestor,
    };
    let class = classify::classify(&facts, &env);
    p.category = class.category;
    if let Some(reason) = class.protect {
        p.plan = Err(format!("受保护进程：{reason}"));
        return p;
    }
    if live.state == b'Z' {
        p.plan = Err("僵尸进程：它已经退出，只是父进程还没回收；需要结束其父进程".to_owned());
        return p;
    }
    if self_ancestor {
        p.warnings
            .push("这是 ProcGuard 的祖先进程，结束它很可能连带关闭 ProcGuard".to_owned());
    }
    if classify::unit_of(&live.cgroup).is_some_and(|u| u.ends_with(".service"))
        && kind != Kind::Restart
    {
        p.warnings
            .push("该进程属于 systemd 服务，按服务的 Restart= 配置可能被自动拉起".to_owned());
    }
    let stopped = matches!(live.state, b'T' | b't');
    let privileged = live.uid != my_uid() && my_uid() != 0;

    p.plan = match kind {
        Kind::Terminate | Kind::Kill => {
            let (sig, name) = if kind == Kind::Kill {
                (Signal::KILL, "SIGKILL")
            } else {
                (Signal::TERM, "SIGTERM")
            };
            p.steps.push(format!("向 PID {} 发送 {name}", key.pid));
            if stopped && kind == Kind::Terminate {
                p.steps
                    .push("进程处于停止状态，随后补发 SIGCONT 使其处理 SIGTERM".to_owned());
            }
            if privileged {
                p.warnings.push(privilege_note());
            }
            Ok(Plan::Signal {
                sig,
                privileged,
                cont: stopped && kind == Kind::Terminate,
            })
        }
        Kind::Restart => {
            let restart = classify::restart_kind(&facts, &class, &env);
            plan_restart(&mut p, &live, restart, stopped)
        }
    };
    p
}

fn plan_restart(
    p: &mut Prepared,
    live: &Live,
    restart: Restart,
    stopped: bool,
) -> Result<Plan, String> {
    let key = p.key;
    match restart {
        Restart::Unavailable(reason) => Err(reason.to_owned()),
        Restart::Unit { unit, user } => {
            let unit = unit.to_string();
            if !valid_unit_name(&unit) {
                return Err(format!("无法识别的服务名：{unit}"));
            }
            let props =
                unit_properties(&unit, user).map_err(|e| format!("查询服务 {unit} 失败：{e}"))?;
            let get = |k: &str| {
                props
                    .iter()
                    .find(|(pk, _)| pk == k)
                    .map(|(_, v)| v.as_str())
            };
            if get("Transient") == Some("yes") {
                // Transient units (systemd-run, launchers) cannot be restarted through systemctl.
                return if live.uid == my_uid() {
                    plan_relaunch(p, live, stopped)
                } else {
                    Err("临时服务单元中的非本用户进程：只能结束".to_owned())
                };
            }
            let main = get("MainPID")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);
            let scope = if user {
                "systemctl --user"
            } else {
                "systemctl"
            };
            if main == key.pid {
                p.steps.push(format!("{scope} restart {unit}"));
            } else if main == 0 {
                p.steps.push(format!(
                    "systemd 未记录该服务的主进程，将重启整个服务：{scope} restart {unit}"
                ));
            } else {
                p.steps.push(format!(
                    "该进程不是服务主进程（MainPID={main}），将重启整个服务：{scope} restart {unit}"
                ));
            }
            if get("KillMode") == Some("process") {
                p.warnings.push(format!(
                    "{unit} 的 KillMode=process：重启只替换主进程，服务里的其他进程会保留"
                ));
            }
            if !user && my_uid() != 0 {
                p.warnings.push(privilege_note());
            }
            Ok(Plan::Unit { unit, user })
        }
        Restart::Docker { id } => {
            if !(id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())) {
                return Err("无法识别的容器 ID".to_owned());
            }
            p.steps.push(format!("docker restart {}", &id[..12]));
            p.warnings
                .push("将重启整个容器，容器内的所有进程都会重新启动".to_owned());
            Ok(Plan::Docker { id: id.to_string() })
        }
        Restart::Kube => {
            let (init, init_comm) = container_init(&live.cgroup).ok_or("找不到容器的主进程")?;
            let pod_slice = Path::new(&live.cgroup)
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            let init_privileged = init_uid(init).is_none_or(|u| u != my_uid()) && my_uid() != 0;
            p.steps.push(format!(
                "向容器主进程 {init_comm}（PID {}）发送 SIGTERM",
                init.pid
            ));
            p.steps.push(format!(
                "等待 kubelet 在同一 pod 中重建容器（最多 {} 秒）",
                KUBE_RECREATE_WAIT.as_secs()
            ));
            if init_comm == "pause" {
                p.warnings
                    .push("这是 pod 的 pause（sandbox）容器，结束它会重建整个 pod".to_owned());
            }
            if init_privileged {
                p.warnings.push(privilege_note());
            }
            Ok(Plan::Kube {
                init,
                pod_slice,
                privileged: init_privileged,
            })
        }
        Restart::Snap { app } => {
            p.steps
                .push(format!("向 PID {} 发送 SIGTERM 并等待退出", key.pid));
            p.steps.push(format!("snap run {app}"));
            Ok(Plan::Launcher {
                key,
                cont: stopped,
                program: "snap",
                args: vec!["run".into(), app.to_string()],
            })
        }
        Restart::Flatpak { app } => {
            p.steps
                .push(format!("向 PID {} 发送 SIGTERM 并等待退出", key.pid));
            p.steps.push(format!("flatpak run {app}"));
            Ok(Plan::Launcher {
                key,
                cont: stopped,
                program: "flatpak",
                args: vec!["run".into(), app.to_string()],
            })
        }
        Restart::Relaunch => plan_relaunch(p, live, stopped),
    }
}

fn plan_relaunch(p: &mut Prepared, live: &Live, stopped: bool) -> Result<Plan, String> {
    // Browser/Electron helpers cannot be started on their own; restart the main process.
    let (key, target) = main_process_of(p.key, live)?;
    if key != p.key {
        p.steps.push(format!(
            "PID {} 是多进程应用的辅助进程，改为重启其主进程 PID {}",
            p.key.pid, key.pid
        ));
    }
    let target = match target {
        Some(t) => t,
        None => read_live(key)?,
    };
    let pid = key.pid;
    if target.argv.is_empty() {
        return Err("读不到命令行，无法重放".to_owned());
    }
    if let Some(tty) = (0..3).find_map(|fd| tty_of(pid, fd)) {
        return Err(format!(
            "进程的标准输入/输出连着终端 {tty}：脱离终端重启后多数程序会退出或空转，请回到终端执行"
        ));
    }
    let exe_link = fs::read_link(format!("/proc/{pid}/exe"))
        .map_err(|_| "读不到可执行文件路径（权限不足或进程已退出）".to_owned())?;
    let exe_meta =
        fs::metadata(format!("/proc/{pid}/exe")).map_err(|_| "读不到可执行文件".to_owned())?;
    let cwd = fs::read_link(format!("/proc/{pid}/cwd")).map_err(|_| "读不到工作目录".to_owned())?;
    let environ =
        fs::read(format!("/proc/{pid}/environ")).map_err(|_| "读不到环境变量".to_owned())?;
    let env = parse_environ(&environ);

    let (env, env_note) = choose_env(env, p.category == Category::App);
    if let Some(note) = env_note {
        p.warnings.push(note);
    }
    let path_var = env
        .iter()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v.clone());
    let cwd = if cwd.is_dir() {
        cwd
    } else {
        let home = env
            .iter()
            .find(|(k, _)| k == "HOME")
            .map(|(_, v)| PathBuf::from(v))
            .unwrap_or_else(|| "/".into());
        p.warnings
            .push(format!("原工作目录已不存在，改用 {}", home.display()));
        home
    };

    // argv[0] must name the running executable; otherwise the command line was rewritten
    // (`sshd: user@pts/0`, postgres titles) and replaying it would run something else.
    let argv0 = target.argv[0].clone();
    let resolved = resolve_program(&argv0, &cwd, path_var.as_deref()).ok_or_else(rewritten)?;
    let deleted_suffix = OsStr::new(" (deleted)");
    let same_file = fs::metadata(&resolved)
        .is_ok_and(|m| m.dev() == exe_meta.dev() && m.ino() == exe_meta.ino());
    if !same_file {
        let replaced = exe_link
            .as_os_str()
            .as_bytes()
            .strip_suffix(deleted_suffix.as_bytes())
            .is_some_and(|orig| {
                resolved.as_os_str().as_bytes() == orig
                    || fs::canonicalize(&resolved).is_ok_and(|c| c.as_os_str().as_bytes() == orig)
            });
        if !replaced {
            return Err(rewritten());
        }
        p.warnings
            .push("可执行文件已被更新（原文件已删除），将启动新版本".to_owned());
    }
    if !is_executable(&resolved) {
        return Err(format!("{} 不存在或不可执行", resolved.display()));
    }

    let uid = my_uid();
    let systemd_run = if classify::in_user_manager(&target.cgroup) {
        let bus = Path::new("/run/user")
            .join(uid.to_string())
            .join("systemd/private");
        match find_in_path("systemd-run", std::env::var_os("PATH").as_deref()) {
            Some(run) if bus.exists() => Some(run),
            _ => {
                p.warnings.push(
                    "未找到用户 systemd 管理器，新进程将作为 ProcGuard 的子进程启动".to_owned(),
                );
                None
            }
        }
    } else {
        None
    };
    let unit_name =
        (systemd_run.is_some() && p.category == Category::App).then(|| app_unit_name(&target.comm));

    let args: Vec<OsString> = target.argv[1..].to_vec();
    p.steps.push(format!(
        "向 PID {pid} 发送 SIGTERM，最多等待 {} 秒退出（不会自动强杀）",
        RESTART_EXIT_WAIT.as_secs()
    ));
    p.steps.push(format!(
        "在 {} 下重新启动：{} {}",
        cwd.display(),
        resolved.display(),
        args.iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    ));
    if systemd_run.is_some() {
        p.steps.push(
            "通过 systemd-run --user --scope 放入独立 scope（与原进程同属用户 systemd 管理）"
                .to_owned(),
        );
    }
    Ok(Plan::Relaunch(Box::new(Relaunch {
        key,
        ppid: target.ppid,
        cont: stopped,
        exe_path: resolved.clone(),
        program: resolved,
        argv0,
        args,
        cwd,
        env,
        systemd_run,
        unit_name,
    })))
}

fn rewritten() -> String {
    "命令行已被进程改写（argv[0] 与实际可执行文件不符），无法可靠重放".to_owned()
}

fn privilege_note() -> String {
    match escalator() {
        Some(Escalator::Sudo) => "需要管理员权限：将通过 sudo -n 执行".to_owned(),
        Some(Escalator::Pkexec) => "需要管理员权限：将通过 pkexec 弹出系统授权".to_owned(),
        None => "需要管理员权限，但未找到可用的 sudo 免密或 pkexec，执行会失败".to_owned(),
    }
}

/// Carries out a prepared plan and returns a message for the status bar.
pub fn execute(p: &Prepared) -> Result<String, String> {
    let plan = p.plan.as_ref().map_err(Clone::clone)?;
    // Nothing that decided the plan may have changed since the dialog opened.
    let live = read_live(p.key)?;
    if live.uid != p.uid || live.cgroup != p.cgroup {
        return Err("进程的用户或所属 cgroup 已变化，请重新操作".to_owned());
    }
    match plan {
        Plan::Signal {
            sig,
            privileged,
            cont,
        } => {
            let pidfd = open_verified(p.key)?;
            send(p.key, &pidfd, *sig, *privileged, *cont)?;
            let wait = if *sig == Signal::KILL {
                KILL_WAIT
            } else {
                TERM_WAIT
            };
            if wait_exit(&pidfd, wait) {
                Ok(format!(
                    "{}（PID {}）已{}",
                    p.name,
                    p.key.pid,
                    p.kind.label()
                ))
            } else if *sig == Signal::KILL {
                Err(format!(
                    "已发送 SIGKILL，但 {} 秒内进程仍在（可能处于不可中断的 D 状态）",
                    wait.as_secs()
                ))
            } else {
                Err(format!(
                    "已发送 SIGTERM，{} 秒内进程未退出，可尝试强制结束",
                    wait.as_secs()
                ))
            }
        }
        Plan::Unit { unit, user } => {
            let systemctl = find_in_path("systemctl", std::env::var_os("PATH").as_deref())
                .ok_or("找不到 systemctl")?;
            let out = if *user {
                Command::new(&systemctl)
                    .args(["--user", "restart", "--"])
                    .arg(unit)
                    .stdin(Stdio::null())
                    .output()
            } else {
                run_privileged(
                    &systemctl,
                    &[OsStr::new("restart"), OsStr::new("--"), OsStr::new(unit)],
                )
            }
            .map_err(|e| format!("执行 systemctl 失败：{e}"))?;
            check_output(&out, "systemctl restart")?;
            Ok(format!("服务 {unit} 已重启"))
        }
        Plan::Docker { id } => {
            let out = Command::new("docker")
                .args(["restart", "--"])
                .arg(id)
                .stdin(Stdio::null())
                .output()
                .map_err(|e| format!("执行 docker 失败：{e}"))?;
            check_output(&out, "docker restart")?;
            Ok(format!("容器 {} 已重启", &id[..12]))
        }
        Plan::Kube {
            init,
            pod_slice,
            privileged,
        } => {
            let pidfd = open_verified(*init)?;
            let since = boot_ticks();
            send(*init, &pidfd, Signal::TERM, *privileged, false)?;
            let deadline = Instant::now() + KUBE_RECREATE_WAIT;
            while Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(500));
                if let Some(pid) = newer_process_in(pod_slice, since) {
                    return Ok(format!("容器已由 kubelet 重建（新 PID {pid}）"));
                }
            }
            Err(format!(
                "已结束容器主进程，但 {} 秒内未见重建（restartPolicy 可能为 Never）",
                KUBE_RECREATE_WAIT.as_secs()
            ))
        }
        Plan::Launcher {
            key,
            cont,
            program,
            args,
        } => {
            stop_for_restart(*key, *cont)?;
            let launcher = find_in_path(program, std::env::var_os("PATH").as_deref())
                .ok_or_else(|| format!("找不到 {program}"))?;
            let mut cmd = Command::new(launcher);
            cmd.args(args).current_dir(
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| "/".into()),
            );
            let pid = spawn_detached(cmd)?;
            Ok(format!("{} 已通过 {program} 重新启动（PID {pid}）", p.name))
        }
        Plan::Relaunch(r) => {
            let since = boot_ticks();
            stop_for_restart(r.key, r.cont)?;
            if let Some(pid) = respawned(&r.exe_path, r.ppid, since) {
                return Ok(format!(
                    "{} 已被其父进程或守护进程自动拉起（PID {pid}），未重复启动",
                    p.name
                ));
            }
            let mut cmd = match &r.systemd_run {
                Some(run) => {
                    let mut c = Command::new(run);
                    c.args(["--user", "--scope", "--collect", "--quiet"]);
                    if let Some(name) = &r.unit_name {
                        c.arg(format!("--unit={name}"));
                    }
                    c.arg("--").arg(&r.program);
                    c
                }
                None => {
                    let mut c = Command::new(&r.program);
                    c.arg0(&r.argv0);
                    c
                }
            };
            cmd.args(&r.args)
                .current_dir(&r.cwd)
                .env_clear()
                .envs(r.env.iter().map(|(k, v)| (k, v)));
            if r.systemd_run.is_some() {
                // systemd-run needs these to reach the user manager; harmless for the app.
                for var in ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
                    if !r.env.iter().any(|(k, _)| k == var)
                        && let Some(v) = std::env::var_os(var)
                    {
                        cmd.env(var, v);
                    }
                }
            }
            let pid = spawn_detached(cmd)?;
            Ok(format!("{} 已重启（新 PID {pid}）", p.name))
        }
    }
}

/// SIGTERM for a restart, then wait for the process to be gone. Never escalates to SIGKILL on
/// its own: a process that ignores SIGTERM may be saving state.
fn stop_for_restart(key: ProcKey, cont: bool) -> Result<(), String> {
    let pidfd = open_verified(key)?;
    send(key, &pidfd, Signal::TERM, false, cont)?;
    if wait_exit(&pidfd, RESTART_EXIT_WAIT) {
        Ok(())
    } else {
        Err(format!(
            "进程 {} 秒内未退出，已放弃重启（进程仍在运行，可先强制结束）",
            RESTART_EXIT_WAIT.as_secs()
        ))
    }
}

/// Opens a pidfd and only then checks the start time: from that point on the fd pins the process
/// we verified, even if it exits and its pid is reused before the signal is sent.
fn open_verified(key: ProcKey) -> Result<OwnedFd, String> {
    let pid = Pid::from_raw(key.pid as i32).ok_or_else(gone)?;
    let fd = rustix::process::pidfd_open(pid, PidfdFlags::empty()).map_err(|_| gone())?;
    let stat = fs::read(format!("/proc/{}/stat", key.pid)).map_err(|_| gone())?;
    match procfs::parse_stat(&stat) {
        Some(s) if s.starttime == key.start => Ok(fd),
        Some(_) => Err(reused()),
        None => Err(gone()),
    }
}

fn send(
    key: ProcKey,
    pidfd: &OwnedFd,
    sig: Signal,
    privileged: bool,
    cont: bool,
) -> Result<(), String> {
    if !privileged {
        match rustix::process::pidfd_send_signal(pidfd, sig) {
            Ok(()) => {
                if cont {
                    let _ = rustix::process::pidfd_send_signal(pidfd, Signal::CONT);
                }
                return Ok(());
            }
            Err(rustix::io::Errno::SRCH) => return Err(gone()),
            // Our uid matches but the target changed its credentials (setuid); escalate.
            Err(rustix::io::Errno::PERM) => {}
            Err(e) => return Err(format!("发送信号失败：{e}")),
        }
    }
    privileged_kill(key, sig, cont)
}

/// Runs the kill as root through a tiny `sh` script that re-checks the start time right before
/// signalling. Arguments travel as argv, never interpolated into the script.
fn privileged_kill(key: ProcKey, sig: Signal, cont: bool) -> Result<(), String> {
    const SCRIPT: &str = r#"set -f; p=$1 e=$2 s=$3 c=$4
st=$(cat "/proc/$p/stat" 2>/dev/null) || exit 3
set -- ${st##*) }
[ "${20}" = "$e" ] || exit 4
kill -s "$s" "$p" || exit 5
[ "$c" = 1 ] && kill -s CONT "$p"
exit 0"#;
    let name = if sig == Signal::KILL { "KILL" } else { "TERM" };
    let (pid, start) = (key.pid.to_string(), key.start.to_string());
    let args = [
        OsStr::new("-c"),
        OsStr::new(SCRIPT),
        OsStr::new("procguard-kill"),
        OsStr::new(&pid),
        OsStr::new(&start),
        OsStr::new(name),
        OsStr::new(if cont { "1" } else { "0" }),
    ];
    let out =
        run_privileged(Path::new("/bin/sh"), &args).map_err(|e| format!("提权执行失败：{e}"))?;
    match out.status.code() {
        Some(0) => Ok(()),
        Some(3) => Err(gone()),
        Some(4) => Err(reused()),
        Some(126) => Err("已取消授权".to_owned()),
        Some(127) if matches!(escalator(), Some(Escalator::Pkexec)) => Err(format!(
            "pkexec 未获授权（会话中可能没有 polkit 认证代理）：{}",
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        _ => Err(format!(
            "提权结束进程失败：{}",
            String::from_utf8_lossy(&out.stderr).trim()
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Escalator {
    Sudo,
    Pkexec,
}

/// `sudo -n` when it works without a password, else pkexec (polkit's own dialog). The app never
/// handles a password itself.
fn escalator() -> Option<Escalator> {
    static E: OnceLock<Option<Escalator>> = OnceLock::new();
    *E.get_or_init(|| {
        let sudo_ok = Command::new("sudo")
            .args(["-n", "true"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if sudo_ok {
            Some(Escalator::Sudo)
        } else {
            find_in_path("pkexec", std::env::var_os("PATH").as_deref()).map(|_| Escalator::Pkexec)
        }
    })
}

fn run_privileged(program: &Path, args: &[&OsStr]) -> io::Result<std::process::Output> {
    let mut cmd = match escalator() {
        Some(Escalator::Sudo) => {
            let mut c = Command::new("sudo");
            c.args(["-n", "--"]).arg(program);
            c
        }
        Some(Escalator::Pkexec) => {
            let mut c = Command::new("pkexec");
            c.arg(program);
            c
        }
        None => return Err(io::Error::other("没有可用的提权方式（sudo 免密或 pkexec）")),
    };
    cmd.args(args).stdin(Stdio::null()).output()
}

fn check_output(out: &std::process::Output, what: &str) -> Result<(), String> {
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    let err = err.trim();
    Err(if err.is_empty() {
        format!("{what} 失败（{}）", out.status)
    } else {
        format!("{what} 失败：{err}")
    })
}

/// `true` once the process behind `pidfd` has exited.
fn wait_exit(pidfd: &OwnedFd, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let Ok(ts) = Timespec::try_from(left) else {
            return false;
        };
        let mut fds = [PollFd::new(pidfd, PollFlags::IN)];
        match rustix::event::poll(&mut fds, Some(&ts)) {
            Ok(n) if n > 0 => return true,
            Ok(_) => return false,
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return false,
        }
    }
}

/// Spawns detached from ProcGuard: own process group, no stdio. A thread reaps the child so it
/// does not linger as a zombie; `waitpid(-1)` is never used, as it would steal other children's
/// exit statuses. Reports a launch that fails within the first second.
fn spawn_detached(mut cmd: Command) -> Result<u32, String> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child: Child = cmd.spawn().map_err(|e| format!("启动失败：{e}"))?;
    let pid = child.id();
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) if !status.success() => {
                return Err(format!("新进程启动后立即退出（{status}）"));
            }
            Ok(Some(_)) => return Ok(pid),
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(format!("等待新进程失败：{e}")),
        }
    }
    std::thread::Builder::new()
        .name(format!("reap-{pid}"))
        .stack_size(64 * 1024)
        .spawn(move || {
            let _ = child.wait();
        })
        .map_err(|e| format!("无法创建回收线程：{e}"))?;
    Ok(pid)
}

/// Current time as clock ticks since boot, comparable to a process's `starttime`.
fn boot_ticks() -> u64 {
    let uptime = fs::read("/proc/uptime")
        .ok()
        .and_then(|b| procfs::parse_uptime(&b))
        .unwrap_or(0.0);
    (uptime * rustix::param::clock_ticks_per_second() as f64) as u64
}

/// A process of ours running `exe` under the same parent that started after `since` (clock ticks
/// since boot): the session manager or supervisor already brought the program back. Matching the
/// parent keeps an unrelated instance of a common program (bash, python) from counting.
/// Waits up to RESPAWN_WINDOW.
fn respawned(exe: &Path, ppid: u32, since: u64) -> Option<u32> {
    let target = fs::metadata(exe).ok()?;
    let deadline = Instant::now() + RESPAWN_WINDOW;
    loop {
        for (pid, parent, start) in own_processes() {
            if start > since
                && parent == ppid
                && fs::metadata(format!("/proc/{pid}/exe"))
                    .is_ok_and(|m| m.dev() == target.dev() && m.ino() == target.ino())
            {
                return Some(pid);
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// (pid, ppid, starttime) of our own live processes.
fn own_processes() -> Vec<(u32, u32, u64)> {
    let uid = my_uid();
    let Ok(dir) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    dir.flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter_map(|pid| {
            let meta = fs::metadata(format!("/proc/{pid}")).ok()?;
            if meta.uid() != uid {
                return None;
            }
            let stat = fs::read(format!("/proc/{pid}/stat")).ok()?;
            let s = procfs::parse_stat(&stat)?;
            (s.state != b'Z').then_some((pid, s.ppid, s.starttime))
        })
        .collect()
}

/// The container's init: the oldest process in the container's cgroup.
fn container_init(cgroup: &str) -> Option<(ProcKey, String)> {
    let mut best: Option<(ProcKey, String)> = None;
    for (pid, cg, s_start, comm) in processes_with_cgroup() {
        if cg == cgroup && best.as_ref().is_none_or(|(k, _)| s_start < k.start) {
            best = Some((
                ProcKey {
                    pid,
                    start: s_start,
                },
                comm,
            ));
        }
    }
    best
}

fn newer_process_in(slice: &str, since: u64) -> Option<u32> {
    let prefix = format!("{slice}/");
    processes_with_cgroup()
        .into_iter()
        .find(|(_, cg, start, _)| cg.starts_with(&prefix) && *start > since)
        .map(|(pid, ..)| pid)
}

fn processes_with_cgroup() -> Vec<(u32, String, u64, String)> {
    let Ok(dir) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    dir.flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter_map(|pid| {
            let stat = fs::read(format!("/proc/{pid}/stat")).ok()?;
            let s = procfs::parse_stat(&stat)?;
            let cg = fs::read(format!("/proc/{pid}/cgroup")).ok()?;
            let cg = procfs::parse_cgroup(&cg)?.to_owned();
            Some((
                pid,
                cg,
                s.starttime,
                String::from_utf8_lossy(s.comm).into_owned(),
            ))
        })
        .collect()
}

fn init_uid(key: ProcKey) -> Option<u32> {
    procfs::parse_status(&fs::read(format!("/proc/{}/status", key.pid)).ok()?).map(|s| s.uid)
}

/// Walks from a browser/Electron helper up to its main process (same executable, no helper
/// flag). Returns the target key and, when it is not the original process, its facts.
fn main_process_of(key: ProcKey, live: &Live) -> Result<(ProcKey, Option<Live>), String> {
    if !classify::is_app_helper(&live.cmdline) {
        return Ok((key, None));
    }
    let exe = fs::metadata(format!("/proc/{}/exe", key.pid))
        .map_err(|_| "读不到可执行文件".to_owned())?;
    let (mut cur_key, mut cur) = (key, None::<Live>);
    let mut cur_cmdline = live.cmdline.clone();
    let mut ppid = live.ppid;
    for _ in 0..8 {
        if !classify::is_app_helper(&cur_cmdline) {
            break;
        }
        let Some(start) = read_start(ppid) else { break };
        let parent_key = ProcKey { pid: ppid, start };
        let same_exe = fs::metadata(format!("/proc/{ppid}/exe"))
            .is_ok_and(|m| m.dev() == exe.dev() && m.ino() == exe.ino());
        if !same_exe {
            break;
        }
        let parent = read_live(parent_key)?;
        cur_cmdline.clone_from(&parent.cmdline);
        ppid = parent.ppid;
        cur_key = parent_key;
        cur = Some(parent);
    }
    Ok((cur_key, cur))
}

fn read_start(pid: u32) -> Option<u64> {
    procfs::parse_stat(&fs::read(format!("/proc/{pid}/stat")).ok()?).map(|s| s.starttime)
}

fn read_comm(pid: u32) -> Option<String> {
    let stat = fs::read(format!("/proc/{pid}/stat")).ok()?;
    procfs::parse_stat(&stat).map(|s| String::from_utf8_lossy(s.comm).into_owned())
}

fn ancestors_of_self() -> Vec<u32> {
    let mut out = Vec::new();
    let mut pid = std::process::id();
    for _ in 0..64 {
        let Some(ppid) = fs::read(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|b| procfs::parse_stat(&b).map(|s| s.ppid))
        else {
            break;
        };
        if ppid <= 1 {
            break;
        }
        out.push(ppid);
        pid = ppid;
    }
    out
}

fn tty_of(pid: u32, fd: u32) -> Option<String> {
    let target = fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?;
    let t = target.to_string_lossy();
    (t.starts_with("/dev/pts/") || t.starts_with("/dev/tty")).then(|| t.into_owned())
}

fn parse_environ(buf: &[u8]) -> Vec<(OsString, OsString)> {
    procfs::split_nul(buf)
        .filter_map(|kv| {
            let eq = kv.iter().position(|&b| b == b'=')?;
            (eq > 0).then(|| {
                (
                    OsString::from_vec(kv[..eq].to_vec()),
                    OsString::from_vec(kv[eq + 1..].to_vec()),
                )
            })
        })
        .collect()
}

/// Keeps the original environment when it looks usable. Some programs (Chrome) overwrite their
/// environ area with the process title, leaving nothing but NULs.
fn choose_env(
    env: Vec<(OsString, OsString)>,
    gui: bool,
) -> (Vec<(OsString, OsString)>, Option<String>) {
    let has = |k: &str| env.iter().any(|(ek, v)| ek == k && !v.is_empty());
    let mut missing: Vec<&str> = ["PATH", "HOME"].into_iter().filter(|k| !has(k)).collect();
    if gui && !has("DISPLAY") && !has("WAYLAND_DISPLAY") {
        missing.push("DISPLAY/WAYLAND_DISPLAY");
    }
    if missing.is_empty() {
        return (env, None);
    }
    let ours: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let note = format!(
        "原进程的环境变量不完整（缺少 {}），将改用 ProcGuard 的环境变量",
        missing.join("、")
    );
    (ours, Some(note))
}

fn resolve_program(argv0: &OsStr, cwd: &Path, path_var: Option<&OsStr>) -> Option<PathBuf> {
    let bytes = argv0.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    if bytes.contains(&b'/') {
        let p = Path::new(argv0);
        let p = if p.is_absolute() {
            p.to_path_buf()
        } else {
            cwd.join(p)
        };
        return p.exists().then_some(p);
    }
    find_in_path(argv0, path_var.or(std::env::var_os("PATH").as_deref()))
}

fn find_in_path(name: impl AsRef<OsStr>, path_var: Option<&OsStr>) -> Option<PathBuf> {
    let name = name.as_ref();
    let default = OsStr::new("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    std::env::split_paths(path_var.unwrap_or(default))
        .map(|dir| dir.join(name))
        .find(|p| is_executable(p))
}

fn is_executable(p: &Path) -> bool {
    fs::metadata(p).is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0)
}

/// `systemd.unit(5)` name characters; guards the argument even though it comes from a cgroup
/// path written by systemd.
fn valid_unit_name(unit: &str) -> bool {
    !unit.is_empty()
        && unit.len() <= 255
        && !unit.starts_with('-')
        && unit
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":_.\\@-".contains(&b))
}

fn unit_properties(unit: &str, user: bool) -> Result<Vec<(String, String)>, String> {
    let systemctl =
        find_in_path("systemctl", std::env::var_os("PATH").as_deref()).ok_or("找不到 systemctl")?;
    let mut cmd = Command::new(systemctl);
    if user {
        cmd.arg("--user");
    }
    let out = cmd
        .args([
            "show",
            "-p",
            "MainPID",
            "-p",
            "KillMode",
            "-p",
            "Transient",
            "--",
        ])
        .arg(unit)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    check_output(&out, "systemctl show")?;
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
        .collect())
}

/// Scope name following the XDG `app-<launcher>-<id>-<random>.scope` convention, so a restarted
/// application stays recognisable as one.
fn app_unit_name(comm: &str) -> String {
    let id: String = comm
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(40)
        .collect();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() % 1_000_000_000)
        .unwrap_or(0);
    format!("app-procguard-{id}-{nonce}.scope")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environ_parsing_and_fallback() {
        let env = parse_environ(b"PATH=/usr/bin\0HOME=/home/u\0EMPTY=\0=bad\0noeq\0A=b=c\0");
        assert_eq!(env.len(), 4);
        assert_eq!(env[3], (OsString::from("A"), OsString::from("b=c")));
        let (kept, note) = choose_env(env.clone(), false);
        assert!(note.is_none());
        assert_eq!(kept, env);
        // Chrome-like: environ overwritten with NULs.
        let (_, note) = choose_env(parse_environ(&[0u8; 64]), true);
        assert!(note.unwrap().contains("PATH"));
        let (_, note) = choose_env(env, true);
        assert!(note.unwrap().contains("DISPLAY"));
    }

    #[test]
    fn unit_names() {
        assert!(valid_unit_name("pipewire.service"));
        assert!(valid_unit_name("sshd@3-10.0.0.1:22-10.0.0.2:5555.service"));
        assert!(valid_unit_name("app-gnome-pipewire\\x2dxrdp-43921.scope"));
        assert!(!valid_unit_name("--now"));
        assert!(!valid_unit_name("a b.service"));
        assert!(!valid_unit_name("x;rm.service"));
        let n = app_unit_name("chrome (x)");
        assert!(
            n.starts_with("app-procguard-chrome__x_-")
                && n.ends_with(".scope")
                && valid_unit_name(&n)
        );
    }

    /// Needs `sudo -n`. The root-side identity check must refuse a mismatching start time.
    #[test]
    #[ignore]
    fn privileged_script_refuses_mismatched_start_time() {
        let mut child = Command::new("sudo")
            .args(["-n", "sleep", "600"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("sudo -n");
        std::thread::sleep(Duration::from_millis(300));
        // sudo forks the command: the root sleep is sudo's child.
        let pid = fs::read_dir("/proc")
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .find(|&p| {
                read_start(p).is_some()
                    && fs::read(format!("/proc/{p}/stat"))
                        .ok()
                        .and_then(|b| procfs::parse_stat(&b).map(|s| s.ppid))
                        == Some(child.id())
            })
            .expect("root sleep");
        let start = read_start(pid).unwrap();
        let err = privileged_kill(
            ProcKey {
                pid,
                start: start + 1,
            },
            Signal::KILL,
            false,
        )
        .unwrap_err();
        assert_eq!(err, reused());
        assert!(read_start(pid).is_some(), "must not be killed");
        privileged_kill(ProcKey { pid, start }, Signal::KILL, false)
            .expect("kill with the right identity");
        child.wait().unwrap();
        assert!(read_start(pid).is_none());
    }

    #[test]
    fn program_resolution() {
        let path = OsStr::new("/usr/bin:/bin");
        let sh = resolve_program(OsStr::new("sh"), Path::new("/"), Some(path)).unwrap();
        assert!(sh.ends_with("sh"));
        assert_eq!(
            resolve_program(OsStr::new("/bin/sh"), Path::new("/"), None),
            Some(PathBuf::from("/bin/sh"))
        );
        assert_eq!(
            resolve_program(OsStr::new("sshd: user@pts/0"), Path::new("/"), Some(path)),
            None
        );
        assert_eq!(
            resolve_program(OsStr::new(""), Path::new("/"), Some(path)),
            None
        );
    }
}
