//! End-to-end checks of terminate/kill/restart against real child processes.
//!
//! Every target is a `setsid`-detached copy of `sleep` spawned by the test itself, so nothing
//! outside the test is ever signalled. Copies get unique file names, which keeps the restart
//! respawn check from matching another test's sleep.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use procguard::actions::{self, Kind, Plan};
use procguard::collector::{Collector, ProcKey, Row};

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "procguard-test-{}-{tag}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// A private copy of `sleep`, so its inode identifies only this test's processes.
    fn sleep_copy(&self, name: &str) -> PathBuf {
        let src = ["/usr/bin/sleep", "/bin/sleep"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .unwrap();
        let dst = self.0.join(name);
        fs::copy(src, &dst).unwrap();
        fs::set_permissions(&dst, fs::Permissions::from_mode(0o755)).unwrap();
        dst
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// `setsid <prog> 600`: own session, no controlling terminal, stdio on /dev/null.
fn spawn(prog: &Path, cwd: &Path, env: &[(&str, &str)], clear_env: bool) -> Child {
    // Tests run in parallel threads: a fork elsewhere can briefly inherit the write fd of a
    // freshly copied binary, making its exec fail with ETXTBSY. Retry in that case.
    for _ in 0..5 {
        let mut cmd = Command::new("setsid");
        cmd.arg(prog)
            .arg("600")
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if clear_env {
            // setsid itself must still be found.
            cmd.env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default());
        }
        cmd.envs(env.iter().copied());
        let mut child = cmd.spawn().unwrap();
        // setsid execs the program in place (the child is not a group leader), so the pid is the
        // sleep's; wait until the exec happened.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if fs::read_link(format!("/proc/{}/exe", child.id())).is_ok_and(|e| e.as_path() == prog)
            {
                return child;
            }
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = child.kill();
        let _ = child.wait();
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("{} did not start", prog.display());
}

fn row_of(pid: u32) -> Row {
    let mut c = Collector::new(false);
    let snap = c.sample(None);
    snap.rows
        .into_iter()
        .find(|r| r.key.pid == pid)
        .expect("process sampled")
}

fn exited_within(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

fn kill_pid(pid: u32) {
    let _ = Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status();
}

#[test]
fn terminate_own_process() {
    let s = Scratch::new("term");
    let prog = s.sleep_copy("pg-term");
    let mut child = spawn(&prog, &s.0, &[], false);
    let prepared = actions::prepare(&row_of(child.id()), Kind::Terminate);
    assert!(
        matches!(
            prepared.plan,
            Ok(Plan::Signal {
                privileged: false,
                cont: false,
                ..
            })
        ),
        "{:?}",
        prepared.plan
    );
    let msg = actions::execute(&prepared).expect("terminate");
    assert!(msg.contains("已结束"), "{msg}");
    assert!(exited_within(&mut child, Duration::from_secs(2)));
}

#[test]
fn refuses_a_reused_pid() {
    let s = Scratch::new("reuse");
    let prog = s.sleep_copy("pg-reuse");
    let mut child = spawn(&prog, &s.0, &[], false);
    let mut row = row_of(child.id());
    // Pretend the row was sampled from an earlier process that had this pid.
    row.key = ProcKey {
        pid: row.key.pid,
        start: row.key.start - 1,
    };
    for kind in [Kind::Terminate, Kind::Kill, Kind::Restart] {
        let prepared = actions::prepare(&row, kind);
        let err = prepared
            .plan
            .as_ref()
            .expect_err("stale identity must be refused");
        assert!(err.contains("复用"), "{err}");
        assert!(actions::execute(&prepared).is_err());
    }
    assert!(
        child.try_wait().unwrap().is_none(),
        "the live process must not be touched"
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn stopped_process_gets_sigcont_after_sigterm() {
    let s = Scratch::new("stop");
    let prog = s.sleep_copy("pg-stopped");
    let mut child = spawn(&prog, &s.0, &[], false);
    assert!(
        Command::new("kill")
            .args(["-STOP", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    while row_of(child.id()).state != b'T' {
        assert!(Instant::now() < deadline, "process did not stop");
        std::thread::sleep(Duration::from_millis(20));
    }
    let prepared = actions::prepare(&row_of(child.id()), Kind::Terminate);
    assert!(
        matches!(prepared.plan, Ok(Plan::Signal { cont: true, .. })),
        "{:?}",
        prepared.plan
    );
    actions::execute(&prepared).expect("terminate stopped process");
    assert!(exited_within(&mut child, Duration::from_secs(2)));
}

fn new_pid(msg: &str) -> u32 {
    let digits: String = msg
        .rsplit("PID ")
        .next()
        .unwrap()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits
        .parse()
        .unwrap_or_else(|_| panic!("no pid in {msg:?}"))
}

#[test]
fn restart_keeps_argv_cwd_and_environment() {
    let s = Scratch::new("restart");
    let prog = s.sleep_copy("pg-restart");
    let mut child = spawn(&prog, &s.0, &[("PROCGUARD_TEST_MARK", "keep-me")], false);
    let prepared = actions::prepare(&row_of(child.id()), Kind::Restart);
    assert!(
        matches!(prepared.plan, Ok(Plan::Relaunch(_))),
        "{:?}",
        prepared.plan
    );
    assert!(prepared.warnings.is_empty(), "{:?}", prepared.warnings);

    let msg = actions::execute(&prepared).expect("restart");
    assert!(exited_within(&mut child, Duration::from_secs(2)));
    let pid = new_pid(&msg);
    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap();
    let cwd = fs::read_link(format!("/proc/{pid}/cwd")).unwrap();
    let environ = fs::read(format!("/proc/{pid}/environ")).unwrap();
    kill_pid(pid);

    assert_eq!(
        cmdline,
        format!("{}\x00600\x00", prog.display()).into_bytes()
    );
    assert_eq!(cwd, s.0);
    assert!(
        environ
            .split(|&b| b == 0)
            .any(|kv| kv == b"PROCGUARD_TEST_MARK=keep-me")
    );
}

#[test]
fn restart_falls_back_to_own_environment_when_original_is_unusable() {
    let s = Scratch::new("env");
    let prog = s.sleep_copy("pg-noenv");
    // No HOME in the target's environment.
    let mut child = spawn(&prog, &s.0, &[], true);
    let prepared = actions::prepare(&row_of(child.id()), Kind::Restart);
    assert!(
        matches!(prepared.plan, Ok(Plan::Relaunch(_))),
        "{:?}",
        prepared.plan
    );
    assert!(
        prepared.warnings.iter().any(|w| w.contains("环境变量")),
        "{:?}",
        prepared.warnings
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn restart_of_replaced_binary_starts_the_new_version() {
    let s = Scratch::new("deleted");
    let prog = s.sleep_copy("pg-upgraded");
    let mut child = spawn(&prog, &s.0, &[], false);
    // Simulate a package upgrade: the running binary is replaced by a new file.
    fs::remove_file(&prog).unwrap();
    s.sleep_copy("pg-upgraded");
    let prepared = actions::prepare(&row_of(child.id()), Kind::Restart);
    assert!(
        prepared.warnings.iter().any(|w| w.contains("新版本")),
        "{:?} {:?}",
        prepared.warnings,
        prepared.plan
    );
    let msg = actions::execute(&prepared).expect("restart");
    assert!(exited_within(&mut child, Duration::from_secs(2)));
    kill_pid(new_pid(&msg));
}

#[test]
fn restart_is_refused_for_ancestors_and_protected_processes() {
    let parent = std::os::unix::process::parent_id();
    let prepared = actions::prepare(&row_of(parent), Kind::Restart);
    assert!(
        prepared.plan.is_err(),
        "restarting our own ancestor must be refused"
    );

    let init = actions::prepare(&row_of(1), Kind::Kill);
    assert!(init.plan.unwrap_err().contains("受保护"));
    let me = actions::prepare(&row_of(std::process::id()), Kind::Terminate);
    assert!(me.plan.unwrap_err().contains("受保护"));
}

/// Needs a systemd user manager; creates (and cleans up) a transient scope.
#[test]
#[ignore]
fn restart_inside_user_manager_goes_through_systemd_run() {
    let s = Scratch::new("scope");
    let prog = s.sleep_copy("pg-scope");
    let mut child = Command::new("systemd-run")
        .args(["--user", "--scope", "--collect", "--quiet", "--"])
        .arg(&prog)
        .arg("600")
        .current_dir(&s.0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let row = row_of(child.id());
    assert!(row.info.cgroup.contains("/user@"), "{}", row.info.cgroup);
    let prepared = actions::prepare(&row, Kind::Restart);
    assert!(
        prepared.steps.iter().any(|s| s.contains("systemd-run")),
        "{:?} {:?}",
        prepared.steps,
        prepared.plan
    );
    let msg = actions::execute(&prepared).expect("restart");
    assert!(exited_within(&mut child, Duration::from_secs(2)));
    let pid = new_pid(&msg);
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
    kill_pid(pid);
    assert!(
        cgroup.contains("/user@") && cgroup.contains(".scope"),
        "{cgroup}"
    );
}
