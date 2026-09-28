//! Escalated and service/container actions. These change real system state (a root process, a
//! system service, a throwaway container), so they only run on request:
//! `cargo test --test privileged -- --ignored` (needs `sudo -n`, systemd and docker).

use std::fs;
use std::process::{Command, Stdio};
use std::time::Duration;

use procguard::actions::{self, Kind, Plan};
use procguard::collector::{Collector, Row};

fn rows() -> Vec<Row> {
    Collector::new(false).sample(None).rows
}

fn cmd_out(program: &str, args: &[&str]) -> String {
    let out = Command::new(program).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

#[test]
#[ignore]
fn terminates_a_root_process_through_sudo() {
    let mut sudo = Command::new("sudo")
        .args(["-n", "sleep", "601"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sudo -n");
    std::thread::sleep(Duration::from_millis(300));
    let row = rows()
        .into_iter()
        .find(|r| r.ppid == sudo.id() && r.info.uid == 0)
        .expect("root sleep");
    assert!(row.class.protect.is_none());
    let prepared = actions::prepare(&row, Kind::Terminate);
    assert!(
        matches!(
            prepared.plan,
            Ok(Plan::Signal {
                privileged: true,
                ..
            })
        ),
        "{:?}",
        prepared.plan
    );
    assert!(
        prepared.warnings.iter().any(|w| w.contains("sudo")),
        "{:?}",
        prepared.warnings
    );
    actions::execute(&prepared).expect("terminate root process");
    sudo.wait().unwrap();
    assert!(fs::metadata(format!("/proc/{}", row.key.pid)).is_err());
}

#[test]
#[ignore]
fn restarts_a_system_service() {
    let unit = "kerneloops.service";
    let before: Vec<Row> = rows()
        .into_iter()
        .filter(|r| r.info.cgroup.ends_with(&format!("/{unit}")))
        .collect();
    let target = before
        .iter()
        .min_by_key(|r| r.key.start)
        .expect("kerneloops running");
    let prepared = actions::prepare(target, Kind::Restart);
    assert!(
        matches!(&prepared.plan, Ok(Plan::Unit { user: false, .. })),
        "{:?}",
        prepared.plan
    );
    actions::execute(&prepared).expect("systemctl restart");
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(cmd_out("systemctl", &["is-active", unit]), "active");
    let after: Vec<Row> = rows()
        .into_iter()
        .filter(|r| r.info.cgroup.ends_with(&format!("/{unit}")))
        .collect();
    assert!(!after.is_empty());
    assert!(
        after.iter().all(|a| before.iter().all(|b| a.key != b.key)),
        "all processes replaced"
    );
}

#[test]
#[ignore]
fn restarts_a_docker_container() {
    let name = format!("procguard-test-{}", std::process::id());
    let id = cmd_out(
        "docker",
        &[
            "run",
            "-d",
            "--rm",
            "--name",
            &name,
            "--entrypoint",
            "sleep",
            "alpine:3.21",
            "600",
        ],
    );
    std::thread::sleep(Duration::from_millis(500));
    let started = cmd_out("docker", &["inspect", "-f", "{{.State.StartedAt}}", &id]);
    let row = rows()
        .into_iter()
        .find(|r| r.info.cgroup.contains(&id))
        .expect("container process");
    let prepared = actions::prepare(&row, Kind::Restart);
    let result = match &prepared.plan {
        Ok(Plan::Docker { .. }) => actions::execute(&prepared),
        other => Err(format!("unexpected plan {other:?}")),
    };
    let restarted = cmd_out("docker", &["inspect", "-f", "{{.State.StartedAt}}", &id]);
    let _ = Command::new("docker").args(["rm", "-f", &id]).output();
    result.expect("docker restart");
    assert_ne!(started, restarted);
}

#[test]
#[ignore]
fn never_restarts_the_bus_for_a_dbus_activated_helper() {
    let user_bus = cmd_out(
        "systemctl",
        &["--user", "show", "-p", "MainPID", "--value", "dbus.service"],
    );
    let Some(helper) = rows().into_iter().find(|r| {
        r.info.cgroup.ends_with("/dbus.service")
            && r.class.protect.is_none()
            && r.info.uid == rustix::process::getuid().as_raw()
    }) else {
        eprintln!("no D-Bus-activated helper running; nothing to check");
        return;
    };
    let prepared = actions::prepare(&helper, Kind::Restart);
    assert!(prepared.plan.is_err(), "{:?}", prepared.plan);
    assert_eq!(
        cmd_out(
            "systemctl",
            &["--user", "show", "-p", "MainPID", "--value", "dbus.service"]
        ),
        user_bus
    );
}
