//! Periodic sampling of all processes into a [`Snapshot`].
//!
//! Per pass every process costs one `stat` read, plus `io` for processes we may read. Everything
//! else (`status`, `cmdline`, `cgroup`) is re-read only when it can have changed: new or young
//! processes, a changed RSS, a changed comm (exec), or a slow round-robin refresh.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::ErrorKind;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::classify::{self, Class, Env, Facts, Restart};
use crate::procfs::{self, CpuTimes, MemInfo, PF_KTHREAD, Reader};
use crate::session::{Sessions, Users, X11Windows};

/// Identifies one process across pid reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcKey {
    pub pid: u32,
    pub start: u64,
}

/// Slowly changing facts, shared between snapshots until one of them changes.
#[derive(Debug, PartialEq, Eq)]
pub struct ProcInfo {
    pub name: Box<str>,
    pub comm: Box<str>,
    pub cmdline: Box<str>,
    pub uid: u32,
    pub user: Arc<str>,
    pub cgroup: Box<str>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Mem {
    pub anon: u64,
    pub swap: u64,
    pub rss: u64,
    pub file: u64,
    pub shmem: u64,
}

/// Disk IO rate in bytes per second.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Io {
    /// Not readable (another user's process) or no second sample yet.
    Unknown,
    Proc {
        read: f64,
        write: f64,
    },
    /// Whole systemd unit / container from cgroup `io.stat`, shown on its oldest process.
    Unit {
        read: f64,
        write: f64,
    },
}

impl Io {
    pub fn total(&self) -> Option<f64> {
        match *self {
            Io::Unknown => None,
            Io::Proc { read, write } | Io::Unit { read, write } => Some(read + write),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Row {
    pub key: ProcKey,
    pub ppid: u32,
    pub info: Arc<ProcInfo>,
    pub state: u8,
    pub threads: u32,
    pub tty: bool,
    pub kthread: bool,
    pub age: Duration,
    pub mem: Mem,
    /// Share of the whole machine, 0–100; `None` until a second sample exists.
    pub cpu: Option<f32>,
    pub io: Io,
    pub class: Class,
    pub restart: Restart,
    pub self_ancestor: bool,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub rows: Vec<Row>,
    pub cpu_total: Option<f32>,
    pub mem: MemInfo,
    /// CPU time the collector thread spent on this pass.
    pub cost: Duration,
    pub taken: Instant,
    pub self_pid: u32,
    pub window_detection: bool,
}

struct Entry {
    /// `/proc/<pid>/stat` kept open: re-reading it with pread skips path lookup, open and close
    /// (measured 3.3 ms instead of 5.7 ms per pass for ~520 processes). An fd of an exited
    /// process fails with ESRCH even if the pid was reused, so it can never read a stranger.
    stat_file: Option<File>,
    start: u64,
    info: Arc<ProcInfo>,
    cpu_ticks: u64,
    /// Last `/proc/<pid>/io` counters and when they were read.
    io: Option<(u64, u64, Instant)>,
    io_rate: Option<(f64, f64)>,
    io_denied: bool,
    rss_pages: u64,
    mem: Mem,
    refresh_at: u64,
    seen: u64,
}

/// Processes younger than this are fully re-read every pass: they are the ones that exec,
/// setuid or move themselves into another cgroup (Chrome does).
const YOUNG: Duration = Duration::from_secs(10);
/// Round-robin period, in passes, for re-reading the slowly changing facts of old processes.
const REFRESH_PASSES: u64 = 15;

pub struct Collector {
    reader: Reader,
    stat_buf: Vec<u8>,
    /// How many stat fds may stay open, below RLIMIT_NOFILE with headroom for everything else.
    stat_fd_budget: usize,
    stat_fds: usize,
    entries: HashMap<u32, Entry>,
    users: Users,
    sessions: Sessions,
    x11: Option<X11Windows>,
    uid_min: u32,
    my_uid: u32,
    self_pid: u32,
    page_size: u64,
    clk_tck: f64,
    pass: u64,
    prev: Option<(CpuTimes, Instant)>,
    unit_io: HashMap<Box<str>, (u64, u64)>,
    physical_dev: HashMap<(u32, u32), bool>,
}

impl Collector {
    pub fn new(window_detection: bool) -> Self {
        let nofile = rustix::process::getrlimit(rustix::process::Resource::Nofile)
            .current
            .unwrap_or(4096);
        Self {
            reader: Reader::default(),
            stat_buf: vec![0; 1024],
            stat_fd_budget: usize::try_from(nofile.saturating_sub(256)).unwrap_or(0),
            stat_fds: 0,
            entries: HashMap::with_capacity(1024),
            users: Users::load(),
            sessions: Sessions::default(),
            x11: if window_detection {
                X11Windows::connect()
            } else {
                None
            },
            uid_min: crate::session::uid_min(),
            my_uid: rustix::process::getuid().as_raw(),
            self_pid: std::process::id(),
            page_size: rustix::param::page_size() as u64,
            clk_tck: rustix::param::clock_ticks_per_second() as f64,
            pass: 0,
            prev: None,
            unit_io: HashMap::new(),
            physical_dev: HashMap::new(),
        }
    }

    /// One sampling pass. `detail` is re-read in full every pass for the detail panel.
    pub fn sample(&mut self, detail: Option<u32>) -> Snapshot {
        let cpu_start = thread_cpu_time();
        let now = Instant::now();
        self.pass += 1;
        self.sessions.refresh();
        let windows = match self.x11.as_ref().map(X11Windows::owner_pids) {
            Some(Some(pids)) => pids,
            Some(None) => {
                // The X server went away; stop asking.
                self.x11 = None;
                HashSet::new()
            }
            None => HashSet::new(),
        };

        let cpu = self
            .reader
            .file("/proc/stat")
            .ok()
            .and_then(procfs::parse_cpu_times);
        let mem = self
            .reader
            .file("/proc/meminfo")
            .ok()
            .and_then(procfs::parse_meminfo)
            .unwrap_or_default();
        let uptime = self
            .reader
            .file("/proc/uptime")
            .ok()
            .and_then(procfs::parse_uptime)
            .unwrap_or(0.0);
        let (cpu_delta, wall) = match (cpu, self.prev) {
            (Some(c), Some((p, at))) => (
                Some((
                    c.total.saturating_sub(p.total),
                    c.idle.saturating_sub(p.idle),
                )),
                Some(now - at),
            ),
            _ => (None, None),
        };
        if let Some(c) = cpu {
            self.prev = Some((c, now));
        }

        let mut rows = Vec::with_capacity(self.entries.len() + 16);
        if let Ok(dir) = std::fs::read_dir("/proc") {
            for entry in dir.flatten() {
                let Some(pid) = entry
                    .file_name()
                    .to_str()
                    .and_then(|n| n.parse::<u32>().ok())
                else {
                    continue;
                };
                if let Some(row) =
                    self.sample_process(pid, detail == Some(pid), uptime, cpu_delta, now)
                {
                    rows.push(row);
                }
            }
        }
        let pass = self.pass;
        let mut closed = 0;
        self.entries.retain(|_, e| {
            let keep = e.seen == pass;
            closed += usize::from(!keep && e.stat_file.is_some());
            keep
        });
        self.stat_fds -= closed;

        self.classify(&mut rows, &windows);
        self.attach_unit_io(&mut rows, wall);

        let cpu_total = cpu_delta
            .filter(|(total, _)| *total > 0)
            .map(|(total, idle)| (100.0 * (total - idle.min(total)) as f64 / total as f64) as f32);
        Snapshot {
            rows,
            cpu_total,
            mem,
            cost: thread_cpu_time().saturating_sub(cpu_start),
            taken: now,
            self_pid: self.self_pid,
            window_detection: self.x11.is_some(),
        }
    }

    fn sample_process(
        &mut self,
        pid: u32,
        is_detail: bool,
        uptime: f64,
        cpu_delta: Option<(u64, u64)>,
        now: Instant,
    ) -> Option<Row> {
        let mut prev = self.entries.remove(&pid);
        let stat_file = self.read_stat(pid, prev.as_mut().and_then(|e| e.stat_file.take()))?;
        let s = procfs::parse_stat(&self.stat_buf)?;
        let (state, ppid, tty, kthread, threads, start, rss_pages) = (
            s.state,
            s.ppid,
            s.tty_nr != 0,
            s.flags & PF_KTHREAD != 0,
            s.num_threads,
            s.starttime,
            s.rss_pages,
        );
        let ticks = s.utime.saturating_add(s.stime);
        // Same pid with another start time is a different (reused-pid) process.
        let prev = prev.filter(|e| e.start == start);
        let comm_changed = prev
            .as_ref()
            .is_none_or(|p| p.info.comm.as_bytes() != s.comm);
        let comm = if comm_changed {
            String::from_utf8_lossy(s.comm).into_owned()
        } else {
            String::new()
        };
        let age = Duration::from_secs_f64((uptime - start as f64 / self.clk_tck).max(0.0));
        let pass = self.pass;

        let refresh_info = match &prev {
            None => true,
            Some(p) => age < YOUNG || p.refresh_at <= pass || comm_changed,
        };
        // stat's rss is an approximate per-CPU counter read (kernel >= 6.2), off by up to a few
        // hundred KiB, so it only signals change; displayed values come from status/statm.
        let rss_changed = prev.as_ref().is_some_and(|p| p.rss_pages != rss_pages);
        let idle = prev.as_ref().is_some_and(|p| p.cpu_ticks == ticks);

        // `status` is the only source of uid and swap but costs ~2.4x `statm`, so it is read
        // only when the slow facts are due; an RSS change alone just refreshes anon via statm.
        let mut mem = prev.as_ref().map(|p| p.mem).unwrap_or_default();
        let mut uid = prev.as_ref().map(|p| p.info.uid);
        if !kthread {
            if refresh_info || is_detail {
                if let Some(st) = self
                    .reader
                    .pid_file(pid, "status")
                    .ok()
                    .and_then(procfs::parse_status)
                {
                    uid = Some(st.uid);
                    mem = Mem {
                        anon: st.anon_kb * 1024,
                        swap: st.swap_kb * 1024,
                        rss: st.rss_kb * 1024,
                        file: st.file_kb * 1024,
                        shmem: st.shmem_kb * 1024,
                    };
                }
            } else if rss_changed
                && let Some((resident, shared)) = self
                    .reader
                    .pid_file(pid, "statm")
                    .ok()
                    .and_then(procfs::parse_statm)
            {
                mem.anon = resident.saturating_sub(shared) * self.page_size;
                mem.rss = resident * self.page_size;
            }
        }

        let info = if refresh_info {
            let comm = if comm_changed {
                comm
            } else {
                prev.as_ref()
                    .map(|p| p.info.comm.to_string())
                    .unwrap_or_default()
            };
            let fresh = read_info(
                &mut self.reader,
                &mut self.users,
                pid,
                comm,
                kthread,
                uid.unwrap_or(0),
            );
            match &prev {
                Some(p) if *p.info == fresh => p.info.clone(),
                _ => Arc::new(fresh),
            }
        } else {
            prev.as_ref()?.info.clone()
        };

        // IO counters only move while the process runs, so a process that used no CPU and did
        // no IO last time is not re-read until the next refresh. The counters are cumulative, so
        // the rate computed after a skip is still exact over the longer interval.
        let mut io_denied = kthread || prev.as_ref().is_some_and(|p| p.io_denied);
        let mut io_state = prev.as_ref().and_then(|p| p.io);
        let mut io_rate = prev.as_ref().and_then(|p| p.io_rate);
        let skip_io = idle && !refresh_info && !is_detail && io_rate == Some((0.0, 0.0));
        if !io_denied && !skip_io {
            match self.reader.pid_file(pid, "io").map(procfs::parse_io) {
                Ok(Some((r, w))) => {
                    if let Some((pr, pw, at)) = io_state {
                        let secs = now.saturating_duration_since(at).as_secs_f64();
                        if secs > 0.0 {
                            io_rate = Some((
                                r.saturating_sub(pr) as f64 / secs,
                                w.saturating_sub(pw) as f64 / secs,
                            ));
                        }
                    }
                    io_state = Some((r, w, now));
                }
                Ok(None) => {}
                Err(e) => io_denied = e.kind() == ErrorKind::PermissionDenied,
            }
        }
        let io = match io_rate {
            Some((read, write)) if !io_denied => Io::Proc { read, write },
            _ => Io::Unknown,
        };

        let cpu = match (&prev, cpu_delta) {
            (Some(p), Some((total, _))) if total > 0 => {
                let used = ticks.saturating_sub(p.cpu_ticks) as f64;
                Some((100.0 * used / total as f64).clamp(0.0, 100.0) as f32)
            }
            _ => None,
        };

        let refresh_at = match &prev {
            // Spread refreshes over the period so every pass stays equally cheap.
            Some(p) if !refresh_info => p.refresh_at,
            _ => pass + REFRESH_PASSES + u64::from(pid) % REFRESH_PASSES,
        };
        let stat_file = (self.stat_fds < self.stat_fd_budget).then(|| {
            self.stat_fds += 1;
            stat_file
        });
        self.entries.insert(
            pid,
            Entry {
                stat_file,
                start,
                info: info.clone(),
                cpu_ticks: ticks,
                io: io_state,
                io_rate,
                io_denied,
                rss_pages,
                mem,
                refresh_at,
                seen: pass,
            },
        );

        Some(Row {
            key: ProcKey { pid, start },
            ppid,
            info,
            state,
            threads,
            tty,
            kthread,
            age,
            mem,
            cpu,
            io,
            class: Class {
                category: classify::Category::UserProcess,
                protect: None,
            },
            restart: Restart::Unavailable(""),
            self_ancestor: false,
        })
    }

    /// Reads `/proc/<pid>/stat` into `stat_buf`, through the kept fd when there is one, and
    /// returns the file so the caller can keep it for the next pass.
    fn read_stat(&mut self, pid: u32, kept: Option<File>) -> Option<File> {
        if let Some(file) = kept {
            self.stat_fds -= 1;
            if pread_all(&file, &mut self.stat_buf).is_ok_and(|n| n > 0) {
                return Some(file);
            }
            // ESRCH: that process exited; the pid may already belong to a new one.
        }
        let file = File::open(format!("/proc/{pid}/stat")).ok()?;
        (pread_all(&file, &mut self.stat_buf).ok()? > 0).then_some(file)
    }

    fn classify(&self, rows: &mut [Row], windows: &HashSet<u32>) {
        let index: HashMap<u32, usize> = rows
            .iter()
            .enumerate()
            .map(|(i, r)| (r.key.pid, i))
            .collect();
        let mut ancestors = HashSet::new();
        let mut cur = index.get(&self.self_pid).map(|&i| rows[i].ppid);
        while let Some(pid) = cur.filter(|&p| p > 1 && ancestors.insert(p)) {
            cur = index.get(&pid).map(|&i| rows[i].ppid);
        }

        let env = Env::new(
            self.self_pid,
            self.my_uid,
            self.uid_min,
            &self.sessions.list,
        );
        let classes: Vec<(Class, Restart)> = rows
            .iter()
            .map(|r| {
                let f = facts(r, rows, &index, windows, &ancestors);
                let class = classify::classify(&f, &env);
                let restart = classify::restart_kind(&f, &class, &env);
                (class, restart)
            })
            .collect();
        for (row, (class, restart)) in rows.iter_mut().zip(classes) {
            row.self_ancestor = ancestors.contains(&row.key.pid);
            row.class = class;
            row.restart = restart;
        }

        // Browser/Electron helpers join their parent application; iterate because renderers hang
        // off a zygote that hangs off the main process.
        loop {
            let mut changed = false;
            for i in 0..rows.len() {
                let r = &rows[i];
                if matches!(
                    r.class.category,
                    classify::Category::UserProcess | classify::Category::UserService
                ) && r.class.protect.is_none()
                    && classify::is_app_helper(&r.info.cmdline)
                    && index
                        .get(&r.ppid)
                        .is_some_and(|&p| rows[p].class.category == classify::Category::App)
                {
                    rows[i].class.category = classify::Category::App;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    /// Unreadable `/proc/<pid>/io` (other users' services, containers) falls back to the unit's
    /// cgroup `io.stat`, which is world-readable, reported on the unit's oldest process.
    fn attach_unit_io(&mut self, rows: &mut [Row], wall: Option<Duration>) {
        let mut groups: HashMap<&str, (bool, usize)> = HashMap::new();
        for (i, r) in rows.iter().enumerate() {
            let cg = &*r.info.cgroup;
            if !(cg.starts_with("/system.slice/") || classify::is_container(cg)) {
                continue;
            }
            let unreadable = matches!(r.io, Io::Unknown)
                && self.entries.get(&r.key.pid).is_some_and(|e| e.io_denied);
            let g = groups.entry(cg).or_insert((true, i));
            g.0 &= unreadable;
            if r.key.start < rows[g.1].key.start {
                g.1 = i;
            }
        }
        let mut seen = HashSet::new();
        let mut updates = Vec::new();
        for (cg, (all_unreadable, oldest)) in groups {
            if !all_unreadable {
                continue;
            }
            let path = format!("/sys/fs/cgroup{cg}/io.stat");
            let Ok(buf) = self.reader.file(&path) else {
                continue;
            };
            let physical_dev = &mut self.physical_dev;
            let Some(total) =
                procfs::parse_io_stat(buf, |major, minor| is_physical(physical_dev, major, minor))
            else {
                continue;
            };
            seen.insert(Box::<str>::from(cg));
            if let (Some(prev), Some(wall)) = (self.unit_io.insert(cg.into(), total), wall) {
                let secs = wall.as_secs_f64().max(1e-3);
                updates.push((
                    oldest,
                    Io::Unit {
                        read: total.0.saturating_sub(prev.0) as f64 / secs,
                        write: total.1.saturating_sub(prev.1) as f64 / secs,
                    },
                ));
            }
        }
        self.unit_io.retain(|k, _| seen.contains(k));
        for (i, io) in updates {
            rows[i].io = io;
        }
    }
}

fn read_info(
    reader: &mut Reader,
    users: &mut Users,
    pid: u32,
    comm: String,
    kthread: bool,
    uid: u32,
) -> ProcInfo {
    let cgroup: Box<str> = reader
        .pid_file(pid, "cgroup")
        .ok()
        .and_then(procfs::parse_cgroup)
        .unwrap_or("")
        .into();
    let (name, cmdline) = if kthread {
        (format!("[{comm}]"), String::new())
    } else {
        let cmdline = reader
            .pid_file(pid, "cmdline")
            .map(join_args)
            .unwrap_or_default();
        (display_name(&comm, &cmdline), cmdline)
    };
    ProcInfo {
        name: name.into(),
        comm: comm.into(),
        cmdline: cmdline.into(),
        uid,
        user: users.name(uid),
        cgroup,
    }
}

/// Space-joined arguments for display and matching, capped so a pathological command line cannot
/// bloat every snapshot.
fn join_args(buf: &[u8]) -> String {
    const MAX: usize = 4096;
    let mut s = String::new();
    for (i, arg) in procfs::split_nul(buf).enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&String::from_utf8_lossy(arg));
        if s.len() > MAX {
            let mut cut = MAX;
            while !s.is_char_boundary(cut) {
                cut -= 1;
            }
            s.truncate(cut);
            s.push('…');
            break;
        }
    }
    s
}

fn facts<'a>(
    r: &'a Row,
    rows: &'a [Row],
    index: &HashMap<u32, usize>,
    windows: &HashSet<u32>,
    ancestors: &HashSet<u32>,
) -> Facts<'a> {
    Facts {
        pid: r.key.pid,
        ppid: r.ppid,
        comm: &r.info.comm,
        cmdline: &r.info.cmdline,
        uid: r.info.uid,
        cgroup: &r.info.cgroup,
        kthread: r.kthread,
        state: r.state,
        has_window: windows.contains(&r.key.pid),
        parent_comm: index.get(&r.ppid).map(|&i| &*rows[i].info.comm),
        self_ancestor: ancestors.contains(&r.key.pid),
    }
}

/// Readable name: comm is cut at 15 bytes, so prefer the executable name from argv[0] when comm
/// is a truncated prefix of it (`gnome-session-b` → `gnome-session-binary`).
fn display_name(comm: &str, cmdline: &str) -> String {
    if comm.len() == 15 {
        let argv0 = cmdline.split(' ').next().unwrap_or("");
        let base = argv0.rsplit('/').next().unwrap_or(argv0);
        if base.len() > comm.len() && base.starts_with(comm) {
            return base.to_owned();
        }
    }
    comm.to_owned()
}

fn is_physical(cache: &mut HashMap<(u32, u32), bool>, major: u32, minor: u32) -> bool {
    *cache.entry((major, minor)).or_insert_with(|| {
        std::fs::read_link(format!("/sys/dev/block/{major}:{minor}"))
            .map(|target| !target.to_string_lossy().contains("/devices/virtual/"))
            .unwrap_or(false)
    })
}

/// Reads the whole file from offset 0 into `buf`, truncating `buf` to the data read.
fn pread_all(file: &File, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    buf.resize(buf.capacity().max(1024), 0);
    loop {
        let n = file.read_at(buf, 0)?;
        if n < buf.len() {
            buf.truncate(n);
            return Ok(n);
        }
        // Did not fit (never expected for stat); grow and retry from the start.
        buf.resize(buf.len() * 2, 0);
    }
}

fn thread_cpu_time() -> Duration {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::ThreadCPUTime);
    Duration::new(
        t.tv_sec.max(0) as u64,
        t.tv_nsec.clamp(0, 999_999_999) as u32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names() {
        assert_eq!(
            display_name(
                "gnome-session-b",
                "/usr/libexec/gnome-session-binary --session=ubuntu"
            ),
            "gnome-session-binary"
        );
        assert_eq!(
            display_name("systemd-journal", "/usr/lib/systemd/systemd-journald"),
            "systemd-journald"
        );
        assert_eq!(display_name("sshd", "sshd: qingteng [priv]"), "sshd");
        assert_eq!(
            display_name("abcdefghijklmno", "/bin/other"),
            "abcdefghijklmno"
        );
    }

    #[test]
    fn sample_sees_self_with_cpu_on_second_pass() {
        let mut c = Collector::new(false);
        let first = c.sample(None);
        let me = std::process::id();
        let row = first
            .rows
            .iter()
            .find(|r| r.key.pid == me)
            .expect("own process listed");
        assert_eq!(row.cpu, None);
        assert_eq!(row.class.protect, Some(classify::SELF_REASON));
        assert!(row.mem.rss > 0);

        // Burn a little CPU so the second pass has something to measure.
        let t = Instant::now();
        while t.elapsed() < Duration::from_millis(50) {
            std::hint::black_box(0u64.wrapping_add(1));
        }
        let second = c.sample(Some(me));
        let row = second.rows.iter().find(|r| r.key.pid == me).unwrap();
        assert!(row.cpu.is_some());
        assert!(row.mem.anon > 0);
        assert!(matches!(row.io, Io::Proc { .. }));
        assert!(
            second
                .rows
                .iter()
                .any(|r| r.key.pid == 1 && r.class.protect.is_some())
        );
        assert!(second.cpu_total.is_some());
    }
}
