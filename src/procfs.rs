//! Parsers for `/proc` and cgroup files.
//!
//! Every parser is a pure function over a byte slice so it can be tested with captured samples,
//! and returns `None` on malformed input instead of panicking: release builds use
//! `panic = "abort"`, so one odd process must not take the whole tool down.

use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Read};

/// `PF_KTHREAD` from `include/linux/sched.h`; set in the `flags` field of kernel threads.
pub const PF_KTHREAD: u32 = 0x0020_0000;

/// The subset of `/proc/<pid>/stat` the collector needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat<'a> {
    pub pid: u32,
    pub comm: &'a [u8],
    pub state: u8,
    pub ppid: u32,
    pub tty_nr: i32,
    pub flags: u32,
    pub utime: u64,
    pub stime: u64,
    pub num_threads: u32,
    /// Clock ticks since boot; together with the pid it identifies a process across pid reuse.
    pub starttime: u64,
    pub rss_pages: u64,
}

pub fn parse_stat(buf: &[u8]) -> Option<Stat<'_>> {
    // comm may contain spaces and parentheses, so it is delimited by the first '(' and the
    // last ')' rather than by whitespace.
    let open = buf.iter().position(|&b| b == b'(')?;
    let close = buf.iter().rposition(|&b| b == b')')?;
    if close <= open {
        return None;
    }
    let pid = parse_u32(trim(&buf[..open]))?;
    let comm = &buf[open + 1..close];
    let mut f = buf[close + 1..]
        .split(|&b| b == b' ' || b == b'\n')
        .filter(|s| !s.is_empty());
    // Field numbers below follow proc(5); the iterator starts at field 3.
    let state = *f.next()?.first()?;
    let ppid = parse_u32(f.next()?)?;
    let mut f = f.skip(2); // 5 pgrp, 6 session
    let tty_nr = parse_i64(f.next()?)? as i32;
    let mut f = f.skip(1); // 8 tpgid
    let flags = parse_u32(f.next()?)?;
    let mut f = f.skip(4); // 10-13 page fault counters
    let utime = parse_u64(f.next()?)?;
    let stime = parse_u64(f.next()?)?;
    let mut f = f.skip(4); // 16-19 cutime, cstime, priority, nice
    let num_threads = parse_u32(f.next()?)?;
    let mut f = f.skip(1); // 21 itrealvalue
    let starttime = parse_u64(f.next()?)?;
    let mut f = f.skip(1); // 23 vsize
    let rss_pages = parse_i64(f.next()?)?.max(0) as u64;
    Some(Stat {
        pid,
        comm,
        state,
        ppid,
        tty_nr,
        flags,
        utime,
        stime,
        num_threads,
        starttime,
        rss_pages,
    })
}

/// The subset of `/proc/<pid>/status` the collector needs. Memory values are in KiB and are zero
/// for kernel threads, which have no `Vm*`/`Rss*` lines.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Status {
    /// Real uid: the kernel's kill permission check is against the target's real/saved uid.
    pub uid: u32,
    pub rss_kb: u64,
    pub anon_kb: u64,
    pub file_kb: u64,
    pub shmem_kb: u64,
    pub swap_kb: u64,
}

pub fn parse_status(buf: &[u8]) -> Option<Status> {
    let mut st = Status::default();
    let mut uid = None;
    for line in buf.split(|&b| b == b'\n') {
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let (key, value) = (&line[..colon], &line[colon + 1..]);
        let slot = match key {
            b"Uid" => {
                uid = first_number(value);
                continue;
            }
            b"VmRSS" => &mut st.rss_kb,
            b"RssAnon" => &mut st.anon_kb,
            b"RssFile" => &mut st.file_kb,
            b"RssShmem" => &mut st.shmem_kb,
            b"VmSwap" => &mut st.swap_kb,
            _ => continue,
        };
        *slot = first_number(value)?.into();
    }
    st.uid = uid?;
    Some(st)
}

/// `/proc/<pid>/statm` → (resident, shared) in pages. `resident - shared` equals `RssAnon`:
/// the kernel reports shared as file-backed plus shmem pages.
pub fn parse_statm(buf: &[u8]) -> Option<(u64, u64)> {
    let mut f = buf
        .split(|&b| b == b' ' || b == b'\n')
        .filter(|s| !s.is_empty())
        .skip(1);
    Some((parse_u64(f.next()?)?, parse_u64(f.next()?)?))
}

/// `/proc/<pid>/io`: bytes this process caused to be read from / written to the block layer.
pub fn parse_io(buf: &[u8]) -> Option<(u64, u64)> {
    let (mut read, mut write) = (None, None);
    for line in buf.split(|&b| b == b'\n') {
        if let Some(v) = line.strip_prefix(b"read_bytes:") {
            read = parse_u64(trim(v));
        } else if let Some(v) = line.strip_prefix(b"write_bytes:") {
            write = parse_u64(trim(v));
        }
    }
    Some((read?, write?))
}

/// Returns the cgroup v2 path, falling back to the systemd v1 hierarchy on legacy hosts.
pub fn parse_cgroup(buf: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(buf).ok()?;
    let mut legacy = None;
    for line in text.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            return Some(path);
        }
        if let Some((_, path)) = line.split_once(":name=systemd:") {
            legacy = Some(path);
        }
    }
    legacy
}

/// Splits a NUL-separated `cmdline`/`environ` buffer. The trailing NUL does not produce an empty
/// element, but embedded empty arguments are preserved.
pub fn split_nul(buf: &[u8]) -> impl Iterator<Item = &[u8]> {
    let buf = buf.strip_suffix(b"\0").unwrap_or(buf);
    buf.split(|&b| b == 0)
        .take(if buf.is_empty() { 0 } else { usize::MAX })
}

/// System-wide CPU time from the first line of `/proc/stat`, in clock ticks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuTimes {
    pub total: u64,
    pub idle: u64,
}

pub fn parse_cpu_times(buf: &[u8]) -> Option<CpuTimes> {
    let line = buf.split(|&b| b == b'\n').next()?;
    let rest = line.strip_prefix(b"cpu ")?;
    let mut total = 0u64;
    let mut idle = 0u64;
    // user nice system idle iowait irq softirq steal; guest/guest_nice are already included in
    // user/nice, so adding them would double count.
    for (i, field) in rest
        .split(|&b| b == b' ')
        .filter(|s| !s.is_empty())
        .take(8)
        .enumerate()
    {
        let v = parse_u64(field)?;
        total = total.checked_add(v)?;
        if i == 3 || i == 4 {
            idle = idle.checked_add(v)?;
        }
    }
    Some(CpuTimes { total, idle })
}

/// `/proc/meminfo` values in KiB.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemInfo {
    pub total_kb: u64,
    pub available_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
}

pub fn parse_meminfo(buf: &[u8]) -> Option<MemInfo> {
    let mut m = MemInfo::default();
    let mut seen = 0u8;
    for line in buf.split(|&b| b == b'\n') {
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let (slot, bit) = match &line[..colon] {
            b"MemTotal" => (&mut m.total_kb, 1),
            b"MemAvailable" => (&mut m.available_kb, 2),
            b"SwapTotal" => (&mut m.swap_total_kb, 4),
            b"SwapFree" => (&mut m.swap_free_kb, 8),
            _ => continue,
        };
        *slot = first_number(&line[colon + 1..])?.into();
        seen |= bit;
    }
    (seen & 3 == 3).then_some(m)
}

/// Seconds since boot from `/proc/uptime`.
pub fn parse_uptime(buf: &[u8]) -> Option<f64> {
    let first = buf.split(|&b| b == b' ').next()?;
    std::str::from_utf8(first).ok()?.trim().parse().ok()
}

/// Sums `rbytes`/`wbytes` of a cgroup v2 `io.stat` over the devices `count_device(major, minor)`
/// accepts. The caller excludes virtual devices so stacked dm/zram IO is not counted twice.
pub fn parse_io_stat(
    buf: &[u8],
    mut count_device: impl FnMut(u32, u32) -> bool,
) -> Option<(u64, u64)> {
    let (mut read, mut write) = (0u64, 0u64);
    for line in buf.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
        let mut fields = line.split(|&b| b == b' ');
        let dev = fields.next()?;
        let colon = dev.iter().position(|&b| b == b':')?;
        let (major, minor) = (parse_u32(&dev[..colon])?, parse_u32(&dev[colon + 1..])?);
        if !count_device(major, minor) {
            continue;
        }
        for field in fields {
            if let Some(v) = field.strip_prefix(b"rbytes=") {
                read = read.saturating_add(parse_u64(v)?);
            } else if let Some(v) = field.strip_prefix(b"wbytes=") {
                write = write.saturating_add(parse_u64(v)?);
            }
        }
    }
    Some((read, write))
}

/// Reads small procfs/sysfs files into one reused buffer, so a collection pass does not allocate
/// per file once warmed up.
pub struct Reader {
    buf: Vec<u8>,
    path: String,
}

impl Default for Reader {
    fn default() -> Self {
        Self {
            buf: Vec::with_capacity(8 * 1024),
            path: String::with_capacity(64),
        }
    }
}

impl Reader {
    pub fn pid_file(&mut self, pid: u32, name: &str) -> io::Result<&[u8]> {
        self.path.clear();
        let _ = write!(self.path, "/proc/{pid}/{name}");
        Self::fill(&mut self.buf, &self.path)
    }

    pub fn file(&mut self, path: &str) -> io::Result<&[u8]> {
        Self::fill(&mut self.buf, path)
    }

    fn fill<'b>(buf: &'b mut Vec<u8>, path: &str) -> io::Result<&'b [u8]> {
        buf.clear();
        File::open(path)?.read_to_end(buf)?;
        Ok(buf)
    }
}

fn trim(s: &[u8]) -> &[u8] {
    s.trim_ascii()
}

fn first_number(value: &[u8]) -> Option<u32> {
    let v = value
        .split(|&b| b == b' ' || b == b'\t')
        .find(|s| !s.is_empty())?;
    parse_u32(v)
}

pub fn parse_u64(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    s.iter().try_fold(0u64, |acc, &b| {
        let d = b.checked_sub(b'0').filter(|d| *d < 10)?;
        acc.checked_mul(10)?.checked_add(u64::from(d))
    })
}

pub fn parse_u32(s: &[u8]) -> Option<u32> {
    parse_u64(s)?.try_into().ok()
}

fn parse_i64(s: &[u8]) -> Option<i64> {
    match s.strip_prefix(b"-") {
        Some(rest) => i64::try_from(parse_u64(rest)?).ok().map(|v| -v),
        None => i64::try_from(parse_u64(s)?).ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured on the development host (Ubuntu 24.04, kernel 7.0).
    const KTHREADD: &[u8] = b"2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 131 0 0 20 0 1 0 19 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
    const SYSTEMD: &[u8] = b"1 (systemd) S 0 1 1 0 -1 4194560 6821112 4746784920 2064 8843880 145299 69958 60835442 13076704 20 0 1 0 19 24772608 3203 18446744073709551615 1 1 0 0 0 0 671173123 4096 1260 0 0 0 17 7 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
    const SD_PAM: &[u8] = b"3567 ((sd-pam)) S 3563 3563 3563 0 -1 4194624 54 0 0 0 0 0 0 0 20 0 1 0 11596 21995520 423 18446744073709551615 1 1 0 0 0 0 0 4096 0 0 0 0 17 2 0 0 0 0 0 0 0 0 0 0 0 0 0\n";

    #[test]
    fn stat_kernel_thread() {
        let s = parse_stat(KTHREADD).unwrap();
        assert_eq!(
            (s.pid, s.comm, s.ppid, s.starttime),
            (2, &b"kthreadd"[..], 0, 19)
        );
        assert_ne!(s.flags & PF_KTHREAD, 0);
        assert_eq!(s.rss_pages, 0);
    }

    #[test]
    fn stat_regular_process() {
        let s = parse_stat(SYSTEMD).unwrap();
        assert_eq!(s.flags & PF_KTHREAD, 0);
        assert_eq!(
            (s.utime, s.stime, s.num_threads, s.rss_pages, s.tty_nr),
            (145299, 69958, 1, 3203, 0)
        );
    }

    #[test]
    fn stat_comm_with_parentheses_and_spaces() {
        let s = parse_stat(SD_PAM).unwrap();
        assert_eq!(s.comm, b"(sd-pam)");
        assert_eq!((s.ppid, s.starttime), (3563, 11596));

        let tricky = b"42 (a) b (c d) Z 7 42 42 34816 -1 4194304 0 0 0 0 5 6 0 0 20 0 3 0 999 0 0 18446744073709551615";
        let s = parse_stat(tricky).unwrap();
        assert_eq!(
            (s.comm, s.state, s.ppid, s.tty_nr),
            (&b"a) b (c d"[..], b'Z', 7, 34816)
        );
        assert_eq!(
            (s.utime, s.stime, s.num_threads, s.starttime),
            (5, 6, 3, 999)
        );
    }

    #[test]
    fn stat_rejects_garbage() {
        for bad in [
            &b""[..],
            b"1 (x",
            b"1 x) S",
            b") 1 (",
            b"1 (x) S 0",
            b"abc (x) S 0 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0",
            b"1 (x) S 99999999999999999999 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0",
        ] {
            assert_eq!(parse_stat(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn status_user_process_and_kernel_thread() {
        let user = b"Name:\tcat\nState:\tR (running)\nUid:\t1000\t1001\t1000\t1000\nVmRSS:\t    1984 kB\nRssAnon:\t     112 kB\nRssFile:\t    1872 kB\nRssShmem:\t       0 kB\nVmSwap:\t      12 kB\nThreads:\t1\n";
        let s = parse_status(user).unwrap();
        assert_eq!(
            s,
            Status {
                uid: 1000,
                rss_kb: 1984,
                anon_kb: 112,
                file_kb: 1872,
                shmem_kb: 0,
                swap_kb: 12
            }
        );

        let kthread = b"Name:\tkthreadd\nState:\tS (sleeping)\nUid:\t0\t0\t0\t0\nThreads:\t1\n";
        assert_eq!(parse_status(kthread), Some(Status::default()));
        assert_eq!(parse_status(b"Name:\tx\n"), None);
    }

    #[test]
    fn statm_resident_and_shared() {
        assert_eq!(parse_statm(b"2111 495 468 5 0 124 0\n"), Some((495, 468)));
        assert_eq!(parse_statm(b"0 0 0 0 0 0 0\n"), Some((0, 0)));
        assert_eq!(parse_statm(b"12\n"), None);
    }

    #[test]
    fn io_counters() {
        let io = b"rchar: 4092\nwchar: 0\nsyscr: 9\nsyscw: 0\nread_bytes: 8192\nwrite_bytes: 4096\ncancelled_write_bytes: 0\n";
        assert_eq!(parse_io(io), Some((8192, 4096)));
        assert_eq!(parse_io(b"rchar: 1\n"), None);
    }

    #[test]
    fn cgroup_paths() {
        assert_eq!(
            parse_cgroup(b"0::/system.slice/systemd-udevd.service/udev\n"),
            Some("/system.slice/systemd-udevd.service/udev")
        );
        assert_eq!(parse_cgroup(b"0::/\n"), Some("/"));
        let hybrid = b"12:cpu:/\n1:name=systemd:/user.slice/user-1000.slice/session-2.scope\n0::/user.slice/user-1000.slice/session-2.scope\n";
        assert_eq!(
            parse_cgroup(hybrid),
            Some("/user.slice/user-1000.slice/session-2.scope")
        );
        let legacy = b"12:cpu:/\n1:name=systemd:/system.slice/cron.service\n";
        assert_eq!(parse_cgroup(legacy), Some("/system.slice/cron.service"));
        assert_eq!(parse_cgroup(b""), None);
    }

    #[test]
    fn nul_separated() {
        let v: Vec<&[u8]> = split_nul(b"/usr/bin/foo\0--x\0\0last\0").collect();
        assert_eq!(v, [&b"/usr/bin/foo"[..], b"--x", b"", b"last"]);
        assert_eq!(split_nul(b"").count(), 0);
        assert_eq!(split_nul(b"\0").count(), 0);
        assert_eq!(split_nul(b"sshd: qingteng [priv]").count(), 1);
    }

    #[test]
    fn cpu_times_exclude_guest() {
        let stat = b"cpu  300030404 254389 307324639 2228501147 6029915 0 12412095 9006729 7 7\ncpu0 1 2 3 4 5 6 7 8 0 0\n";
        let t = parse_cpu_times(stat).unwrap();
        assert_eq!(
            t.total,
            300030404 + 254389 + 307324639 + 2228501147 + 6029915 + 12412095 + 9006729
        );
        assert_eq!(t.idle, 2228501147 + 6029915);
        assert_eq!(parse_cpu_times(b"intr 1 2\n"), None);
    }

    #[test]
    fn meminfo_and_uptime() {
        let m = b"MemTotal:       16371204 kB\nMemFree:         6120004 kB\nMemAvailable:   11943052 kB\nSwapTotal:      12379640 kB\nSwapFree:       10242576 kB\n";
        assert_eq!(
            parse_meminfo(m),
            Some(MemInfo {
                total_kb: 16371204,
                available_kb: 11943052,
                swap_total_kb: 12379640,
                swap_free_kb: 10242576
            })
        );
        assert_eq!(parse_meminfo(b"MemFree: 1 kB\n"), None);
        assert_eq!(parse_uptime(b"3627048.51 22285011.54\n"), Some(3627048.51));
    }

    #[test]
    fn io_stat_skips_rejected_devices() {
        let s = b"251:0 rbytes=100 wbytes=200 rios=1 wios=2 dbytes=0 dios=0\n8:0 rbytes=1000 wbytes=2000 rios=3 wios=4 dbytes=0 dios=0\n";
        assert_eq!(
            parse_io_stat(s, |major, _| major != 251),
            Some((1000, 2000))
        );
        assert_eq!(parse_io_stat(b"", |_, _| true), Some((0, 0)));
        assert_eq!(parse_io_stat(b"garbage\n", |_, _| true), None);
    }

    #[test]
    fn numbers_do_not_overflow() {
        assert_eq!(parse_u64(b"18446744073709551615"), Some(u64::MAX));
        assert_eq!(parse_u64(b"18446744073709551616"), None);
        assert_eq!(parse_u32(b"4294967296"), None);
        assert_eq!(parse_i64(b"-1"), Some(-1));
        assert_eq!(parse_u64(b"12a"), None);
    }

    #[test]
    fn reader_reads_own_stat() {
        let mut r = Reader::default();
        let pid = std::process::id();
        let s = parse_stat(r.pid_file(pid, "stat").unwrap()).map(|s| s.pid);
        assert_eq!(s, Some(pid));
    }
}
