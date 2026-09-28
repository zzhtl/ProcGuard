use std::process::ExitCode;
use std::time::Duration;

use procguard::collector::{Collector, Io};
use procguard::format;

const USAGE: &str = "用法: procguard [--dump [--passes N]]\n  --dump      不启动界面，采样后以 TSV 输出分类、保护原因和重启策略\n  --passes N  采样次数（默认 2，间隔 1 秒；CPU 与 IO 需要至少 2 次）";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => procguard::app::run(),
        ["--dump"] => dump(2),
        ["--dump", "--passes", n] => match n.parse() {
            Ok(n) if n >= 1 => dump(n),
            _ => usage_error(),
        },
        ["-h" | "--help"] => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        _ => usage_error(),
    }
}

fn usage_error() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

fn dump(passes: u32) -> ExitCode {
    let mut collector = Collector::new(true);
    let mut snap = collector.sample(None);
    eprintln!(
        "pass 1: {} processes, collector cpu {:?}",
        snap.rows.len(),
        snap.cost
    );
    for pass in 2..=passes {
        std::thread::sleep(Duration::from_secs(1));
        snap = collector.sample(None);
        eprintln!(
            "pass {pass}: {} processes, collector cpu {:?}",
            snap.rows.len(),
            snap.cost
        );
    }
    eprintln!("window detection: {}", snap.window_detection);

    let mut rows: Vec<_> = snap.rows.iter().collect();
    rows.sort_by(|a, b| {
        a.class
            .category
            .cmp(&b.class.category)
            .then(b.mem.anon.cmp(&a.mem.anon))
    });
    println!(
        "pid\tppid\tuser\tcategory\tprotect\trestart\tmem\tswap\trss\tcpu\tio\tname\tcgroup\tcmdline"
    );
    for r in rows {
        let io = match r.io {
            Io::Unknown => "-".to_owned(),
            Io::Proc { .. } => format::rate(r.io.total().unwrap_or(0.0)),
            Io::Unit { .. } => format!("≈{}", format::rate(r.io.total().unwrap_or(0.0))),
        };
        let cmd: String = r.info.cmdline.chars().take(80).collect();
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            r.key.pid,
            r.ppid,
            r.info.user,
            r.class.category.label(),
            r.class.protect.unwrap_or("-"),
            r.restart.describe(),
            format::bytes(r.mem.anon),
            format::bytes(r.mem.swap),
            format::bytes(r.mem.rss),
            r.cpu.map(format::percent).unwrap_or_else(|| "-".to_owned()),
            io,
            r.info.name,
            r.info.cgroup,
            cmd,
        );
    }
    ExitCode::SUCCESS
}
