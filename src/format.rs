//! Human-readable units. Sizes are binary (1 KiB = 1024 B) and keep three significant digits.

use std::time::Duration;

const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];

pub fn bytes(n: u64) -> String {
    if n < 1000 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut unit = 0;
    // Switch units at 1000 rather than 1024 so a value never needs four integer digits.
    while v >= 999.5 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    let u = UNITS[unit];
    if v < 9.995 {
        format!("{v:.2} {u}")
    } else if v < 99.95 {
        format!("{v:.1} {u}")
    } else {
        format!("{v:.0} {u}")
    }
}

pub fn rate(bytes_per_sec: f64) -> String {
    format!("{}/s", bytes(bytes_per_sec.max(0.0).round() as u64))
}

pub fn percent(p: f32) -> String {
    format!("{p:.1}%")
}

pub fn duration(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..60 => format!("{s}秒"),
        60..3600 => format!("{}分{:02}秒", s / 60, s % 60),
        3600..86400 => format!("{}小时{:02}分", s / 3600, s % 3600 / 60),
        _ => format!("{}天{}小时", s / 86400, s % 86400 / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(999), "999 B");
        assert_eq!(bytes(1000), "0.98 KiB");
        assert_eq!(bytes(1024), "1.00 KiB");
        assert_eq!(bytes(1536), "1.50 KiB");
        assert_eq!(bytes(12_900_000), "12.3 MiB");
        assert_eq!(bytes(350 * 1024 * 1024), "350 MiB");
        assert_eq!(bytes(1_023 * 1024 * 1024), "1.00 GiB");
        assert_eq!(bytes(16_371_204 * 1024), "15.6 GiB");
        assert_eq!(bytes(u64::MAX), "16384 PiB");
    }

    #[test]
    fn rates_percent_durations() {
        assert_eq!(rate(0.0), "0 B/s");
        assert_eq!(rate(-5.0), "0 B/s");
        assert_eq!(rate(2.5 * 1024.0 * 1024.0), "2.50 MiB/s");
        assert_eq!(percent(12.345), "12.3%");
        assert_eq!(duration(Duration::from_secs(45)), "45秒");
        assert_eq!(duration(Duration::from_secs(125)), "2分05秒");
        assert_eq!(
            duration(Duration::from_secs(3 * 3600 + 7 * 60)),
            "3小时07分"
        );
        assert_eq!(
            duration(Duration::from_secs(2 * 86400 + 5 * 3600)),
            "2天5小时"
        );
    }
}
