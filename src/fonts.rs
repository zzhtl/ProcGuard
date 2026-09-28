//! CJK glyphs for the Chinese UI. egui's bundled fonts have none, and embedding one would add
//! ~20 MB to the binary, so the system's CJK font is used, found through fontconfig.

use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::process::{Command, Stdio};

use eframe::egui::epaint::text::{FontInsert, FontPriority, InsertFontFamily};
use eframe::egui::{self, FontData, FontFamily};

/// Paths tried when fontconfig is unavailable: (file, face index of Simplified Chinese).
const FALLBACKS: &[(&str, u32)] = &[
    ("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", 2),
    ("/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc", 2),
    (
        "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc",
        2,
    ),
    ("/usr/share/fonts/truetype/wqy/wqy-microhei.ttc", 0),
    ("/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc", 0),
    (
        "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
        0,
    ),
];

/// Adds a system CJK font as the last fallback of both families. Returns what was loaded, or why
/// nothing was (Chinese text then renders as boxes, the rest of the UI still works).
pub fn install_cjk(ctx: &egui::Context) -> Result<String, String> {
    let (path, index) = fontconfig_match()
        .or_else(|| {
            FALLBACKS
                .iter()
                .find(|(p, _)| std::path::Path::new(p).exists())
                .map(|&(p, i)| (p.to_owned(), i))
        })
        .ok_or("未找到支持中文的系统字体（可安装 fonts-noto-cjk）")?;
    let (bytes, how) = load(&path).map_err(|e| format!("读取字体 {path} 失败：{e}"))?;
    let data = FontData {
        index,
        ..FontData::from_static(bytes)
    };
    let families = [FontFamily::Proportional, FontFamily::Monospace]
        .into_iter()
        .map(|family| InsertFontFamily {
            family,
            priority: FontPriority::Lowest,
        })
        .collect();
    ctx.add_font(FontInsert::new("system-cjk", data, families));
    Ok(format!("{path}#{index}（{how}）"))
}

/// Asks fontconfig for the preferred Simplified Chinese font. fc-match always answers with some
/// font, so its language coverage is checked too.
fn fontconfig_match() -> Option<(String, u32)> {
    let out = Command::new("fc-match")
        .args(["-f", "%{file}\n%{index}\n%{lang}", ":lang=zh-cn"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    let mut lines = text.lines();
    let file = lines.next()?.to_owned();
    let index = lines.next()?.parse().ok()?;
    let covers_zh = lines.next()?.split('|').any(|l| l == "zh-cn");
    covers_zh.then_some((file, index))
}

/// Maps root-owned font files instead of reading them: only the pages of glyphs actually drawn
/// become resident, and they stay reclaimable page cache. epaint borrows `'static` font data
/// without copying (owned data would be copied again on every font atlas rebuild).
fn load(path: &str) -> std::io::Result<(&'static [u8], &'static str)> {
    let file = File::open(path)?;
    let meta = file.metadata()?;
    if meta.uid() == 0 && meta.mode() & 0o022 == 0 {
        // SAFETY: the mapped file is owned by root and writable by nobody else (checked on this
        // very fd above), so no unprivileged process can modify or truncate it while mapped, and
        // package managers replace font files by rename, which leaves this inode untouched. The
        // mapping is leaked, so it lives as long as the `'static` slice handed to egui.
        let map = unsafe { memmap2::Mmap::map(&file) }?;
        let map: &'static memmap2::Mmap = Box::leak(Box::new(map));
        Ok((&map[..], "mmap"))
    } else {
        let bytes = std::fs::read(path)?;
        Ok((Box::leak(bytes.into_boxed_slice()), "读入内存"))
    }
}
