//! The egui front end.
//!
//! Frames are only drawn for input or a new snapshot. The table renders just the visible rows;
//! filtering and sorting run when a snapshot arrives or the view settings change, not per frame.

use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::SeqCst};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, Thread};
use std::time::{Duration, Instant};

use eframe::egui::{self, Align, Color32, Layout, RichText, Sense};
use egui_extras::{Column, TableBuilder};

use crate::actions::{self, Kind, Prepared};
use crate::classify::{Category, Restart};
use crate::collector::{Collector, Io, ProcKey, Row, Snapshot};
use crate::format;

/// Sampling period. Two seconds keeps collection around 0.4% of one core on ~500 processes.
const INTERVAL: Duration = Duration::from_secs(2);

pub fn run() -> ExitCode {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("ProcGuard")
            .with_app_id("procguard")
            .with_inner_size([1180.0, 720.0])
            .with_min_inner_size([760.0, 420.0]),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    match eframe::run_native(
        "ProcGuard",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("procguard: {e}");
            ExitCode::FAILURE
        }
    }
}

/// State shared with the collector thread.
#[derive(Default)]
struct Shared {
    latest: Mutex<Option<Snapshot>>,
    /// Paused by the user.
    paused: AtomicBool,
    /// Window minimized or occluded: nothing is shown, so nothing is sampled.
    hidden: AtomicBool,
    wake: AtomicBool,
    /// pid of the selected process, re-read in full for the detail panel (0 = none).
    detail: AtomicU32,
}

fn collect_loop(shared: Arc<Shared>, ctx: egui::Context) {
    let mut collector = Collector::new(true);
    let idle = |s: &Shared| s.paused.load(SeqCst) || s.hidden.load(SeqCst);
    loop {
        if idle(&shared) {
            thread::park();
            continue;
        }
        shared.wake.store(false, SeqCst);
        let detail = shared.detail.load(SeqCst);
        let snap = collector.sample((detail != 0).then_some(detail));
        *shared.latest.lock().unwrap_or_else(PoisonError::into_inner) = Some(snap);
        // A zero-delay request makes egui paint two frames "to let things settle"; with a non-zero
        // delay it paints once. On software GL every frame is real CPU, so ask for one.
        ctx.request_repaint_after(Duration::from_millis(1));
        let deadline = Instant::now() + INTERVAL;
        loop {
            let now = Instant::now();
            if now >= deadline || shared.wake.load(SeqCst) || idle(&shared) {
                break;
            }
            thread::park_timeout(deadline - now);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortKey {
    Name,
    Pid,
    User,
    Category,
    Mem,
    Swap,
    Rss,
    Cpu,
    Io,
}

const COLUMNS: [(&str, SortKey, &str); 9] = [
    ("名称", SortKey::Name, "进程名；🔒 表示受保护的核心进程"),
    ("PID", SortKey::Pid, "进程号"),
    ("用户", SortKey::User, "进程的真实用户"),
    ("类型", SortKey::Category, "进程分类"),
    (
        "内存",
        SortKey::Mem,
        "私有常驻内存（RssAnon）：进程独占、未被换出的物理内存，不含共享库和文件缓存，最接近结束该进程能释放的内存",
    ),
    ("交换", SortKey::Swap, "已被换出到交换区的内存（VmSwap）"),
    (
        "RSS",
        SortKey::Rss,
        "常驻内存总量，含共享库与共享内存，与 top 的 RES 一致；多个进程会重复计算共享部分",
    ),
    (
        "CPU",
        SortKey::Cpu,
        "占整机 CPU 的百分比（所有核心合计为 100%）",
    ),
    (
        "磁盘 I/O",
        SortKey::Io,
        "磁盘读+写速率；≈ 表示按 systemd 服务/容器统计（该进程的 IO 计数需要 root 才能读取），— 表示无法获取",
    ),
];

enum Event {
    Prepared(Box<Prepared>),
    Done(Result<String, String>),
}

enum Dialog {
    Preparing {
        name: String,
        key: ProcKey,
        kind: Kind,
    },
    Confirm(Box<Prepared>),
    Running {
        name: String,
        kind: Kind,
    },
}

struct App {
    shared: Arc<Shared>,
    collector: Thread,
    events_tx: Sender<Event>,
    events: Receiver<Event>,
    snap: Option<Snapshot>,
    /// Indices into `snap.rows` after filtering and sorting.
    view: Vec<usize>,
    dirty: bool,
    sort: SortKey,
    desc: bool,
    filter: String,
    category: Option<Category>,
    /// (count, summed private memory) per category, and for all processes.
    totals: Vec<(Option<Category>, usize, u64)>,
    selected: Option<ProcKey>,
    dialog: Option<Dialog>,
    message: Option<(String, bool)>,
    font_error: Option<String>,
    hidden: bool,
    /// New snapshots are being held back because a menu or dialog is open.
    holding: bool,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let font_error = crate::fonts::install_cjk(&cc.egui_ctx).err();
        cc.egui_ctx.all_styles_mut(|style| {
            // Floating scroll bars would cover the right-aligned last column.
            style.spacing.scroll = egui::style::ScrollStyle::solid();
            // CJK glyphs are hard to read at egui's 12.5 pt default.
            for (text_style, font) in style.text_styles.iter_mut() {
                font.size = match text_style {
                    egui::TextStyle::Heading => 18.0,
                    egui::TextStyle::Small => 11.0,
                    _ => 14.0,
                };
            }
        });
        let shared = Arc::new(Shared::default());
        let collector = {
            let (shared, ctx) = (shared.clone(), cc.egui_ctx.clone());
            thread::Builder::new()
                .name("collector".into())
                .spawn(move || collect_loop(shared, ctx))
                .expect("failed to start the collector thread")
                .thread()
                .clone()
        };
        let (events_tx, events) = mpsc::channel();
        Self {
            shared,
            collector,
            events_tx,
            events,
            snap: None,
            view: Vec::new(),
            dirty: false,
            sort: SortKey::Mem,
            desc: true,
            filter: String::new(),
            category: None,
            totals: Vec::new(),
            selected: None,
            dialog: None,
            message: None,
            font_error,
            hidden: false,
            holding: false,
        }
    }

    fn wake_collector(&self) {
        self.shared.wake.store(true, SeqCst);
        self.collector.unpark();
    }

    fn select(&mut self, key: ProcKey) {
        self.selected = Some(key);
        self.shared.detail.store(key.pid, SeqCst);
    }

    fn selected_row(&self) -> Option<&Row> {
        let key = self.selected?;
        self.snap.as_ref()?.rows.iter().find(|r| r.key == key)
    }

    fn rebuild_view(&mut self) {
        self.dirty = false;
        let Some(snap) = &self.snap else { return };
        self.totals.clear();
        self.totals.push((
            None,
            snap.rows.len(),
            snap.rows.iter().map(|r| r.mem.anon).sum(),
        ));
        for cat in Category::ALL {
            let (n, mem) = snap
                .rows
                .iter()
                .filter(|r| r.class.category == cat)
                .fold((0, 0), |(n, m), r| (n + 1, m + r.mem.anon));
            self.totals.push((Some(cat), n, mem));
        }

        let needle = self.filter.trim().to_lowercase();
        self.view.clear();
        self.view
            .extend(snap.rows.iter().enumerate().filter_map(|(i, r)| {
                let in_category = self.category.is_none_or(|c| r.class.category == c);
                (in_category && (needle.is_empty() || matches_filter(r, &needle))).then_some(i)
            }));

        let rows = &snap.rows;
        let (sort, desc) = (self.sort, self.desc);
        self.view.sort_by(|&a, &b| {
            let (a, b) = (&rows[a], &rows[b]);
            let ord = match sort {
                SortKey::Name => a.info.name.to_lowercase().cmp(&b.info.name.to_lowercase()),
                SortKey::Pid => a.key.pid.cmp(&b.key.pid),
                SortKey::User => a.info.user.cmp(&b.info.user),
                SortKey::Category => a.class.category.cmp(&b.class.category),
                SortKey::Mem => a.mem.anon.cmp(&b.mem.anon),
                SortKey::Swap => a.mem.swap.cmp(&b.mem.swap),
                SortKey::Rss => a.mem.rss.cmp(&b.mem.rss),
                // Unknown values sort as lowest in either direction's natural order.
                SortKey::Cpu => a.cpu.unwrap_or(-1.0).total_cmp(&b.cpu.unwrap_or(-1.0)),
                SortKey::Io => {
                    a.io.total()
                        .unwrap_or(-1.0)
                        .total_cmp(&b.io.total().unwrap_or(-1.0))
                }
            };
            let ord = if desc { ord.reverse() } else { ord };
            ord.then(a.key.pid.cmp(&b.key.pid))
        });
    }

    fn start_action(&mut self, row: Row, kind: Kind, ctx: &egui::Context) {
        self.dialog = Some(Dialog::Preparing {
            name: row.info.name.to_string(),
            key: row.key,
            kind,
        });
        let (tx, ctx) = (self.events_tx.clone(), ctx.clone());
        thread::spawn(move || {
            let prepared = actions::prepare(&row, kind);
            let _ = tx.send(Event::Prepared(Box::new(prepared)));
            ctx.request_repaint();
        });
    }

    fn on_event(&mut self, event: Event) {
        match event {
            Event::Prepared(p) => {
                // Ignore a late answer for a dialog the user already dismissed.
                if matches!(&self.dialog, Some(Dialog::Preparing { key, kind, .. }) if *key == p.key && *kind == p.kind)
                {
                    self.dialog = Some(Dialog::Confirm(p));
                }
            }
            Event::Done(result) => {
                self.dialog = None;
                self.message = Some(match result {
                    Ok(msg) => (msg, true),
                    Err(msg) => (msg, false),
                });
                self.wake_collector();
            }
        }
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("ProcGuard").strong().size(16.0));
            ui.separator();
            let search = egui::TextEdit::singleline(&mut self.filter)
                .hint_text("搜索名称 / 命令行 / PID / 用户")
                .desired_width(280.0);
            if ui.add(search).changed() {
                self.dirty = true;
            }
            if !self.filter.is_empty() && ui.small_button("清除").clicked() {
                self.filter.clear();
                self.dirty = true;
            }
            ui.separator();
            let paused = self.shared.paused.load(SeqCst);
            let label = if paused {
                "继续刷新"
            } else {
                "暂停刷新"
            };
            if ui
                .selectable_label(paused, label)
                .on_hover_text("暂停后停止采集，列表保持不动")
                .clicked()
            {
                self.shared.paused.store(!paused, SeqCst);
                if paused {
                    self.wake_collector();
                }
            }
        });
    }

    fn categories(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        let totals = self.totals.clone();
        for (cat, count, mem) in totals {
            let label = cat.map_or("全部", Category::label);
            let text = format!("{label}  {count}");
            let resp = ui
                .selectable_label(self.category == cat, text)
                .on_hover_text(format!("私有内存合计 {}", format::bytes(mem)));
            if resp.clicked() {
                self.category = cat;
                self.dirty = true;
            }
            ui.label(RichText::new(format::bytes(mem)).small().weak());
            ui.add_space(2.0);
        }
    }

    fn status_bar(&self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            let Some(snap) = &self.snap else {
                ui.label("正在采集…");
                return;
            };
            let m = snap.mem;
            ui.label(format!("进程 {}", snap.rows.len()));
            ui.separator();
            ui.label(format!(
                "CPU {}",
                snap.cpu_total
                    .map(format::percent)
                    .unwrap_or_else(|| "—".into())
            ));
            ui.separator();
            ui.label(format!(
                "内存 {} / {}",
                format::bytes(m.total_kb.saturating_sub(m.available_kb) * 1024),
                format::bytes(m.total_kb * 1024)
            ));
            ui.separator();
            ui.label(format!(
                "交换 {} / {}",
                format::bytes(m.swap_total_kb.saturating_sub(m.swap_free_kb) * 1024),
                format::bytes(m.swap_total_kb * 1024)
            ));
            ui.separator();
            if let Some(me) = snap.rows.iter().find(|r| r.key.pid == snap.self_pid) {
                ui.label(format!(
                    "本程序 CPU {} 内存 {}",
                    me.cpu.map(format::percent).unwrap_or_else(|| "—".into()),
                    format::bytes(me.mem.anon)
                ))
                .on_hover_text(format!(
                    "单轮采集耗时 {:.1} ms（采集线程 CPU 时间）",
                    snap.cost.as_secs_f64() * 1e3
                ));
                ui.separator();
            }
            if self.shared.paused.load(SeqCst) {
                ui.label(RichText::new("已暂停").color(ui.visuals().warn_fg_color));
            } else if self.holding {
                ui.label(RichText::new("列表已冻结（菜单或对话框打开中）").weak());
            } else {
                let age = snap.taken.elapsed().as_secs();
                let text = if age < 2 {
                    "实时".to_owned()
                } else {
                    format!("更新于 {age} 秒前")
                };
                let stale = age > 3 * INTERVAL.as_secs();
                ui.label(if stale {
                    RichText::new(text).color(ui.visuals().warn_fg_color)
                } else {
                    RichText::new(text).weak()
                });
            }
            if let Some(err) = &self.font_error {
                ui.separator();
                ui.label(RichText::new(err).color(ui.visuals().warn_fg_color));
            }
            if let Some((msg, ok)) = &self.message {
                ui.separator();
                let color = if *ok {
                    Color32::from_rgb(0x4c, 0xaf, 0x50)
                } else {
                    ui.visuals().error_fg_color
                };
                ui.label(RichText::new(msg).color(color));
            }
        });
    }

    fn details(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let Some(r) = self.selected_row().cloned() else {
            return;
        };
        let mut action = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&*r.info.name).strong().size(15.0));
                    ui.label(format!(
                        "PID {}  父进程 {}  用户 {}  {}",
                        r.key.pid,
                        r.ppid,
                        r.info.user,
                        r.class.category.label()
                    ));
                    ui.separator();
                    action = action_buttons(ui, &r);
                });
                egui::Grid::new("details")
                    .num_columns(2)
                    .spacing([12.0, 4.0])
                    .show(ui, |ui| {
                        ui.label(RichText::new("命令行").weak());
                        ui.add(
                            egui::Label::new(if r.info.cmdline.is_empty() {
                                "（无）"
                            } else {
                                &r.info.cmdline
                            })
                            .wrap(),
                        );
                        ui.end_row();
                        ui.label(RichText::new("状态").weak());
                        ui.label(format!(
                            "{}  线程 {}  已运行 {}{}",
                            state_label(r.state),
                            r.threads,
                            format::duration(r.age),
                            if r.tty { "  依附终端" } else { "" }
                        ));
                        ui.end_row();
                        ui.label(RichText::new("内存").weak());
                        ui.label(format!(
                            "私有 {}  交换 {}  RSS {}（文件映射 {}，共享内存 {}）",
                            format::bytes(r.mem.anon),
                            format::bytes(r.mem.swap),
                            format::bytes(r.mem.rss),
                            format::bytes(r.mem.file),
                            format::bytes(r.mem.shmem)
                        ));
                        ui.end_row();
                        ui.label(RichText::new("cgroup").weak());
                        ui.add(egui::Label::new(&*r.info.cgroup).wrap());
                        ui.end_row();
                        ui.label(RichText::new("保护").weak());
                        match r.class.protect {
                            Some(reason) => ui.label(
                                RichText::new(format!("🔒 {reason}"))
                                    .color(ui.visuals().warn_fg_color),
                            ),
                            None => ui.label("可结束"),
                        };
                        ui.end_row();
                        ui.label(RichText::new("重启方式").weak());
                        ui.label(r.restart.describe());
                        ui.end_row();
                    });
            });
        if let Some(kind) = action {
            self.start_action(r, kind, ctx);
        }
    }

    fn table(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let Some(snap) = &self.snap else {
            ui.centered_and_justified(|ui| ui.spinner());
            return;
        };
        let row_height = egui::TextStyle::Body.resolve(ui.style()).size + 8.0;
        let mut clicked_header = None;
        let mut clicked_row = None;
        let mut action: Option<(Row, Kind)> = None;
        let (sort, desc, selected, view) = (self.sort, self.desc, self.selected, &self.view);

        TableBuilder::new(ui)
            .id_salt("processes")
            // Stripes fill half the table with blended rects every frame: measured 0.4% of a core
            // on software GL (1.4% -> 1.0% idle), so rows are told apart by hover/selection only.
            .striped(false)
            .resizable(true)
            .sense(Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::initial(230.0).at_least(120.0).clip(true))
            .column(Column::initial(72.0).at_least(56.0))
            .column(Column::initial(90.0).at_least(56.0).clip(true))
            .column(Column::initial(76.0).at_least(60.0))
            .column(Column::initial(84.0).at_least(64.0))
            .column(Column::initial(78.0).at_least(56.0))
            .column(Column::initial(84.0).at_least(64.0))
            .column(Column::initial(64.0).at_least(52.0))
            .column(Column::remainder().at_least(96.0))
            .header(row_height + 2.0, |mut header| {
                for (label, key, tip) in COLUMNS.iter() {
                    header.col(|ui| {
                        let arrow = if sort == *key {
                            if desc { " ▼" } else { " ▲" }
                        } else {
                            ""
                        };
                        let text = RichText::new(format!("{label}{arrow}")).strong();
                        let resp = ui
                            .add(egui::Button::new(text).frame(false))
                            .on_hover_text(*tip);
                        if resp.clicked() {
                            clicked_header = Some(*key);
                        }
                    });
                }
            })
            .body(|body| {
                body.rows(row_height, view.len(), |mut row| {
                    let r = &snap.rows[view[row.index()]];
                    row.set_selected(selected == Some(r.key));
                    let protected = r.class.protect.is_some();
                    let dim = |text: String| {
                        if protected {
                            RichText::new(text).weak()
                        } else {
                            RichText::new(text)
                        }
                    };
                    row.col(|ui| {
                        let name = if protected {
                            format!("🔒 {}", r.info.name)
                        } else {
                            r.info.name.to_string()
                        };
                        ui.add(egui::Label::new(dim(name)).truncate());
                    });
                    row.col(|ui| right(ui, dim(r.key.pid.to_string())));
                    row.col(|ui| {
                        ui.add(egui::Label::new(dim(r.info.user.to_string())).truncate());
                    });
                    row.col(|ui| {
                        ui.label(dim(r.class.category.label().to_owned()));
                    });
                    row.col(|ui| right(ui, dim(format::bytes(r.mem.anon))));
                    row.col(|ui| {
                        right(
                            ui,
                            dim(if r.mem.swap == 0 {
                                "—".into()
                            } else {
                                format::bytes(r.mem.swap)
                            }),
                        )
                    });
                    row.col(|ui| right(ui, dim(format::bytes(r.mem.rss))));
                    row.col(|ui| {
                        right(
                            ui,
                            dim(r.cpu.map(format::percent).unwrap_or_else(|| "—".into())),
                        )
                    });
                    row.col(|ui| right(ui, dim(io_text(&r.io))));

                    let resp = row.response();
                    if resp.clicked() || resp.secondary_clicked() {
                        clicked_row = Some(r.key);
                    }
                    // The snapshot is frozen while this menu is open (see `logic`), so the row
                    // under it cannot change to another process.
                    resp.context_menu(|ui| {
                        ui.label(
                            RichText::new(format!("{}（PID {}）", r.info.name, r.key.pid)).strong(),
                        );
                        ui.separator();
                        if let Some(kind) = action_buttons(ui, r) {
                            action = Some((r.clone(), kind));
                            ui.close();
                        }
                    });
                });
            });

        if let Some(key) = clicked_header {
            if self.sort == key {
                self.desc = !self.desc;
            } else {
                self.sort = key;
                // Big-number columns start with the largest; text columns alphabetically.
                self.desc = !matches!(
                    key,
                    SortKey::Name | SortKey::User | SortKey::Pid | SortKey::Category
                );
            }
            self.dirty = true;
        }
        if let Some(key) = clicked_row {
            self.select(key);
        }
        if let Some((row, kind)) = action {
            self.start_action(row, kind, ctx);
        }
    }

    fn dialog(&mut self, ctx: &egui::Context) {
        let Some(dialog) = &self.dialog else { return };
        let (mut close, mut confirm) = (false, false);
        let resp = egui::Modal::new(egui::Id::new("action-dialog")).show(ctx, |ui| {
            ui.set_width(600.0);
            match dialog {
                Dialog::Preparing { name, key, kind } => {
                    ui.heading(format!("{}：{name}（PID {}）", kind.label(), key.pid));
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("正在分析进程…");
                    });
                    if ui.button("取消").clicked() {
                        close = true;
                    }
                }
                Dialog::Running { name, kind } => {
                    ui.heading(format!("{}：{name}", kind.label()));
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("正在执行…");
                    });
                }
                Dialog::Confirm(p) => {
                    ui.heading(format!(
                        "{}：{}（PID {}）",
                        p.kind.label(),
                        p.name,
                        p.key.pid
                    ));
                    ui.add_space(4.0);
                    egui::Grid::new("confirm")
                        .num_columns(2)
                        .spacing([12.0, 4.0])
                        .show(ui, |ui| {
                            ui.label(RichText::new("用户").weak());
                            ui.label(&p.user);
                            ui.end_row();
                            ui.label(RichText::new("类型").weak());
                            ui.label(p.category.label());
                            ui.end_row();
                            ui.label(RichText::new("命令行").weak());
                            ui.add(
                                egui::Label::new(if p.cmdline.is_empty() {
                                    "（无）"
                                } else {
                                    &p.cmdline
                                })
                                .wrap(),
                            );
                            ui.end_row();
                        });
                    ui.add_space(6.0);
                    match &p.plan {
                        Err(reason) => {
                            ui.label(
                                RichText::new(format!("无法{}：{reason}", p.kind.label()))
                                    .color(ui.visuals().error_fg_color),
                            );
                            ui.add_space(6.0);
                            if ui.button("关闭").clicked() {
                                close = true;
                            }
                        }
                        Ok(_) => {
                            ui.label(RichText::new("将执行：").strong());
                            for step in &p.steps {
                                ui.label(format!("• {step}"));
                            }
                            for warning in &p.warnings {
                                ui.label(
                                    RichText::new(format!("⚠ {warning}"))
                                        .color(ui.visuals().warn_fg_color),
                                );
                            }
                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                let text =
                                    RichText::new(format!("确认{}", p.kind.label())).strong();
                                let text = if p.kind == Kind::Kill {
                                    text.color(ui.visuals().error_fg_color)
                                } else {
                                    text
                                };
                                if ui.button(text).clicked() {
                                    confirm = true;
                                }
                                if ui.button("取消").clicked() {
                                    close = true;
                                }
                            });
                        }
                    }
                }
            }
        });
        let running = matches!(dialog, Dialog::Running { .. });
        if confirm {
            if let Some(Dialog::Confirm(p)) = self.dialog.take() {
                self.dialog = Some(Dialog::Running {
                    name: p.name.clone(),
                    kind: p.kind,
                });
                let (tx, ctx) = (self.events_tx.clone(), ctx.clone());
                thread::spawn(move || {
                    let result = actions::execute(&p);
                    let _ = tx.send(Event::Done(result));
                    ctx.request_repaint();
                });
            }
        } else if close || (resp.should_close() && !running) {
            self.dialog = None;
        }
    }
}

impl eframe::App for App {
    fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
        visuals.panel_fill.to_normalized_gamma_f32()
    }

    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let hidden = ctx.input(|i| i.viewport().visible()) == Some(false);
        if hidden != self.hidden {
            self.hidden = hidden;
            self.shared.hidden.store(hidden, SeqCst);
            if !hidden {
                self.wake_collector();
            }
        }
        while let Ok(event) = self.events.try_recv() {
            self.on_event(event);
        }
        // Hold new data while a context menu or dialog is open, so the process the user is
        // acting on cannot be replaced under the cursor by a re-sort.
        let hold = self.dialog.is_some() || egui::Popup::is_any_open(ctx);
        self.holding = hold;
        if !hold
            && let Some(snap) = self
                .shared
                .latest
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
        {
            self.snap = Some(snap);
            self.dirty = true;
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if self.dirty {
            self.rebuild_view();
        }
        let ctx = ui.ctx().clone();
        // Backgrounds come from the clear colour (see `clear_color`), not from each panel: on
        // software GL every full-window fill is another alpha-blended pass over all pixels.
        let style = ui.style().clone();
        let bare = |frame: egui::Frame| frame.fill(Color32::TRANSPARENT);
        egui::Panel::top("toolbar")
            .frame(bare(egui::Frame::side_top_panel(&style)))
            .show(ui, |ui| {
                ui.add_space(2.0);
                self.toolbar(ui);
                ui.add_space(2.0);
            });
        egui::Panel::bottom("status")
            .frame(bare(egui::Frame::side_top_panel(&style)))
            .show(ui, |ui| self.status_bar(ui));
        if self.selected_row().is_some() {
            egui::Panel::bottom("details")
                .frame(bare(egui::Frame::side_top_panel(&style)))
                .resizable(true)
                .default_size(150.0)
                .min_size(90.0)
                .show(ui, |ui| {
                    self.details(ui, &ctx);
                });
        } else {
            // Keep the ids of everything after this panel stable whether it is shown or not;
            // otherwise the context menu of the row that was just selected loses its state.
            ui.skip_ahead_auto_ids(1);
        }
        egui::Panel::left("categories")
            .frame(bare(egui::Frame::side_top_panel(&style)))
            .resizable(false)
            .exact_size(150.0)
            .show(ui, |ui| self.categories(ui));
        egui::CentralPanel::default()
            .frame(bare(egui::Frame::central_panel(&style)))
            .show(ui, |ui| self.table(ui, &ctx));
        self.dialog(&ctx);
    }
}

/// Terminate / kill / restart buttons for one process, disabled with the reason when not allowed.
fn action_buttons(ui: &mut egui::Ui, r: &Row) -> Option<Kind> {
    let blocked = match (r.class.protect, r.state) {
        (Some(reason), _) => Some(reason.to_owned()),
        (None, b'Z') => Some("僵尸进程：已经退出，等待父进程回收".to_owned()),
        _ => None,
    };
    let restart_blocked = match &r.restart {
        _ if blocked.is_some() => blocked.clone(),
        Restart::Unavailable(reason) => Some((*reason).to_owned()),
        _ => None,
    };
    let mut chosen = None;
    for (kind, label, why) in [
        (Kind::Terminate, "结束", &blocked),
        (Kind::Kill, "强制结束", &blocked),
        (Kind::Restart, "重启", &restart_blocked),
    ] {
        let resp = ui.add_enabled(why.is_none(), egui::Button::new(label));
        let resp = match why {
            Some(reason) => resp.on_disabled_hover_text(reason.as_str()),
            None => resp.on_hover_text(match kind {
                Kind::Terminate => "发送 SIGTERM，请进程自行退出".to_owned(),
                Kind::Kill => "发送 SIGKILL，立即终止（不给进程保存数据的机会）".to_owned(),
                Kind::Restart => r.restart.describe(),
            }),
        };
        if resp.clicked() {
            chosen = Some(kind);
        }
    }
    chosen
}

fn right(ui: &mut egui::Ui, text: RichText) {
    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
        ui.label(text);
    });
}

fn io_text(io: &Io) -> String {
    match *io {
        Io::Unknown => "—".to_owned(),
        Io::Proc { read, write } => format::rate(read + write),
        Io::Unit { read, write } => format!("≈{}", format::rate(read + write)),
    }
}

fn state_label(state: u8) -> &'static str {
    match state {
        b'R' => "运行中",
        b'S' => "睡眠",
        b'D' => "不可中断睡眠（D）",
        b'Z' => "僵尸",
        b'T' => "已停止",
        b't' => "被跟踪",
        b'I' => "空闲",
        b'X' => "已退出",
        _ => "未知",
    }
}

/// Case-insensitive substring match on name, command line and user; digits also match pids.
fn matches_filter(r: &Row, needle: &str) -> bool {
    let has = |hay: &str| hay.to_lowercase().contains(needle);
    has(&r.info.name)
        || has(&r.info.cmdline)
        || has(&r.info.user)
        || r.key.pid.to_string().starts_with(needle)
}
