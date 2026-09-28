//! Probes of the running system that classification depends on: logind sessions, the account
//! database and X11 window ownership.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;

use x11rb::connection::{Connection, RequestConnection};
use x11rb::protocol::res::{self, ClientIdMask, ClientIdSpec, ConnectionExt as _};
use x11rb::protocol::xproto::{AtomEnum, ConnectionExt as _};
use x11rb::rust_connection::RustConnection;

const SESSIONS_DIR: &str = "/run/systemd/sessions";

/// One logind session, from `/run/systemd/sessions/<id>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogindSession {
    pub id: Box<str>,
    pub uid: u32,
    /// `active`, `online` or `closing`.
    pub state: Box<str>,
    /// `x11`, `wayland`, `tty`, `mir` or `unspecified`.
    pub kind: Box<str>,
    /// `user`, `greeter`, `lock-screen`, ...
    pub class: Box<str>,
    pub leader: Option<u32>,
    pub scope: Option<Box<str>>,
}

impl LogindSession {
    /// A closing session has already been logged out; whatever it leaked (e.g. an abandoned
    /// ssh session's dbus-daemon) no longer keeps anyone logged in.
    pub fn is_live(&self) -> bool {
        matches!(&*self.state, "active" | "online")
    }
}

pub fn parse_session_file(id: &str, text: &[u8]) -> Option<LogindSession> {
    let text = std::str::from_utf8(text).ok()?;
    let mut s = LogindSession {
        id: id.into(),
        uid: u32::MAX,
        state: "".into(),
        kind: "".into(),
        class: "".into(),
        leader: None,
        scope: None,
    };
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "UID" => s.uid = v.parse().ok()?,
            "STATE" => s.state = v.into(),
            "TYPE" => s.kind = v.into(),
            "CLASS" => s.class = v.into(),
            "LEADER" => s.leader = v.parse().ok(),
            "SCOPE" => s.scope = Some(v.into()),
            _ => {}
        }
    }
    (s.uid != u32::MAX).then_some(s)
}

/// Cached view of the logind session directory, re-read only when the directory changes
/// (systemd replaces session files by rename, which bumps the directory mtime).
#[derive(Default)]
pub struct Sessions {
    mtime: Option<SystemTime>,
    pub list: Vec<LogindSession>,
}

impl Sessions {
    pub fn refresh(&mut self) {
        let mtime = std::fs::metadata(SESSIONS_DIR)
            .and_then(|m| m.modified())
            .ok();
        if mtime.is_some() && mtime == self.mtime {
            return;
        }
        self.mtime = mtime;
        self.list.clear();
        let Ok(dir) = std::fs::read_dir(SESSIONS_DIR) else {
            return;
        };
        for entry in dir.flatten() {
            let name = entry.file_name();
            let Some(id) = name.to_str().filter(|n| !n.ends_with(".ref")) else {
                continue;
            };
            if let Ok(text) = std::fs::read(entry.path())
                && let Some(s) = parse_session_file(id, &text)
            {
                self.list.push(s);
            }
        }
    }

    pub fn by_scope(&self, scope: &str) -> Option<&LogindSession> {
        self.list.iter().find(|s| s.scope.as_deref() == Some(scope))
    }
}

/// uid → user name from `/etc/passwd`, with a numeric fallback for accounts only known to NSS
/// (e.g. systemd DynamicUser services).
pub struct Users {
    names: HashMap<u32, Arc<str>>,
}

impl Users {
    pub fn load() -> Self {
        let text = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
        Self {
            names: parse_passwd(&text),
        }
    }

    pub fn name(&mut self, uid: u32) -> Arc<str> {
        self.names
            .entry(uid)
            .or_insert_with(|| uid.to_string().into())
            .clone()
    }
}

fn parse_passwd(text: &str) -> HashMap<u32, Arc<str>> {
    text.lines()
        .filter_map(|line| {
            let mut f = line.split(':');
            let name = f.next()?;
            let uid = f.nth(1)?.parse().ok()?;
            Some((uid, Arc::from(name)))
        })
        .collect()
}

/// First uid of regular (human) accounts, `UID_MIN` in `/etc/login.defs`.
pub fn uid_min() -> u32 {
    std::fs::read_to_string("/etc/login.defs")
        .ok()
        .and_then(|t| parse_uid_min(&t))
        .unwrap_or(1000)
}

fn parse_uid_min(text: &str) -> Option<u32> {
    text.lines().find_map(|l| {
        let mut f = l.split_whitespace();
        (f.next()? == "UID_MIN")
            .then(|| f.next()?.parse().ok())
            .flatten()
    })
}

/// Finds which processes own a regular top-level X11 window.
///
/// PIDs come from the X-Resource extension when available: the server derives them from the
/// client socket, whereas `_NET_WM_PID` is merely what the client claims.
pub struct X11Windows {
    conn: RustConnection,
    root: u32,
    client_list: u32,
    wm_pid: u32,
    window_type: u32,
    type_dock: u32,
    type_desktop: u32,
    has_res: bool,
}

impl X11Windows {
    pub fn connect() -> Option<Self> {
        std::env::var_os("DISPLAY")?;
        let (conn, screen) = x11rb::connect(None).ok()?;
        let root = conn.setup().roots.get(screen)?.root;
        let atom = |name: &[u8]| -> Option<u32> {
            Some(conn.intern_atom(false, name).ok()?.reply().ok()?.atom)
        };
        let has_res = conn
            .extension_information(res::X11_EXTENSION_NAME)
            .ok()
            .flatten()
            .is_some()
            && conn
                .res_query_version(1, 2)
                .ok()
                .and_then(|c| c.reply().ok())
                .is_some_and(|v| (v.server_major, v.server_minor) >= (1, 2));
        Some(Self {
            client_list: atom(b"_NET_CLIENT_LIST")?,
            wm_pid: atom(b"_NET_WM_PID")?,
            window_type: atom(b"_NET_WM_WINDOW_TYPE")?,
            type_dock: atom(b"_NET_WM_WINDOW_TYPE_DOCK")?,
            type_desktop: atom(b"_NET_WM_WINDOW_TYPE_DESKTOP")?,
            root,
            has_res,
            conn,
        })
    }

    /// `None` means the connection failed and should be dropped.
    pub fn owner_pids(&self) -> Option<HashSet<u32>> {
        let windows: Vec<u32> = self
            .conn
            .get_property(
                false,
                self.root,
                self.client_list,
                AtomEnum::WINDOW,
                0,
                u32::MAX,
            )
            .ok()?
            .reply()
            .ok()?
            .value32()
            .map(Iterator::collect)
            .unwrap_or_default();

        // Pipeline: send every request before waiting for any reply.
        let type_cookies: Vec<_> = windows
            .iter()
            .map(|&w| {
                self.conn
                    .get_property(false, w, self.window_type, AtomEnum::ATOM, 0, 16)
            })
            .collect::<Result<_, _>>()
            .ok()?;
        let mut regular = Vec::with_capacity(windows.len());
        for (&w, cookie) in windows.iter().zip(type_cookies) {
            // A window destroyed in the meantime yields an X error; just skip it.
            let Ok(reply) = cookie.reply() else { continue };
            let is_shell = reply
                .value32()
                .is_some_and(|mut t| t.any(|a| a == self.type_dock || a == self.type_desktop));
            if !is_shell {
                regular.push(w);
            }
        }

        let mut pids = HashSet::with_capacity(regular.len());
        if self.has_res {
            let specs: Vec<ClientIdSpec> = regular
                .iter()
                .map(|&w| ClientIdSpec {
                    client: w,
                    mask: ClientIdMask::LOCAL_CLIENT_PID,
                })
                .collect();
            let reply = self.conn.res_query_client_ids(&specs).ok()?.reply().ok()?;
            pids.extend(reply.ids.iter().filter_map(|id| id.value.first().copied()));
        } else {
            let cookies: Vec<_> = regular
                .iter()
                .map(|&w| {
                    self.conn
                        .get_property(false, w, self.wm_pid, AtomEnum::CARDINAL, 0, 1)
                })
                .collect::<Result<_, _>>()
                .ok()?;
            for cookie in cookies {
                if let Ok(reply) = cookie.reply()
                    && let Some(pid) = reply.value32().and_then(|mut v| v.next())
                {
                    pids.insert(pid);
                }
            }
        }
        Some(pids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_files() {
        // Captured on the development host; REMOTE_HOST and similar fields removed.
        let xrdp = b"# This is private data. Do not parse.\nUID=1000\nUSER=qingteng\nACTIVE=1\nIS_DISPLAY=0\nSTATE=active\nREMOTE=0\nLEADER_FD_SAVED=1\nTYPE=x11\nORIGINAL_TYPE=x11\nCLASS=user\nSCOPE=session-c14.scope\nFIFO=/run/systemd/sessions/c14.ref\nDISPLAY=:10\nSERVICE=xrdp-sesman\nLEADER=239850\n";
        let s = parse_session_file("c14", xrdp).unwrap();
        assert_eq!(
            (s.uid, &*s.kind, &*s.class, s.leader),
            (1000, "x11", "user", Some(239850))
        );
        assert_eq!(s.scope.as_deref(), Some("session-c14.scope"));
        assert!(s.is_live());

        let closing = b"UID=1000\nSTATE=closing\nTYPE=tty\nCLASS=user\nSCOPE=session-9.scope\nSERVICE=sshd\nLEADER=49111\n";
        assert!(!parse_session_file("9", closing).unwrap().is_live());

        assert_eq!(parse_session_file("x", b"STATE=active\n"), None);
    }

    #[test]
    fn passwd_and_login_defs() {
        let users = parse_passwd(
            "root:x:0:0:root:/root:/bin/bash\nqingteng:x:1000:1000::/home/q:/bin/bash\nbroken\n",
        );
        assert_eq!(users.get(&1000).map(|s| &**s), Some("qingteng"));
        assert_eq!(users.len(), 2);
        assert_eq!(
            parse_uid_min("# c\nUID_MIN\t\t\t 1000\nUID_MAX 60000\n"),
            Some(1000)
        );
        assert_eq!(parse_uid_min("SYS_UID_MIN 100\n"), None);
    }
}
