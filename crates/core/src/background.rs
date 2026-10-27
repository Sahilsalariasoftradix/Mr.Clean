//! What Mr.Clean does while its window is closed: the menu bar / tray status,
//! automatic security scans, and the notifications they may send.
//!
//! All decisions live here so they can be tested; the Tauri shell only runs
//! the timer, draws the menu and shows notifications. Settings are a small
//! JSON file next to the quarantine (`~/.mrclean/settings.json`).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::env::{Env, Os};
use crate::security::{SecurityReport, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Schedule {
    #[default]
    Off,
    Daily,
    Weekly,
}

impl Schedule {
    fn every_secs(self) -> Option<i64> {
        match self {
            Schedule::Off => None,
            Schedule::Daily => Some(24 * 3600),
            Schedule::Weekly => Some(7 * 24 * 3600),
        }
    }
}

/// Disk use (in %) that counts as "almost full", and the level it must drop
/// back under before we warn again.
pub const DISK_WARN_PERCENT: f64 = 90.0;
const DISK_REARM_PERCENT: f64 = 85.0;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Closing the window keeps Mr.Clean running in the menu bar / tray.
    pub keep_in_menu_bar: bool,
    pub auto_scan: Schedule,
    pub notify_threats: bool,
    pub notify_disk: bool,
    /// Unix seconds of the last automatic scan.
    pub last_auto_scan: Option<i64>,
    /// High/medium findings already reported, so each one notifies once.
    pub known_threats: Vec<String>,
    /// Already warned that the disk is almost full.
    pub disk_warned: bool,
}

impl Settings {
    pub fn defaults_for(os: Os) -> Self {
        Settings {
            // Mac apps usually keep running after their window closes; on
            // Windows and Linux closing the window quits, unless you opt in.
            keep_in_menu_bar: os == Os::Mac,
            auto_scan: Schedule::Off,
            notify_threats: true,
            notify_disk: true,
            last_auto_scan: None,
            known_threats: Vec::new(),
            disk_warned: false,
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Settings::defaults_for(Os::current())
    }
}

fn path(env: &Env) -> PathBuf {
    env.home.join(".mrclean/settings.json")
}

pub fn load(env: &Env) -> Settings {
    std::fs::read_to_string(path(env))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_else(|| Settings::defaults_for(env.os))
}

pub fn save(env: &Env, s: &Settings) -> Result<(), String> {
    let p = path(env);
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(s).map_err(|e| e.to_string())?;
    std::fs::write(p, json).map_err(|e| format!("Couldn't save settings: {e}"))
}

/// Whether an automatic scan should run now.
pub fn is_due(s: &Settings, now: i64) -> bool {
    match (s.auto_scan.every_secs(), s.last_auto_scan) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(every), Some(last)) => now - last >= every || now < last,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Alert {
    pub title: String,
    pub body: String,
}

/// Notifications for a finished automatic scan, and the settings to save
/// afterwards (remembered threats, disk warning state, scan time).
pub fn after_scan(
    s: &Settings,
    report: Option<&SecurityReport>,
    disk_used_percent: Option<f64>,
    now: i64,
) -> (Vec<Alert>, Settings) {
    let mut next = s.clone();
    next.last_auto_scan = Some(now);
    let mut alerts = Vec::new();

    if let Some(r) = report {
        let serious: Vec<_> = r.findings.iter().filter(|f| f.severity >= Severity::Medium).collect();
        let new: Vec<_> = serious.iter().filter(|f| !s.known_threats.contains(&f.id)).collect();
        if s.notify_threats && !new.is_empty() {
            let high = new.iter().filter(|f| f.severity == Severity::High).count();
            alerts.push(Alert {
                title: if new.len() == 1 {
                    "Mr.Clean found a new security issue".into()
                } else {
                    format!("Mr.Clean found {} new security issues", new.len())
                },
                body: if high > 0 {
                    format!("{}. Open Mr.Clean to review it.", new[0].title)
                } else {
                    format!("{}. Worth a look when you have a minute.", new[0].title)
                },
            });
        }
        // Only remember what's still there, so a threat that comes back notifies again.
        next.known_threats = serious.iter().map(|f| f.id.clone()).collect();
    }

    if let Some(pct) = disk_used_percent {
        if pct >= DISK_WARN_PERCENT && !s.disk_warned {
            if s.notify_disk {
                alerts.push(Alert {
                    title: format!("Your disk is {}% full", pct.round()),
                    body: "Open Mr.Clean to see what's taking the space and free some up.".into(),
                });
            }
            next.disk_warned = true;
        } else if pct < DISK_REARM_PERCENT {
            next.disk_warned = false;
        }
    }
    (alerts, next)
}

/// Sizes in the same style as the app: 1000-based, one decimal under 100.
pub fn human_bytes(n: u64) -> String {
    if n == 0 {
        return "0 B".into();
    }
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let i = ((n as f64).ln() / 1000f64.ln()).floor().min(4.0) as usize;
    let v = n as f64 / 1000f64.powi(i as i32);
    if i == 0 || v >= 100.0 {
        format!("{v:.0} {}", UNITS[i])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// The status lines at the top of the menu bar / tray menu.
pub fn status_lines(disk: Option<(u64, u64)>, memory: Option<(u64, u64)>, threats: Option<usize>) -> [String; 3] {
    [
        match disk {
            Some((free, total)) if total > 0 => format!("Disk: {} free of {}", human_bytes(free), human_bytes(total)),
            _ => "Disk: —".into(),
        },
        match memory {
            Some((used, total)) if total > 0 => {
                format!("Memory: {} of {} in use", human_bytes(used), human_bytes(total))
            }
            _ => "Memory: —".into(),
        },
        match threats {
            None => "Security: not scanned yet".into(),
            Some(0) => "Security: no issues".into(),
            Some(1) => "Security: 1 issue to review".into(),
            Some(n) => format!("Security: {n} issues to review"),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{Area, Counts, Finding};

    fn report(findings: &[(&str, Severity)]) -> SecurityReport {
        SecurityReport {
            findings: findings
                .iter()
                .map(|(id, sev)| {
                    let mut f = Finding::new(*sev, Area::Startup, format!("Finding {id}"), "");
                    f.id = id.to_string();
                    f
                })
                .collect(),
            scanned_repos: 0,
            scanned_projects: 0,
            scanned_packages: 0,
            duration_ms: 0,
            counts: Counts::default(),
        }
    }

    #[test]
    fn settings_round_trip_in_a_sandbox() {
        let d = tempfile::tempdir().unwrap();
        let env = Env::sandboxed(d.path(), Os::Windows);
        let s = load(&env);
        assert!(!s.keep_in_menu_bar, "Windows defaults to quitting on close");
        assert_eq!(s.auto_scan, Schedule::Off);
        let changed = Settings {
            auto_scan: Schedule::Weekly,
            keep_in_menu_bar: true,
            ..s
        };
        save(&env, &changed).unwrap();
        assert_eq!(load(&env), changed);
        assert!(Settings::defaults_for(Os::Mac).keep_in_menu_bar);
    }

    #[test]
    fn schedule_due() {
        let mut s = Settings::defaults_for(Os::Mac);
        assert!(!is_due(&s, 1_000_000), "off never runs");
        s.auto_scan = Schedule::Daily;
        assert!(is_due(&s, 1_000_000), "first run is due straight away");
        s.last_auto_scan = Some(1_000_000);
        assert!(!is_due(&s, 1_000_000 + 3600));
        assert!(is_due(&s, 1_000_000 + 24 * 3600));
        s.auto_scan = Schedule::Weekly;
        assert!(!is_due(&s, 1_000_000 + 24 * 3600));
        assert!(is_due(&s, 1_000_000 - 10), "clock moved back");
    }

    #[test]
    fn notifies_each_new_threat_once() {
        let s = Settings::defaults_for(Os::Mac);
        let r = report(&[("a", Severity::High), ("b", Severity::Low)]);
        let (alerts, s) = after_scan(&s, Some(&r), None, 10);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].title, "Mr.Clean found a new security issue");
        assert!(alerts[0].body.starts_with("Finding a"));
        assert_eq!(s.known_threats, ["a"], "low findings aren't tracked");
        assert_eq!(s.last_auto_scan, Some(10));

        let (again, s) = after_scan(&s, Some(&r), None, 20);
        assert!(again.is_empty(), "same threat, no second notification");

        let r2 = report(&[("a", Severity::High), ("c", Severity::Medium), ("d", Severity::Medium)]);
        let (more, _) = after_scan(&s, Some(&r2), None, 30);
        assert_eq!(more[0].title, "Mr.Clean found 2 new security issues");

        let quiet = Settings {
            notify_threats: false,
            ..Settings::defaults_for(Os::Mac)
        };
        assert!(after_scan(&quiet, Some(&r2), None, 40).0.is_empty());
    }

    #[test]
    fn warns_once_when_the_disk_fills_up() {
        let s = Settings::defaults_for(Os::Mac);
        let (a, s) = after_scan(&s, None, Some(93.4), 1);
        assert_eq!(a[0].title, "Your disk is 93% full");
        let (a, s) = after_scan(&s, None, Some(95.0), 2);
        assert!(a.is_empty(), "already warned");
        let (_, s) = after_scan(&s, None, Some(80.0), 3);
        assert!(!s.disk_warned, "freed space, so warn again next time");
        let (a, _) = after_scan(&s, None, Some(91.0), 4);
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn status_text() {
        assert_eq!(human_bytes(658_000_000_000), "658 GB");
        assert_eq!(human_bytes(6_120_000_000), "6.1 GB");
        assert_eq!(human_bytes(512), "512 B");
        let l = status_lines(
            Some((658_000_000_000, 1_000_000_000_000)),
            Some((6_100_000_000, 16_000_000_000)),
            Some(2),
        );
        assert_eq!(l[0], "Disk: 658 GB free of 1.0 TB");
        assert_eq!(l[1], "Memory: 6.1 GB of 16.0 GB in use");
        assert_eq!(l[2], "Security: 2 issues to review");
        assert_eq!(status_lines(None, None, None)[2], "Security: not scanned yet");
    }
}
