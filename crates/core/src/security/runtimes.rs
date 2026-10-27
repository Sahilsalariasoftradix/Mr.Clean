//! Installed or pinned runtimes with known remote-code-execution bugs.
//!
//! First entry: Node2Shell (CVE-2026-111497, October 2026), an out-of-bounds
//! write in the Brotli decoder that Node.js and Bun bundle. Any program that
//! decodes Brotli data from the network (fetch(), Express 5, body-parser 2…)
//! can be taken over by a crafted response or request. The fixed versions live
//! in iocs.json, so a new advisory needs no code change.
//!
//! Versions come from install folder names (nvm, fnm, Volta, asdf, mise, n,
//! Homebrew) and project files. Only on the real machine is `node --version`
//! / `bun --version` asked for the one on PATH.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;

use super::discover::Discovered;
use super::iocs::Iocs;
use super::{read_small, Area, Finding, Severity};
use crate::env::{Env, Os};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Advisory {
    /// "node" or "bun".
    pub runtime: String,
    pub id: String,
    pub name: String,
    pub summary: String,
    /// The first fixed version of each supported release line.
    pub fixed: Vec<String>,
}

pub type Version = (u64, u64, u64);

/// "v24.22.0", "24.22.0-alpine", "node-v22.1.0" → (24, 22, 0). Needs all three parts.
pub fn parse_version(s: &str) -> Option<Version> {
    let start = s.find(|c: char| c.is_ascii_digit())?;
    let rest = &s[start..];
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(rest.len());
    let mut it = rest[..end].split('.');
    let mut num = || it.next()?.parse::<u64>().ok();
    Some((num()?, num()?, num()?))
}

fn show((a, b, c): Version) -> String {
    format!("{a}.{b}.{c}")
}

/// `Some(advice)` when `v` has the advisory's bug: older than the fix for its
/// release line, or on a line that never got a fix and is older than the newest fix.
pub fn vulnerable(adv: &Advisory, v: Version) -> Option<String> {
    let mut fixes: Vec<Version> = adv.fixed.iter().filter_map(|f| parse_version(f)).collect();
    fixes.sort();
    let newest = *fixes.last()?;
    match fixes.iter().find(|f| f.0 == v.0) {
        Some(&fix) => (v.cmp(&fix) == Ordering::Less).then(|| format!("Update to {} or later.", show(fix))),
        None => (v < newest).then(|| {
            // The newest fixed line with an even major is the long-term-support one for Node.js.
            let lts = fixes.iter().rev().find(|f| f.0 % 2 == 0 && f.0 < newest.0).copied();
            format!(
                "This release line no longer gets fixes. Move to {}.",
                lts.map(|l| format!("{} (LTS) or {}", show(l), show(newest)))
                    .unwrap_or_else(|| show(newest))
            )
        }),
    }
}

fn label(runtime: &str) -> &'static str {
    if runtime == "bun" {
        "Bun"
    } else {
        "Node.js"
    }
}

// ------------------------------------------------------------- installed runtimes

/// Version folders created by version managers: `<dir>/<v24.22.0>`.
fn manager_dirs(env: &Env) -> Vec<(&'static str, &'static str, PathBuf)> {
    let h = &env.home;
    let mut v = vec![
        ("node", "nvm", h.join(".nvm/versions/node")),
        ("node", "fnm", h.join(".local/share/fnm/node-versions")),
        ("node", "fnm", h.join(".fnm/node-versions")),
        ("node", "Volta", h.join(".volta/tools/image/node")),
        ("node", "asdf", h.join(".asdf/installs/nodejs")),
        ("node", "mise", h.join(".local/share/mise/installs/node")),
        ("node", "n", env.root.join("usr/local/n/versions/node")),
        ("bun", "Homebrew", env.root.join("opt/homebrew/Cellar/bun")),
        ("bun", "Homebrew", env.root.join("usr/local/Cellar/bun")),
    ];
    match env.os {
        Os::Mac => {
            v.push(("node", "fnm", h.join("Library/Application Support/fnm/node-versions")));
            for cellar in ["opt/homebrew/Cellar", "usr/local/Cellar"] {
                v.push(("node", "Homebrew", env.root.join(cellar).join("node")));
                for line in ["node@18", "node@20", "node@22", "node@24", "node@26"] {
                    v.push(("node", "Homebrew", env.root.join(cellar).join(line)));
                }
            }
        }
        Os::Windows => {
            if let Some(a) = &env.app_data {
                v.push(("node", "nvm-windows", a.join("nvm")));
                v.push(("node", "fnm", a.join("fnm/node-versions")));
            }
            if let Some(l) = &env.local_app_data {
                v.push(("node", "Volta", l.join("Volta/tools/image/node")));
            }
        }
        Os::Linux => v.push((
            "node",
            "Homebrew",
            env.root.join("home/linuxbrew/.linuxbrew/Cellar/node"),
        )),
    }
    v
}

/// Every runtime version installed on this machine, with where it came from.
pub fn installed(env: &Env) -> Vec<(String, String, Version)> {
    let mut out = Vec::new();
    for (runtime, tool, dir) in manager_dirs(env) {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            if !e.path().is_dir() {
                continue;
            }
            if let Some(v) = parse_version(&e.file_name().to_string_lossy()) {
                out.push((runtime.to_string(), tool.to_string(), v));
            }
        }
    }
    // Official installers and distro packages ship the C headers with the version in them.
    for header in [
        "usr/local/include/node/node_version.h",
        "usr/include/node/node_version.h",
    ] {
        if let Some(v) = read_small(&env.root.join(header), 64 * 1024).and_then(|t| header_version(&t)) {
            out.push(("node".into(), "the system installer".into(), v));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn header_version(h: &str) -> Option<Version> {
    let part = |name: &str| -> Option<u64> {
        h.lines()
            .find_map(|l| l.trim().strip_prefix(&format!("#define {name} ")))?
            .trim()
            .parse()
            .ok()
    };
    Some((
        part("NODE_MAJOR_VERSION")?,
        part("NODE_MINOR_VERSION")?,
        part("NODE_PATCH_VERSION")?,
    ))
}

/// The `node` and `bun` that run when you type the command (real machine only).
pub fn on_path() -> Vec<(String, Version)> {
    ["node", "bun"]
        .iter()
        .filter_map(|rt| {
            let out = crate::fsutil::command(rt).arg("--version").output().ok()?;
            let v = parse_version(&String::from_utf8_lossy(&out.stdout))?;
            Some((rt.to_string(), v))
        })
        .collect()
}

pub fn installed_findings(
    installed: &[(String, String, Version)],
    default: &[(String, Version)],
    iocs: &Iocs,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for adv in &iocs.runtime_advisories {
        let rt = label(&adv.runtime);
        // The one on PATH runs your servers and scripts: High.
        for (_, v) in default.iter().filter(|(r, _)| *r == adv.runtime) {
            if let Some(advice) = vulnerable(adv, *v) {
                out.push(
                    Finding::new(
                        Severity::High,
                        Area::Runtimes,
                        format!("{rt} {} has {} ({})", show(*v), adv.name, adv.id),
                        format!("This is the {rt} you run by default. {}", adv.summary),
                    )
                    .evidence(format!("{} --version → {}", adv.runtime, show(*v)))
                    .advice(format!("{advice} Then restart any running dev servers.")),
                );
            }
        }
        // Other installed versions, one finding per tool.
        let mut by_tool: Vec<(&str, Vec<Version>)> = Vec::new();
        for (_, tool, v) in installed.iter().filter(|(r, _, _)| *r == adv.runtime) {
            if default.iter().any(|(dr, dv)| *dr == adv.runtime && dv == v) || vulnerable(adv, *v).is_none() {
                continue;
            }
            match by_tool.iter_mut().find(|(t, _)| t == tool) {
                Some((_, vs)) => vs.push(*v),
                None => by_tool.push((tool, vec![*v])),
            }
        }
        for (tool, vs) in by_tool {
            let list: Vec<String> = vs.iter().map(|v| show(*v)).collect();
            let newest = *vs.iter().max().unwrap();
            out.push(
                Finding::new(
                    Severity::Medium,
                    Area::Runtimes,
                    format!("Old {rt} with {} installed by {tool}", adv.name),
                    format!(
                        "{} {} installed by {tool} {} {}. {}",
                        rt,
                        list.join(", "),
                        if vs.len() == 1 { "has" } else { "have" },
                        adv.id,
                        adv.summary
                    ),
                )
                .evidence(list.join(", "))
                .advice(format!(
                    "{} Remove versions you no longer use{}.",
                    vulnerable(adv, newest).unwrap_or_default(),
                    match tool {
                        "nvm" => " (nvm uninstall <version>)",
                        "fnm" => " (fnm uninstall <version>)",
                        "Volta" => " (volta uninstall node@<version>)",
                        "Homebrew" => " (brew upgrade)",
                        _ => "",
                    }
                )),
            );
        }
    }
    out
}

// ------------------------------------------------------------- project pins

/// Exact versions a project pins, with the file and line: `.nvmrc`, Dockerfiles, CI…
fn pins_in(path: &Path, text: &str) -> Vec<(&'static str, Version, usize)> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut out = Vec::new();
    let mut add = |rt: &'static str, s: &str, line: usize| {
        if let Some(v) = parse_version(s.trim().trim_matches(['"', '\''])) {
            out.push((rt, v, line));
        }
    };
    for (i, line) in text.lines().enumerate() {
        let l = line.trim();
        let n = i + 1;
        match name.as_str() {
            ".nvmrc" | ".node-version" if !l.starts_with('#') && !l.is_empty() => add("node", l, n),
            ".tool-versions" => {
                let mut parts = l.split_whitespace();
                match (parts.next(), parts.next()) {
                    (Some("nodejs" | "node"), Some(v)) => add("node", v, n),
                    (Some("bun"), Some(v)) => add("bun", v, n),
                    _ => {}
                }
            }
            _ if name.starts_with("Dockerfile") || name.ends_with(".Dockerfile") || name.ends_with(".dockerfile") => {
                let lower = l.to_ascii_lowercase();
                if let Some(image) = lower
                    .strip_prefix("from ")
                    .map(|r| r.split_whitespace().next().unwrap_or(""))
                {
                    let image = image.rsplit('/').next().unwrap_or(image);
                    if let Some(tag) = image.strip_prefix("node:") {
                        add("node", tag, n);
                    } else if let Some(tag) = image.strip_prefix("bun:") {
                        add("bun", tag, n);
                    }
                }
            }
            _ if name.ends_with(".yml") || name.ends_with(".yaml") => {
                for (key, rt) in [("node-version:", "node"), ("bun-version:", "bun")] {
                    if let Some(v) = l.strip_prefix(key) {
                        add(rt, v, n);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// `"volta": { "node": "24.22.0" }` and `"packageManager": "bun@1.4.3"` in package.json.
fn package_pins(text: &str) -> Vec<(&'static str, Version)> {
    let Ok(pkg) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(v) = pkg["volta"]["node"].as_str().and_then(parse_version) {
        out.push(("node", v));
    }
    if let Some(v) = pkg["packageManager"]
        .as_str()
        .and_then(|p| p.strip_prefix("bun@"))
        .and_then(parse_version)
    {
        out.push(("bun", v));
    }
    out
}

pub fn project_findings(d: &Discovered, iocs: &Iocs) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut check = |path: &Path, rt: &str, v: Version, line: Option<usize>| {
        for adv in iocs.runtime_advisories.iter().filter(|a| a.runtime == rt) {
            if let Some(advice) = vulnerable(adv, v) {
                let mut f = Finding::new(
                    Severity::Medium,
                    Area::Runtimes,
                    format!("Project pins {} {} ({})", label(rt), show(v), adv.name),
                    format!(
                        "This file sets the {} version for this project, its containers or its CI, and that version has {}. {}",
                        label(rt),
                        adv.id,
                        adv.summary
                    ),
                )
                .path(path)
                .evidence(format!("{} {}", label(rt), show(v)))
                .advice(format!("{advice} Change the version here and rebuild any images built from it."));
                if let Some(n) = line {
                    f = f.line(n);
                }
                out.push(f);
            }
        }
    };
    for p in d.runtime_pins.iter().chain(&d.workflows) {
        let Some(text) = read_small(p, 512 * 1024) else {
            continue;
        };
        for (rt, v, line) in pins_in(p, &text) {
            check(p, rt, v, Some(line));
        }
    }
    for p in &d.packages {
        let Some(text) = read_small(p, 1024 * 1024) else {
            continue;
        };
        for (rt, v) in package_pins(&text) {
            check(p, rt, v, None);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node2shell() -> Advisory {
        Iocs::bundled()
            .runtime_advisories
            .into_iter()
            .find(|a| a.runtime == "node")
            .unwrap()
    }

    #[test]
    fn versions_parse() {
        assert_eq!(parse_version("v24.22.0"), Some((24, 22, 0)));
        assert_eq!(
            parse_version("v22.22.0\n"),
            Some((22, 22, 0)),
            "`node --version` output"
        );
        assert_eq!(parse_version("24.22.0-alpine3.20"), Some((24, 22, 0)));
        assert_eq!(parse_version("node-v22.1.0-darwin-arm64"), Some((22, 1, 0)));
        assert_eq!(parse_version("lts/*"), None);
        assert_eq!(parse_version("22"), None);
    }

    #[test]
    fn node2shell_ranges() {
        let a = node2shell();
        assert!(vulnerable(&a, (24, 22, 0)).is_some());
        assert!(vulnerable(&a, (24, 22, 1)).is_none());
        assert!(vulnerable(&a, (22, 23, 3)).is_some());
        assert!(vulnerable(&a, (22, 23, 4)).is_none());
        assert!(vulnerable(&a, (26, 12, 0)).is_some());
        assert!(vulnerable(&a, (26, 13, 0)).is_none());
        // End-of-life lines never got a fix.
        let eol = vulnerable(&a, (20, 19, 0)).unwrap();
        assert!(eol.contains("no longer gets fixes") && eol.contains("24.22.1"), "{eol}");
        assert!(vulnerable(&a, (25, 9, 0)).is_some());
        assert!(vulnerable(&a, (27, 0, 0)).is_none());
        let bun = Iocs::bundled()
            .runtime_advisories
            .into_iter()
            .find(|a| a.runtime == "bun")
            .unwrap();
        assert!(vulnerable(&bun, (1, 4, 3)).is_some());
        assert!(vulnerable(&bun, (1, 4, 4)).is_none());
    }

    #[test]
    fn finds_pins() {
        let p = |n: &str, t: &str| pins_in(Path::new(n), t);
        assert_eq!(p(".nvmrc", "v24.22.0\n"), [("node", (24, 22, 0), 1)]);
        assert_eq!(p(".nvmrc", "lts/*\n"), []);
        assert_eq!(
            p(".tool-versions", "python 3.12.1\nnodejs 22.20.0\n"),
            [("node", (22, 20, 0), 2)]
        );
        assert_eq!(
            p("Dockerfile", "FROM node:24.22.0-alpine AS build\nFROM nginx:1.27\n"),
            [("node", (24, 22, 0), 1)]
        );
        assert_eq!(p("Dockerfile", "FROM node:24-slim\n"), []);
        assert_eq!(p("api.Dockerfile", "FROM oven/bun:1.4.3\n"), [("bun", (1, 4, 3), 1)]);
        assert_eq!(
            p(
                "ci.yml",
                "      - uses: actions/setup-node@v4\n        with:\n          node-version: '24.21.0'\n"
            ),
            [("node", (24, 21, 0), 3)]
        );
        assert_eq!(p("ci.yml", "          node-version: 22\n"), []);
        assert_eq!(
            package_pins(r#"{"volta":{"node":"22.1.0"},"packageManager":"bun@1.4.3"}"#),
            [("node", (22, 1, 0)), ("bun", (1, 4, 3))]
        );
    }

    #[test]
    fn header_versions() {
        let h = "#define NODE_MAJOR_VERSION 24\n#define NODE_MINOR_VERSION 22\n#define NODE_PATCH_VERSION 0\n";
        assert_eq!(header_version(h), Some((24, 22, 0)));
    }
}
