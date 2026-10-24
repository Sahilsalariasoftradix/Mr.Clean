//! Code a project runs on its own, and scripts disguised as other files.
//!
//! Modelled on a real attack (a pull request to this repo, October 2026): a
//! VS Code task set to run when the folder is opened started `node` on a
//! "font" that was really an obfuscated loader, and `npm run dev` / `build`
//! were changed to run another copy first. Opening the folder or starting the
//! app was enough; no `npm install` needed. The loader then fetched its next
//! stage from an address hidden in Ethereum transactions.
//!
//! Everything here only reads files (and, on the real machine, process command
//! lines). Nothing found is ever run.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use super::discover::{Discovered, ASSET_EXTENSIONS};
use super::iocs::Iocs;
use super::{patterns, read_small, Area, Finding, Severity};
use crate::env::{Env, Os};

const MAX_SCRIPT: u64 = 2 * 1024 * 1024;
/// Interpreters an editor task or npm script can hand a file to.
const RUNNERS: &str = r"node|nodejs|bun|deno(?:\s+run)?|tsx|ts-node|python3?|ruby|perl|bash|sh|zsh|pwsh|powershell";

pub fn findings(d: &Discovered, iocs: &Iocs) -> Vec<Finding> {
    let mut out = Vec::new();
    for p in &d.editor_files {
        out.extend(editor_file(p, iocs));
    }
    for p in &d.packages {
        out.extend(package_scripts(p, iocs));
    }
    for p in &d.assets {
        out.extend(disguised_script(p, iocs));
    }
    for p in &d.scripts {
        out.extend(hidden_script(p, iocs));
    }
    out
}

/// Editor tasks the user's own VS Code-family editors run in every folder.
pub fn user_editor_tasks(env: &Env, iocs: &Iocs) -> Vec<Finding> {
    const EDITORS: &[&str] = &["Code", "Code - Insiders", "Cursor", "VSCodium", "Windsurf"];
    let base = match env.os {
        Os::Mac => Some(env.home.join("Library/Application Support")),
        Os::Linux => Some(env.home.join(".config")),
        Os::Windows => env.app_data.clone(),
    };
    let Some(base) = base else { return Vec::new() };
    EDITORS
        .iter()
        .flat_map(|e| editor_file(&base.join(e).join("User/tasks.json"), iocs))
        .collect()
}

// ------------------------------------------------------------- editor tasks

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).unwrap())
}

fn editor_file(path: &Path, iocs: &Iocs) -> Vec<Finding> {
    static FOLDER_OPEN: OnceLock<Regex> = OnceLock::new();
    static AUTO_TASKS: OnceLock<Regex> = OnceLock::new();
    static QUIET: OnceLock<Regex> = OnceLock::new();
    static COMMAND: OnceLock<Regex> = OnceLock::new();
    static ARGS: OnceLock<Regex> = OnceLock::new();
    let Some(text) = read_small(path, 1024 * 1024) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if re(&AUTO_TASKS, r#""task\.allowAutomaticTasks"\s*:\s*(true|"on")"#).is_match(&text) {
        out.push(
            Finding::new(
                Severity::Medium,
                Area::ProjectCode,
                "Folder settings let tasks run without asking",
                "This folder's VS Code settings turn on automatic tasks, so a task here can start as soon as the folder is opened, without the usual prompt.",
            )
            .path(path)
            .evidence("\"task.allowAutomaticTasks\"")
            .advice("Remove the setting unless you added it yourself."),
        );
    }
    if !re(&FOLDER_OPEN, r#""runOn"\s*:\s*"folderOpen""#).is_match(&text) {
        return out;
    }

    // What the task runs: "command" plus its "args".
    let mut parts: Vec<String> = re(&COMMAND, r#""command"\s*:\s*"((?:\\.|[^"\\])*)""#)
        .captures_iter(&text)
        .map(|c| c[1].to_string())
        .collect();
    for c in re(&ARGS, r#""args"\s*:\s*\[([^\]]*)\]"#).captures_iter(&text) {
        parts.extend(
            c[1].split(',')
                .map(|a| a.trim().trim_matches('"').to_string())
                .filter(|a| !a.is_empty()),
        );
    }
    let ran = parts.join(" ");
    let mut reasons = Vec::new();
    if re(&QUIET, r#""reveal"\s*:\s*"never"|"hide"\s*:\s*true|"echo"\s*:\s*false"#).is_match(&text) {
        reasons.push("hides its terminal so you don't see it run".to_string());
    }
    let root = workspace_root(path);
    for target in run_targets(&ran) {
        if let Some(why) = target_problem(&target, root.as_deref(), iocs) {
            reasons.push(why);
        }
    }
    if let Some(h) = patterns::scan_text(&ran)
        .into_iter()
        .find(|h| h.severity == Severity::High)
    {
        reasons.push(h.reason.to_string());
    }
    let severity = if reasons.is_empty() {
        Severity::Medium
    } else {
        Severity::High
    };
    let detail = if reasons.is_empty() {
        "A task here runs a command automatically as soon as this folder is opened in VS Code, Cursor or a similar editor.".to_string()
    } else {
        format!(
            "A task here runs automatically as soon as this folder is opened in VS Code, Cursor or a similar editor, and it {}. Malware hidden in shared projects and pull requests starts this way.",
            reasons.join("; ")
        )
    };
    out.push(
        Finding::new(severity, Area::ProjectCode, "Editor task runs when the folder is opened", detail)
            .path(path)
            .evidence(patterns::excerpt(if ran.is_empty() { "runOn: folderOpen" } else { &ran }))
            .advice("Don't open this folder in your editor until it's checked (or open it in Restricted Mode). Delete the task and the file it runs, then check the project's recent commits.")
            .quarantinable(),
    );
    out
}

/// The folder a `.vscode/…` file belongs to.
fn workspace_root(path: &Path) -> Option<PathBuf> {
    let dir = path.parent()?;
    dir.ends_with(".vscode")
        .then(|| dir.parent().map(Path::to_path_buf))
        .flatten()
}

// ------------------------------------------------------------- npm scripts

fn package_scripts(path: &Path, iocs: &Iocs) -> Vec<Finding> {
    let Some(pkg) = read_small(path, 1024 * 1024).and_then(|t| serde_json::from_str::<Value>(&t).ok()) else {
        return Vec::new();
    };
    let Some(scripts) = pkg["scripts"].as_object() else {
        return Vec::new();
    };
    let dir = path.parent();
    let mut out = Vec::new();
    for (name, cmd) in scripts {
        let Some(cmd) = cmd.as_str() else { continue };
        let problems: Vec<String> = run_targets(cmd)
            .iter()
            .filter_map(|t| target_problem(t, dir, iocs))
            .collect();
        if !problems.is_empty() {
            out.push(
                Finding::new(
                    Severity::High,
                    Area::ProjectCode,
                    format!("npm script \"{name}\" runs hidden code"),
                    format!(
                        "Running `npm run {name}` would start a file that {}. This is how poisoned projects infect whoever runs them.",
                        problems.join("; ")
                    ),
                )
                .path(path)
                .evidence(patterns::excerpt(&format!("\"{name}\": \"{cmd}\"")))
                .advice("Don't run npm scripts in this project. Remove the extra command from package.json and delete the file it runs."),
            );
        } else if let Some(h) = patterns::scan_text(cmd)
            .into_iter()
            .find(|h| h.severity == Severity::High)
        {
            out.push(
                Finding::new(
                    Severity::Medium,
                    Area::ProjectCode,
                    format!("npm script \"{name}\" looks risky"),
                    format!("This script {}.", h.reason),
                )
                .path(path)
                .evidence(patterns::excerpt(&format!("\"{name}\": \"{cmd}\""))),
            );
        }
    }
    out
}

/// Files a command line hands to an interpreter: `node api.js && vite` → `api.js`.
fn run_targets(cmd: &str) -> Vec<String> {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = R.get_or_init(|| {
        Regex::new(&format!(
            r#"(?i)(?:^|[\s;&|("'])(?:{RUNNERS})(?:\.exe)?\s+((?:-\S+\s+)*)([^\s;&|"')]+)"#
        ))
        .unwrap()
    });
    r.captures_iter(cmd)
        .map(|c| c[2].to_string())
        .filter(|t| !t.starts_with('-'))
        .collect()
}

/// Why handing `target` to an interpreter is suspicious, if it is.
fn target_problem(target: &str, base: Option<&Path>, iocs: &Iocs) -> Option<String> {
    let clean = target
        .replace("${workspaceFolder}", ".")
        .replace("${workspaceRoot}", ".");
    let name = clean.rsplit(['/', '\\']).next().unwrap_or(&clean);
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    if let Some(e) = ext.as_deref().filter(|e| ASSET_EXTENSIONS.contains(e)) {
        return Some(format!("is named like a .{e} file but is run as code ({name})"));
    }
    let file = base?.join(clean.trim_start_matches("./"));
    let text = read_small(&file, MAX_SCRIPT)?;
    if let Some(m) = iocs.has_script_marker(&text) {
        return Some(format!(
            "contains a known malware marker ({}) in {name}",
            patterns::mask(m)
        ));
    }
    patterns::hidden_code(&text)
        .first()
        .map(|h| format!("{} ({name})", h.reason))
}

// ------------------------------------------------------------- disguised and hidden scripts

/// A font, image or media file that is really readable code.
fn disguised_script(path: &Path, iocs: &Iocs) -> Option<Finding> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > 10 * 1024 * 1024 {
        return None;
    }
    let mut head = vec![0u8; 4096];
    let n = {
        use std::io::Read;
        std::fs::File::open(path).ok()?.read(&mut head).ok()?
    };
    head.truncate(n);
    if !looks_like_code(&head) {
        return None;
    }
    let ext = path.extension()?.to_string_lossy().to_ascii_lowercase();
    let text = read_small(path, MAX_SCRIPT).unwrap_or_default();
    let mut detail = format!(
        "This file is named like a .{ext} file but contains JavaScript instead. Real fonts and images are binary data, so this is a script in disguise, usually started by an editor task or npm script."
    );
    let extra: Vec<&str> = patterns::hidden_code(&text).iter().map(|h| h.reason).collect();
    if !extra.is_empty() {
        detail.push_str(&format!(" It also {}.", extra.join("; ")));
    }
    if let Some(m) = iocs.has_script_marker(&text) {
        detail.push_str(&format!(" It matches known malware ({}).", patterns::mask(m)));
    }
    Some(
        Finding::new(Severity::High, Area::ProjectCode, format!("Script disguised as a .{ext} file"), detail)
            .path(path)
            .evidence(patterns::excerpt(&text))
            .advice("Don't run anything in this project. Delete the file, look for an editor task or npm script that runs it, and check who added it.")
            .quarantinable(),
    )
}

/// Text with JavaScript in it, not binary font or image data.
fn looks_like_code(head: &[u8]) -> bool {
    if head.len() < 16 || head.contains(&0) {
        return false;
    }
    let text = String::from_utf8_lossy(head);
    let printable = text.chars().filter(|c| !c.is_control() || c.is_whitespace()).count();
    if printable * 100 < text.chars().count() * 95 {
        return false;
    }
    let code = text.trim_start_matches(['\u{feff}', ' ', '\t', '\r', '\n']);
    [
        "function",
        "require(",
        "import",
        "=>",
        "var ",
        "const ",
        "let ",
        "eval(",
        "global[",
        "module.exports",
    ]
    .iter()
    .any(|k| code.contains(k))
}

/// A `.js` file with deliberately hidden code or a known malware marker.
fn hidden_script(path: &Path, iocs: &Iocs) -> Option<Finding> {
    let text = read_small(path, MAX_SCRIPT)?;
    let marker = iocs.has_script_marker(&text);
    let hits = patterns::hidden_code(&text);
    if marker.is_none() && hits.is_empty() {
        return None;
    }
    let mut reasons: Vec<String> = hits.iter().map(|h| h.reason.to_string()).collect();
    if let Some(m) = marker {
        reasons.push(format!("contains a known malware marker ({})", patterns::mask(m)));
    }
    let mut f = Finding::new(
        Severity::High,
        Area::ProjectCode,
        "Hidden code in a JavaScript file",
        format!("This file {}. Ordinary source code never needs to hide itself like this.", reasons.join("; ")),
    )
    .path(path)
    .advice("Don't run it or the project's npm scripts. Check the file's history (git log) and delete it if nobody on your team wrote it.")
    .quarantinable();
    if let Some((n, l)) = patterns::first_matching_line(&text) {
        f = f.line(n).evidence(l);
    }
    Some(f)
}

// ------------------------------------------------------------- running processes

/// Malware loaders running right now, from process command lines
/// (`node -e "global['r']=require;…"` is how this family starts its next stage).
pub fn running_loaders(procs: &[(u32, String)], iocs: &Iocs) -> Vec<Finding> {
    static LOADER: OnceLock<Regex> = OnceLock::new();
    let loader = re(&LOADER, r#"global\[['"](_V|r)['"]\]\s*=|global\[['"]_H2?['"]\]\s*="#);
    procs
        .iter()
        .filter_map(|(pid, cmd)| {
            let why = iocs
                .has_script_marker(cmd)
                .map(|m| format!("matches known malware ({})", patterns::mask(m)))
                .or_else(|| loader.is_match(cmd).then(|| "runs the BeaverTail / InvisibleFerret loader".to_string()))?;
            Some(
                Finding::new(
                    Severity::High,
                    Area::KnownMalware,
                    "Malware is running on this computer now",
                    format!("Process {pid} {why}. This family steals saved passwords, browser cookies, crypto wallets and SSH/GitHub keys."),
                )
                .evidence(patterns::excerpt(cmd))
                .advice("Disconnect from the internet and restart the computer. From another device, change your passwords and revoke GitHub tokens and SSH keys. Then run this scan again."),
            )
        })
        .collect()
}

/// Command lines of the processes on this machine.
pub fn process_command_lines() -> Vec<(u32, String)> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_cmd(UpdateKind::Always),
    );
    sys.processes()
        .iter()
        .map(|(pid, p)| {
            let cmd: Vec<String> = p.cmd().iter().map(|s| s.to_string_lossy().into_owned()).collect();
            (pid.as_u32(), cmd.join(" "))
        })
        .filter(|(_, c)| !c.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_run_targets() {
        assert_eq!(run_targets("node api.js && vite"), ["api.js"]);
        assert_eq!(run_targets("vite build"), Vec::<String>::new());
        assert_eq!(
            run_targets("node --no-warnings ./public/fonts/x.ttf"),
            ["./public/fonts/x.ttf"]
        );
        assert_eq!(run_targets("tsc --noEmit && node scripts/gen.mjs"), ["scripts/gen.mjs"]);
        assert_eq!(run_targets("eslint . && prettier --check ."), Vec::<String>::new());
    }

    #[test]
    fn code_versus_binary() {
        assert!(looks_like_code(b"\t\t\t\tfunction y7(R,c){var n=[];return n}"));
        assert!(!looks_like_code(&[
            0, 1, 0, 0, 0, 14, 0, 128, 0, 3, 0, 96, 79, 83, 47, 50
        ]));
        assert!(!looks_like_code(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR"));
        assert!(!looks_like_code(b"%PDF-1.7 just some words that are long enough"));
    }

    #[test]
    fn running_loader_is_reported() {
        let iocs = Iocs::bundled();
        let procs = vec![
            (
                10,
                "node -e global['_V']='A8-';global['_H']='http://1.2.3.4:80';var x=1".to_string(),
            ),
            (11, "/usr/bin/node server.js".to_string()),
            (12, "node -e console.log(1)".to_string()),
        ];
        let f = running_loaders(&procs, &iocs);
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("Process 10"));
    }
}
