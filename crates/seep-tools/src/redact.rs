//! Secret redaction.
//!
//! Tool output goes three places that a raw credential must never reach: a chat
//! message, the audit log, and the model's context window. All three are
//! long-lived, and the last one gets sent to a third-party API.
//!
//! This is defence in depth, not a guarantee. It cannot recognise a secret that
//! looks like ordinary text, so it is layered *behind* not storing credentials in
//! places tools read from. What it does reliably catch is the common, costly
//! case: an `env` dump, a config file, a connection string in an error message,
//! a token echoed by a failing curl.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

/// Replacement text. Deliberately distinctive so it is obvious in a transcript
/// that redaction happened, rather than looking like the value was empty.
const MASK: &str = "«redacted»";

struct Pattern {
    regex: Regex,
    /// Capture group holding the secret itself. Group 0 masks the whole match.
    group: usize,
}

/// Patterns for credentials that carry a recognisable shape.
static PATTERNS: Lazy<Vec<Pattern>> = Lazy::new(|| {
    let specs: &[(&str, usize)] = &[
        // KEY=value / KEY: value, for key names that imply a secret.
        (
            r#"(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|AUTH)[A-Z0-9_]*)\s*[=:]\s*["']?([^\s"'`,;]{4,})["']?"#,
            2,
        ),
        // Authorization headers.
        (r#"(?i)\b(authorization|proxy-authorization)\s*:\s*(\S+\s+)?(\S{8,})"#, 3),
        // Credentials embedded in a URL.
        (r#"(?i)([a-z][a-z0-9+.\-]*://)([^:/\s@]+):([^@/\s]+)@"#, 3),
        // Well-known token shapes.
        (r#"\b(sk-[A-Za-z0-9_\-]{16,})\b"#, 1),
        (r#"\b(sk-ant-[A-Za-z0-9_\-]{16,})\b"#, 1),
        (r#"\b(gh[pousr]_[A-Za-z0-9]{16,})\b"#, 1),
        (r#"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b"#, 1),
        (r#"\b(AKIA[0-9A-Z]{16})\b"#, 1),
        (r#"\b(AIza[0-9A-Za-z_\-]{35})\b"#, 1),
        (r#"\b(glpat-[A-Za-z0-9_\-]{20,})\b"#, 1),
        (r#"\b(npm_[A-Za-z0-9]{36})\b"#, 1),
        (r#"\b(dckr_pat_[A-Za-z0-9_\-]{20,})\b"#, 1),
        // Telegram bot tokens.
        (r#"\b(\d{8,10}:AA[A-Za-z0-9_\-]{30,})\b"#, 1),
        // JWTs.
        (r#"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b"#, 1),
        // PEM private key blocks, masked whole.
        (
            r#"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"#,
            0,
        ),
    ];
    specs
        .iter()
        .filter_map(|(pattern, group)| {
            // A malformed pattern must not take the process down; skip it and
            // keep the rest of the protections working.
            match Regex::new(pattern) {
                Ok(regex) => Some(Pattern { regex, group: *group }),
                Err(e) => {
                    tracing::error!(pattern = pattern, error = %e, "invalid redaction pattern");
                    None
                }
            }
        })
        .collect()
});

/// Masks secrets in text.
#[derive(Debug, Default, Clone)]
pub struct Redactor {
    /// Exact values known to be secret — anything the secrets store has handed
    /// out this session. These are caught even when they look like plain words.
    literals: HashSet<String>,
    disabled: bool,
}

impl Redactor {
    pub fn new() -> Self {
        Self::default()
    }

    /// A redactor that passes text through untouched.
    ///
    /// Only appropriate where the output is going nowhere persistent — a local
    /// interactive terminal the operator is already staring at.
    pub fn disabled() -> Self {
        Self { literals: HashSet::new(), disabled: true }
    }

    /// Register a known secret value so it is masked wherever it appears.
    pub fn add_literal(&mut self, value: impl Into<String>) {
        let value = value.into();
        // Very short values would mask ordinary text everywhere and make output
        // unreadable, which in practice gets redaction turned off entirely.
        if value.len() >= 6 {
            self.literals.insert(value);
        }
    }

    pub fn literal_count(&self) -> usize {
        self.literals.len()
    }

    /// Mask every recognised secret in `text`.
    pub fn redact(&self, text: &str) -> String {
        if self.disabled || text.is_empty() {
            return text.to_string();
        }

        let mut result = text.to_string();

        // Known literals first: they are exact and cannot false-positive.
        // Longest first, so a value that contains another is masked as a whole.
        let mut literals: Vec<&String> = self.literals.iter().collect();
        literals.sort_by_key(|s| std::cmp::Reverse(s.len()));
        for literal in literals {
            if result.contains(literal.as_str()) {
                result = result.replace(literal.as_str(), MASK);
            }
        }

        for pattern in PATTERNS.iter() {
            result = replace_group(&pattern.regex, pattern.group, &result);
        }
        result
    }

    /// Whether redaction would change this text. Useful for warning an operator
    /// that a file they asked to display contains credentials.
    pub fn contains_secret(&self, text: &str) -> bool {
        self.redact(text) != text
    }
}

/// Replace only the capture group, preserving the surrounding context so the
/// output still reads as `API_KEY=«redacted»` rather than losing the key name.
fn replace_group(regex: &Regex, group: usize, text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for caps in regex.captures_iter(text) {
        let Some(target) = caps.get(group).or_else(|| caps.get(0)) else {
            continue;
        };
        let whole = caps.get(0).expect("group 0 always exists");
        if whole.start() < last {
            continue;
        }
        out.push_str(&text[last..target.start()]);
        out.push_str(MASK);
        last = target.end();
    }
    out.push_str(&text[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r() -> Redactor {
        Redactor::new()
    }

    #[test]
    fn env_style_secrets_are_masked_but_keys_remain_visible() {
        let out = r().redact("DATABASE_PASSWORD=hunter2000\nPATH=/usr/bin");
        assert!(!out.contains("hunter2000"));
        assert!(out.contains("DATABASE_PASSWORD"), "the key name stays readable");
        assert!(out.contains("/usr/bin"), "non-secrets are untouched");
    }

    #[test]
    fn common_token_shapes_are_caught() {
        for secret in [
            "sk-abcdefghijklmnopqrstuvwx",
            "sk-ant-abcdefghijklmnopqrstuvwx",
            "ghp_abcdefghijklmnopqrstuvwxyz012345",
            "xoxb-1234567890-abcdefghij",
            "AKIAIOSFODNN7EXAMPLE",
            "glpat-abcdefghijklmnopqrst",
        ] {
            let out = r().redact(&format!("token is {} ok", secret));
            assert!(!out.contains(secret), "leaked: {}", secret);
        }
    }

    #[test]
    fn urls_keep_their_host_but_lose_the_password() {
        // The host is diagnostically essential; the password is not.
        let out = r().redact("postgres://admin:s3cr3tpw@db.internal:5432/app");
        assert!(!out.contains("s3cr3tpw"));
        assert!(out.contains("db.internal"));
        assert!(out.contains("admin"));
    }

    #[test]
    fn authorization_headers_are_masked() {
        let out = r().redact("Authorization: Bearer abcdefghijklmnop");
        assert!(!out.contains("abcdefghijklmnop"));
        assert!(out.contains("Authorization"));
    }

    #[test]
    fn private_key_blocks_are_masked_whole() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nlines\n-----END RSA PRIVATE KEY-----";
        let out = r().redact(pem);
        assert!(!out.contains("MIIEow"));
        assert!(!out.contains("BEGIN RSA PRIVATE KEY"));
    }

    #[test]
    fn jwts_are_masked() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r";
        assert!(!r().redact(jwt).contains(jwt));
    }

    #[test]
    fn registered_literals_are_masked_even_when_they_look_ordinary() {
        // A secret whose value is a dictionary word has no recognisable shape;
        // this is why the secrets store registers what it hands out.
        let mut redactor = r();
        redactor.add_literal("correcthorse");
        let out = redactor.redact("the value is correcthorse today");
        assert!(!out.contains("correcthorse"));
        assert!(out.contains("today"));
    }

    #[test]
    fn very_short_literals_are_ignored() {
        // Masking "ab" everywhere would make output useless.
        let mut redactor = r();
        redactor.add_literal("ab");
        assert_eq!(redactor.literal_count(), 0);
        assert_eq!(redactor.redact("a table"), "a table");
    }

    #[test]
    fn overlapping_literals_mask_the_longest() {
        let mut redactor = r();
        redactor.add_literal("secretvalue");
        redactor.add_literal("secretvalue-extended");
        let out = redactor.redact("x secretvalue-extended y");
        assert!(!out.contains("secretvalue"));
        assert!(out.contains('x') && out.contains('y'));
    }

    #[test]
    fn ordinary_output_is_left_completely_alone() {
        let text = "CONTAINER ID   IMAGE     STATUS\nabc123   nginx   Up 3 hours";
        assert_eq!(r().redact(text), text);
    }

    #[test]
    fn a_disabled_redactor_passes_everything_through() {
        assert_eq!(
            Redactor::disabled().redact("API_KEY=supersecretvalue"),
            "API_KEY=supersecretvalue"
        );
    }

    #[test]
    fn empty_input_is_handled() {
        assert_eq!(r().redact(""), "");
    }

    #[test]
    fn detection_reports_whether_anything_would_change() {
        assert!(r().contains_secret("AWS_SECRET_ACCESS_KEY=abcd1234efgh"));
        assert!(!r().contains_secret("just some log output"));
    }

    #[test]
    fn multiple_secrets_on_one_line_are_all_masked() {
        let out = r().redact("A_TOKEN=aaaaaaaaaa B_SECRET=bbbbbbbbbb");
        assert!(!out.contains("aaaaaaaaaa"));
        assert!(!out.contains("bbbbbbbbbb"));
    }

    #[test]
    fn redaction_is_idempotent() {
        let once = r().redact("API_KEY=abcdefghij");
        assert_eq!(r().redact(&once), once);
    }
}
