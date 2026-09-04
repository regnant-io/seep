//! Talking to a gateway.
//!
//! Every operator command goes through this rather than reaching into the
//! gateway's database directly, so `seep approvals` behaves identically whether
//! the gateway is on this machine or in another datacentre — and so there is
//! exactly one place where authentication, error messages, and `--json` live.

use anyhow::Result;
use colored::Colorize;
use seep_core::Config;

/// Flags that apply to every command, resolved once at startup.
#[derive(Clone, Debug, Default)]
pub struct Ctx {
    /// Emit JSON rather than formatted output.
    pub json: bool,
    /// Gateway URL, when overridden on the command line or by `SEEP_GATEWAY`.
    pub gateway_url: Option<String>,
    /// API token, when overridden on the command line or by `SEEP_TOKEN`.
    pub token: Option<String>,
}

impl Ctx {
    /// Print a value as JSON, or hand it back for formatting.
    ///
    /// Returns `true` when it printed, so callers read as:
    /// `if ctx.emit(&value) { return Ok(()); }`
    pub fn emit<T: serde::Serialize>(&self, value: &T) -> bool {
        if !self.json {
            return false;
        }
        match serde_json::to_string_pretty(value) {
            Ok(text) => println!("{}", text),
            Err(e) => eprintln!("{{\"error\": \"{}\"}}", e),
        }
        true
    }

    /// Report an outcome that has no natural body — a delete, an acknowledgement.
    pub fn emit_ok(&self, message: &str, detail: serde_json::Value) -> bool {
        if !self.json {
            return false;
        }
        let mut body = serde_json::json!({ "ok": true, "message": message });
        if let serde_json::Value::Object(fields) = detail {
            for (key, value) in fields {
                body[key] = value;
            }
        }
        println!("{}", serde_json::to_string_pretty(&body).unwrap_or_default());
        true
    }
}

/// A thin API client that knows where the gateway is.
pub struct Client {
    base: String,
    token: String,
    http: reqwest::Client,
}

impl Client {
    pub fn new(config: &Config, ctx: &Ctx) -> Result<Self> {
        Ok(Self {
            base: ctx
                .gateway_url
                .clone()
                .unwrap_or_else(|| config.gateway.base_url())
                .trim_end_matches('/')
                .to_string(),
            token: ctx
                .token
                .clone()
                .unwrap_or_else(|| config.gateway.api_token.clone()),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        })
    }

    /// Load the config and build a client in one step, which is what nearly
    /// every command wants.
    pub fn connect(ctx: &Ctx) -> Result<Self> {
        Self::new(&Config::load()?, ctx)
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub async fn get(&self, path: &str) -> Result<serde_json::Value> {
        let mut request = self.http.get(format!("{}{}", self.base, path));
        if !self.token.is_empty() {
            request = request.bearer_auth(&self.token);
        }
        let response = request.send().await.map_err(|e| self.offline(e))?;
        self.decode(response).await
    }

    pub async fn post(&self, path: &str, body: serde_json::Value) -> Result<serde_json::Value> {
        let mut request = self.http.post(format!("{}{}", self.base, path)).json(&body);
        if !self.token.is_empty() {
            request = request.bearer_auth(&self.token);
        }
        let response = request.send().await.map_err(|e| self.offline(e))?;
        self.decode(response).await
    }

    pub async fn delete(&self, path: &str) -> Result<serde_json::Value> {
        let mut request = self.http.delete(format!("{}{}", self.base, path));
        if !self.token.is_empty() {
            request = request.bearer_auth(&self.token);
        }
        let response = request.send().await.map_err(|e| self.offline(e))?;
        self.decode(response).await
    }

    /// A GET whose array body is what the caller wants.
    pub async fn get_array(&self, path: &str) -> Result<Vec<serde_json::Value>> {
        Ok(self.get(path).await?.as_array().cloned().unwrap_or_default())
    }

    /// Whether a gateway is answering at all, for `seep status`.
    pub async fn is_up(&self) -> bool {
        self.http
            .get(format!("{}/healthz", self.base))
            .timeout(std::time::Duration::from_secs(3))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    fn offline(&self, e: reqwest::Error) -> anyhow::Error {
        // The transport error is three lines of nested `error trying to connect`
        // that say nothing an operator can act on. What they need is the
        // address and the command that fixes it.
        let detail = if e.is_connect() {
            "nothing is listening".to_string()
        } else if e.is_timeout() {
            "it did not answer in time".to_string()
        } else {
            e.to_string()
        };
        anyhow::anyhow!(
            "could not reach the gateway at {} — {}.\n  Start it with `seep gateway`, or point \
             elsewhere with --gateway-url.",
            self.base,
            detail
        )
    }

    async fn decode(&self, response: reqwest::Response) -> Result<serde_json::Value> {
        let status = response.status();
        let body: serde_json::Value = response.json().await.unwrap_or(serde_json::Value::Null);
        if status.is_success() {
            return Ok(body);
        }
        let detail = body["error"].as_str().unwrap_or("no detail");
        // The two failures worth explaining rather than reporting: a missing or
        // wrong credential, and a request the gateway understood but refused.
        match status.as_u16() {
            401 => anyhow::bail!(
                "the gateway rejected this credential ({}). Set gateway.api_token, pass \
                 --token, or issue yourself one with `seep operator token <name>`.",
                detail
            ),
            403 => anyhow::bail!("refused by the gateway: {}", detail),
            404 => anyhow::bail!("{}", detail),
            _ => anyhow::bail!("gateway returned {}: {}", status.as_u16(), detail),
        }
    }
}

// ── Shared formatting ─────────────────────────────────────────────────────

/// Colour a blast-radius label by how much it should worry you.
pub fn blast(label: &str) -> colored::ColoredString {
    match label {
        "CRIT" | "CRITICAL" => label.on_red().white().bold(),
        "HIGH" => label.red().bold(),
        "MED" | "MEDIUM" => label.yellow(),
        _ => label.green(),
    }
}

/// The same, padded to a column width.
///
/// Rust's `{:<8}` counts the ANSI escape bytes a colour adds, so padding a
/// coloured string leaves the column short by however long the escape happened
/// to be — and every row is short by a different amount. Padding the plain text
/// first and colouring the result keeps the table square.
pub fn blast_padded(label: &str, width: usize) -> colored::ColoredString {
    blast_like(label, &pad(label, width))
}

fn blast_like(label: &str, text: &str) -> colored::ColoredString {
    match label {
        "CRIT" | "CRITICAL" => text.on_red().white().bold(),
        "HIGH" => text.red().bold(),
        "MED" | "MEDIUM" => text.yellow(),
        _ => text.green(),
    }
}

/// Colour a node or run status.
pub fn status_word(status: &str) -> colored::ColoredString {
    status_like(status, status)
}

/// The same, padded to a column width. See [`blast_padded`].
pub fn status_padded(status: &str, width: usize) -> colored::ColoredString {
    status_like(status, &pad(status, width))
}

fn status_like(status: &str, text: &str) -> colored::ColoredString {
    match status {
        "online" | "succeeded" | "resolved" | "granted" => text.green(),
        "degraded" | "partially_succeeded" | "pending" | "triaging" => text.yellow(),
        "failed" | "rejected" | "denied" | "quarantined" => text.red(),
        _ => text.dimmed(),
    }
}

/// Pad to a column width, counting characters rather than bytes.
pub fn pad(text: &str, width: usize) -> String {
    let len = text.chars().count();
    if len >= width {
        return text.to_string();
    }
    format!("{}{}", text, " ".repeat(width - len))
}

/// "3m ago" for a past RFC-3339 timestamp.
pub fn relative(iso: &str) -> String {
    let Ok(then) = chrono::DateTime::parse_from_rfc3339(iso) else {
        return iso.to_string();
    };
    let seconds = (chrono::Utc::now() - then.with_timezone(&chrono::Utc)).num_seconds();
    if seconds < 60 {
        format!("{}s ago", seconds.max(0))
    } else if seconds < 3_600 {
        format!("{}m ago", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h ago", seconds / 3_600)
    } else {
        format!("{}d ago", seconds / 86_400)
    }
}

/// "in 12m" for a future RFC-3339 timestamp.
pub fn relative_future(iso: &str) -> String {
    let Ok(then) = chrono::DateTime::parse_from_rfc3339(iso) else {
        return iso.to_string();
    };
    let seconds = (then.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_seconds();
    if seconds <= 0 {
        "now".into()
    } else if seconds < 90 {
        format!("in {}s", seconds)
    } else if seconds < 7_200 {
        format!("in {}m", seconds / 60)
    } else {
        format!("in {}h", seconds / 3_600)
    }
}

/// A heading with a rule under it, used by every listing command.
pub fn heading(text: &str) {
    println!("\n  {}", text.bold());
}

/// What to say when a list is empty, and what to do about it.
///
/// An empty list is the most common thing a new user sees, so it says what to
/// run next rather than leaving them at a blank screen wondering if it broke.
pub fn empty(what: &str, next: &str) {
    println!("\n  {}\n", what.dimmed());
    if !next.is_empty() {
        println!("  {}  {}\n", "Try:".dimmed(), next.cyan());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_mode_prints_and_claims_the_output() {
        let ctx = Ctx { json: true, ..Default::default() };
        assert!(ctx.emit(&serde_json::json!({ "a": 1 })));

        let human = Ctx::default();
        assert!(!human.emit(&serde_json::json!({ "a": 1 })));
    }

    #[test]
    fn an_explicit_gateway_url_wins_over_the_config() {
        let config = Config::default();
        let ctx = Ctx {
            gateway_url: Some("https://ops.example.com/".into()),
            ..Default::default()
        };
        let client = Client::new(&config, &ctx).unwrap();
        // Trailing slash trimmed, so paths do not end up doubled.
        assert_eq!(client.base(), "https://ops.example.com");
    }

    #[test]
    fn the_configured_gateway_is_used_when_nothing_overrides_it() {
        let config = Config::default();
        let client = Client::new(&config, &Ctx::default()).unwrap();
        assert_eq!(client.base(), config.gateway.base_url());
    }

    #[test]
    fn relative_times_read_the_way_people_say_them() {
        // A second past the boundary, so the assertion is about the wording and
        // not about which side of a truncation the test happened to land on.
        let recent = (chrono::Utc::now() - chrono::Duration::seconds(5 * 60 + 1)).to_rfc3339();
        assert_eq!(relative(&recent), "5m ago");

        let soon = (chrono::Utc::now() + chrono::Duration::seconds(14 * 60 + 30)).to_rfc3339();
        assert_eq!(relative_future(&soon), "in 14m");
    }

    #[test]
    fn a_countdown_never_claims_more_time_than_remains() {
        // Rounding an expiry up would tell an operator they have a minute they
        // do not have. Truncating is the safe direction.
        let soon = (chrono::Utc::now() + chrono::Duration::seconds(14 * 60 + 59)).to_rfc3339();
        assert_eq!(relative_future(&soon), "in 14m");
    }

    #[test]
    fn an_unparseable_timestamp_is_shown_rather_than_hidden() {
        // Better to print something odd than to silently render "now".
        assert_eq!(relative("not a date"), "not a date");
        assert_eq!(relative_future("not a date"), "not a date");
    }

    #[test]
    fn a_coloured_column_is_still_the_width_it_claims() {
        // The bug this prevents: `{:<8}` counts escape bytes, so a coloured
        // status silently shrinks its column and every row below shifts left.
        colored::control::set_override(true);
        let plain = pad("online", 12);
        assert_eq!(plain.chars().count(), 12);

        let coloured = status_padded("online", 12).to_string();
        assert!(coloured.contains("online      "), "the padding must be inside the colour");
        colored::control::unset_override();
    }

    #[test]
    fn padding_never_truncates() {
        assert_eq!(pad("a-very-long-value", 4), "a-very-long-value");
    }

    #[test]
    fn an_expired_deadline_reads_as_now_not_as_negative_time() {
        let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        assert_eq!(relative_future(&past), "now");
    }
}
