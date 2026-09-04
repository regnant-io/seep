//! Turning a message into what each platform expects.
//!
//! The approval card is the most important thing SeeP renders. Somebody is going
//! to read it on a phone, at night, and decide whether to let a machine change
//! production. Everything here serves that: what is being done, where, how bad it
//! could be, and how long they have to decide — above the fold, in that order.

use seep_proto::channel::{ChannelKind, OutboundMessage};

/// Severity accents, mapped to each platform's colour vocabulary.
pub fn severity_colour(severity: Option<&str>) -> &'static str {
    match severity.unwrap_or("info") {
        "danger" | "critical" => "#d93025",
        "warning" => "#f5a623",
        "success" => "#2e7d32",
        _ => "#4a6fa5",
    }
}

/// A leading glyph, for platforms with no colour concept.
pub fn severity_icon(severity: Option<&str>) -> &'static str {
    match severity.unwrap_or("info") {
        "danger" | "critical" => "🔴",
        "warning" => "🟡",
        "success" => "🟢",
        _ => "🔵",
    }
}

/// Render a message as plain text, used by platforms without rich formatting and
/// as the fallback everywhere else.
pub fn to_plain_text(message: &OutboundMessage) -> String {
    let mut out = String::new();
    if let Some(title) = &message.title {
        out.push_str(&format!("{} {}\n\n", severity_icon(message.severity.as_deref()), title));
    }
    out.push_str(&message.text);
    if let Some(code) = &message.code_block {
        if !code.trim().is_empty() {
            out.push_str("\n\n");
            out.push_str(code.trim_end());
        }
    }
    out
}

/// Render as Markdown, for platforms that accept it.
pub fn to_markdown(message: &OutboundMessage) -> String {
    let mut out = String::new();
    if let Some(title) = &message.title {
        out.push_str(&format!(
            "{} *{}*\n\n",
            severity_icon(message.severity.as_deref()),
            escape_markdown(title)
        ));
    }
    out.push_str(&message.text);
    if let Some(code) = &message.code_block {
        if !code.trim().is_empty() {
            out.push_str(&format!("\n\n```\n{}\n```", code.trim_end()));
        }
    }
    out
}

/// Escape the characters that would otherwise break Markdown emphasis.
///
/// Deliberately minimal: escaping aggressively makes log excerpts unreadable,
/// which defeats the purpose of showing them.
pub fn escape_markdown(text: &str) -> String {
    text.replace('*', "\\*").replace('_', "\\_").replace('`', "\\`")
}

/// Fence a block of tool output so a platform does not try to format it.
///
/// Any fence sequence inside the content is neutralised — otherwise a log line
/// containing three backticks closes the block early and the rest of the output
/// renders as markup, which at best looks broken and at worst hides a line the
/// operator needed to read.
pub fn fence(content: &str, limit: usize) -> String {
    let cleaned = content.replace("```", "'''");
    let trimmed = if cleaned.chars().count() > limit {
        let kept: String = cleaned.chars().take(limit.saturating_sub(20)).collect();
        format!("{}\n… truncated …", kept)
    } else {
        cleaned
    };
    format!("```\n{}\n```", trimmed.trim_end())
}

/// Split a message so each piece fits the platform's limit.
///
/// Actions ride on the final piece: a button on part two of four is a button the
/// operator scrolls past.
pub fn split_for(kind: ChannelKind, message: &OutboundMessage) -> Vec<OutboundMessage> {
    let body = to_markdown(message);
    let limit = kind.max_message_chars().saturating_sub(64);
    let chunks = OutboundMessage::split_text(&body, limit);

    if chunks.len() <= 1 {
        return vec![message.clone()];
    }

    let last = chunks.len() - 1;
    chunks
        .into_iter()
        .enumerate()
        .map(|(index, text)| OutboundMessage {
            text,
            title: None,
            code_block: None,
            actions: if index == last { message.actions.clone() } else { Vec::new() },
            severity: message.severity.clone(),
            attachments: Vec::new(),
            session_id: message.session_id.clone(),
            // Only the last piece may notify, so a four-part answer buzzes once.
            silent: index != last || message.silent,
        })
        .collect()
}

/// A compact, scannable time-remaining string for an approval card.
pub fn time_remaining(seconds: i64) -> String {
    if seconds <= 0 {
        return "expired".into();
    }
    if seconds < 90 {
        return format!("{}s", seconds);
    }
    let minutes = seconds / 60;
    if minutes < 90 {
        return format!("{}m", minutes);
    }
    format!("{}h{}m", minutes / 60, minutes % 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seep_proto::channel::PresentedAction;

    fn message() -> OutboundMessage {
        OutboundMessage {
            text: "the body".into(),
            title: Some("A Title".into()),
            code_block: Some("some output".into()),
            actions: vec![PresentedAction::primary("approve", "Approve")],
            severity: Some("warning".into()),
            attachments: vec![],
            session_id: None,
            silent: false,
        }
    }

    #[test]
    fn plain_text_includes_title_body_and_output() {
        let rendered = to_plain_text(&message());
        assert!(rendered.contains("A Title"));
        assert!(rendered.contains("the body"));
        assert!(rendered.contains("some output"));
        assert!(rendered.contains("🟡"));
    }

    #[test]
    fn markdown_fences_the_code_block() {
        let rendered = to_markdown(&message());
        assert!(rendered.contains("```"));
        assert!(rendered.contains("some output"));
    }

    #[test]
    fn an_empty_code_block_is_omitted_rather_than_rendered_empty() {
        let message = OutboundMessage { code_block: Some("   ".into()), ..message() };
        assert!(!to_markdown(&message).contains("```"));
    }

    #[test]
    fn fencing_neutralises_embedded_fences() {
        // A log line containing ``` would otherwise close the block early and
        // render the rest of the output as markup.
        let fenced = fence("before ``` after", 1000);
        assert_eq!(fenced.matches("```").count(), 2);
        assert!(fenced.contains("'''"));
    }

    #[test]
    fn fencing_truncates_long_content() {
        let fenced = fence(&"x".repeat(5_000), 200);
        assert!(fenced.chars().count() < 300);
        assert!(fenced.contains("truncated"));
    }

    #[test]
    fn long_messages_split_within_the_platform_limit() {
        let long = OutboundMessage {
            text: (0..500).map(|i| format!("line {}\n", i)).collect(),
            title: None,
            code_block: None,
            ..message()
        };
        let parts = split_for(ChannelKind::Discord, &long);
        assert!(parts.len() > 1);
        for part in &parts {
            assert!(
                to_markdown(part).chars().count() <= ChannelKind::Discord.max_message_chars(),
                "a part exceeded the platform limit"
            );
        }
    }

    #[test]
    fn actions_ride_on_the_final_part_only() {
        // A button on part two of four is a button nobody sees.
        let long = OutboundMessage {
            text: (0..500).map(|i| format!("line {}\n", i)).collect(),
            title: None,
            code_block: None,
            ..message()
        };
        let parts = split_for(ChannelKind::Discord, &long);
        assert!(parts.last().unwrap().actions.len() == 1);
        assert!(parts[..parts.len() - 1].iter().all(|p| p.actions.is_empty()));
    }

    #[test]
    fn only_the_final_part_notifies() {
        let long = OutboundMessage {
            text: (0..500).map(|i| format!("line {}\n", i)).collect(),
            title: None,
            code_block: None,
            ..message()
        };
        let parts = split_for(ChannelKind::Discord, &long);
        assert!(parts[..parts.len() - 1].iter().all(|p| p.silent));
        assert!(!parts.last().unwrap().silent);
    }

    #[test]
    fn a_short_message_is_not_split() {
        let parts = split_for(ChannelKind::Telegram, &message());
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].actions.len(), 1);
    }

    #[test]
    fn markdown_escaping_is_minimal_enough_to_stay_readable() {
        // Aggressive escaping makes log excerpts unreadable.
        let escaped = escape_markdown("error in file_name.rs at *line* 40 (code 500)");
        assert!(escaped.contains("(code 500)"));
        assert!(escaped.contains("\\_"));
        assert!(escaped.contains("\\*"));
    }

    #[test]
    fn time_remaining_reads_naturally_at_every_scale() {
        assert_eq!(time_remaining(-5), "expired");
        assert_eq!(time_remaining(0), "expired");
        assert_eq!(time_remaining(45), "45s");
        assert_eq!(time_remaining(600), "10m");
        assert_eq!(time_remaining(7_200), "2h0m");
        assert_eq!(time_remaining(5_400), "1h30m");
        assert_eq!(time_remaining(5_340), "89m");
    }

    #[test]
    fn severity_maps_to_distinct_colours_and_icons() {
        assert_ne!(severity_colour(Some("danger")), severity_colour(Some("success")));
        assert_ne!(severity_icon(Some("danger")), severity_icon(Some("info")));
        assert_eq!(severity_icon(None), severity_icon(Some("info")));
    }
}
