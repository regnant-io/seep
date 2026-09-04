//! Conversation history with a context budget.
//!
//! An ops session is long-lived — an incident can run for hours — while a context
//! window is not. The transcript decides what to keep when those two facts
//! collide.
//!
//! The rule is that **structure is preserved over recency**. Naively dropping the
//! oldest messages breaks tool-call pairing (an assistant message with a
//! `tool_use` block whose result has been evicted makes several providers reject
//! the whole request), and it discards the original request, which is usually the
//! single most important message in the conversation. So the system prompt and
//! the first user turn are pinned, tool calls and their results are evicted
//! together, and what gets dropped from the middle is replaced by an explicit
//! note rather than vanishing silently.

use crate::llm::{ChatMessage, MessageRole};

/// A bounded conversation.
#[derive(Debug, Clone)]
pub struct Transcript {
    messages: Vec<ChatMessage>,
    /// Token budget for the whole history, leaving room for the reply.
    budget: usize,
    /// How many messages were dropped to fit.
    dropped: usize,
}

impl Transcript {
    pub fn new(budget: usize) -> Self {
        Self { messages: Vec::new(), budget: budget.max(2_000), dropped: 0 }
    }

    /// A transcript sized from a model's context window, reserving headroom for
    /// the response and for tool schemas.
    pub fn for_context_window(window: usize) -> Self {
        // Half the window for history is conservative, but running out of room
        // mid-incident is a far worse failure than being slightly frugal.
        Self::new(window / 2)
    }

    pub fn push(&mut self, message: ChatMessage) {
        self.messages.push(message);
        self.compact();
    }

    pub fn extend(&mut self, messages: impl IntoIterator<Item = ChatMessage>) {
        self.messages.extend(messages);
        self.compact();
    }

    pub fn messages(&self) -> &[ChatMessage] {
        &self.messages
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    pub fn dropped_count(&self) -> usize {
        self.dropped
    }

    pub fn estimated_tokens(&self) -> usize {
        self.messages.iter().map(|m| m.estimated_tokens()).sum()
    }

    pub fn clear(&mut self) {
        self.messages.clear();
        self.dropped = 0;
    }

    /// The last assistant message's text, if any.
    pub fn last_assistant_text(&self) -> Option<&str> {
        self.messages
            .iter()
            .rev()
            .find(|m| m.role == MessageRole::Assistant && !m.content.trim().is_empty())
            .map(|m| m.content.as_str())
    }

    /// Trim the history to fit the budget.
    fn compact(&mut self) {
        if self.estimated_tokens() <= self.budget {
            return;
        }

        // Everything before this index is pinned: the system prompt, and the
        // first user turn — the actual request, which must survive however long
        // the session runs.
        let pinned = self.pinned_prefix();
        if pinned >= self.messages.len() {
            return;
        }

        let mut removed = 0usize;
        while self.estimated_tokens() > self.budget && pinned < self.messages.len().saturating_sub(4)
        {
            let evicted = self.evict_one(pinned);
            if evicted == 0 {
                break;
            }
            removed += evicted;
        }

        if removed > 0 {
            self.dropped += removed;
            // Say what was dropped rather than letting the model silently
            // reason from a history with an invisible hole in it.
            self.messages.insert(
                pinned,
                ChatMessage::user(format!(
                    "[{} earlier message(s) omitted to stay within the context window. \
                     Ask for anything you need re-established rather than assuming.]",
                    self.dropped
                )),
            );
        }
    }

    /// Number of leading messages that must never be evicted.
    fn pinned_prefix(&self) -> usize {
        let mut index = 0;
        while index < self.messages.len() && self.messages[index].role == MessageRole::System {
            index += 1;
        }
        // Pin the first user turn as well.
        if index < self.messages.len() && self.messages[index].role == MessageRole::User {
            index += 1;
        }
        index
    }

    /// Remove the oldest evictable message, taking its tool results with it.
    ///
    /// Returns how many messages were removed. Evicting an assistant message
    /// without its tool results leaves orphaned `tool_result` blocks, which
    /// several providers reject outright — so they always go together.
    fn evict_one(&mut self, from: usize) -> usize {
        if from >= self.messages.len() {
            return 0;
        }
        // Skip over any note we previously inserted, so it does not accumulate.
        let index = from;
        if self.messages[index].content.starts_with("[") && self.messages[index].content.contains("omitted") {
            self.messages.remove(index);
            if index >= self.messages.len() {
                return 1;
            }
        }

        let has_calls = !self.messages[index].tool_calls.is_empty();
        let mut removed = 1;
        self.messages.remove(index);

        if has_calls {
            // Consume the matching tool results that follow.
            while index < self.messages.len() && self.messages[index].role == MessageRole::Tool {
                self.messages.remove(index);
                removed += 1;
            }
        } else {
            // A leading orphaned tool result would be invalid on its own.
            while index < self.messages.len() && self.messages[index].role == MessageRole::Tool {
                self.messages.remove(index);
                removed += 1;
            }
        }
        removed
    }

    /// Whether the history is structurally valid: every tool result answers a
    /// call that is still present.
    pub fn is_well_formed(&self) -> bool {
        let mut open_calls: Vec<&str> = Vec::new();
        for message in &self.messages {
            match message.role {
                MessageRole::Assistant => {
                    open_calls = message.tool_calls.iter().map(|c| c.id.as_str()).collect();
                }
                MessageRole::Tool => {
                    let Some(id) = message.tool_call_id.as_deref() else { return false };
                    if !open_calls.contains(&id) {
                        return false;
                    }
                }
                _ => open_calls.clear(),
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::ToolCall;

    fn tool_call(id: &str) -> ToolCall {
        ToolCall { id: id.into(), name: "sys_cpu".into(), arguments: serde_json::json!({}) }
    }

    fn big(role: &str, size: usize) -> ChatMessage {
        let content = "x".repeat(size);
        match role {
            "user" => ChatMessage::user(content),
            _ => ChatMessage::assistant(content),
        }
    }

    #[test]
    fn a_short_conversation_is_left_alone() {
        let mut transcript = Transcript::new(10_000);
        transcript.push(ChatMessage::system("you are seep"));
        transcript.push(ChatMessage::user("what is up"));
        transcript.push(ChatMessage::assistant("not much"));
        assert_eq!(transcript.len(), 3);
        assert_eq!(transcript.dropped_count(), 0);
    }

    #[test]
    fn the_system_prompt_and_first_request_survive_compaction() {
        // The original request is usually the most important message in a long
        // incident session; dropping it is how an agent forgets what it is doing.
        let mut transcript = Transcript::new(2_000);
        transcript.push(ChatMessage::system("SYSTEM PROMPT"));
        transcript.push(ChatMessage::user("THE ORIGINAL REQUEST"));
        for _ in 0..40 {
            transcript.push(big("assistant", 2_000));
            transcript.push(big("user", 2_000));
        }
        assert!(transcript.dropped_count() > 0);
        assert_eq!(transcript.messages()[0].content, "SYSTEM PROMPT");
        assert_eq!(transcript.messages()[1].content, "THE ORIGINAL REQUEST");
    }

    #[test]
    fn compaction_keeps_the_history_within_budget() {
        let mut transcript = Transcript::new(3_000);
        transcript.push(ChatMessage::system("s"));
        transcript.push(ChatMessage::user("first"));
        for _ in 0..50 {
            transcript.push(big("assistant", 4_000));
        }
        // Some overshoot is acceptable because the tail is never evicted, but it
        // must be bounded rather than unbounded growth.
        assert!(transcript.estimated_tokens() < 3_000 * 4);
    }

    #[test]
    fn dropped_messages_are_announced_rather_than_vanishing() {
        let mut transcript = Transcript::new(2_000);
        transcript.push(ChatMessage::system("s"));
        transcript.push(ChatMessage::user("first"));
        for _ in 0..40 {
            transcript.push(big("assistant", 2_000));
        }
        assert!(transcript
            .messages()
            .iter()
            .any(|m| m.content.contains("omitted")));
    }

    #[test]
    fn eviction_never_orphans_a_tool_result() {
        // Several providers reject a request containing a tool_result whose
        // matching tool_use has been evicted.
        let mut transcript = Transcript::new(2_000);
        transcript.push(ChatMessage::system("s"));
        transcript.push(ChatMessage::user("go"));
        for i in 0..30 {
            let id = format!("call_{}", i);
            transcript.push(ChatMessage::assistant_with_calls(
                "x".repeat(1_500),
                vec![tool_call(&id)],
            ));
            transcript.push(ChatMessage::tool_result(&id, "sys_cpu", "y".repeat(1_500)));
        }
        assert!(transcript.dropped_count() > 0);
        assert!(
            transcript.is_well_formed(),
            "compaction left an orphaned tool result"
        );
    }

    #[test]
    fn well_formedness_detects_an_orphaned_result() {
        let mut transcript = Transcript::new(100_000);
        transcript.push(ChatMessage::user("go"));
        transcript.push(ChatMessage::tool_result("call_missing", "sys_cpu", "result"));
        assert!(!transcript.is_well_formed());
    }

    #[test]
    fn the_omission_note_does_not_accumulate() {
        let mut transcript = Transcript::new(2_000);
        transcript.push(ChatMessage::system("s"));
        transcript.push(ChatMessage::user("first"));
        for _ in 0..60 {
            transcript.push(big("assistant", 2_000));
        }
        let notes = transcript
            .messages()
            .iter()
            .filter(|m| m.content.contains("omitted"))
            .count();
        assert_eq!(notes, 1, "one note, not one per compaction pass");
    }

    #[test]
    fn the_most_recent_exchange_is_always_retained() {
        let mut transcript = Transcript::new(2_000);
        transcript.push(ChatMessage::system("s"));
        transcript.push(ChatMessage::user("first"));
        for _ in 0..40 {
            transcript.push(big("assistant", 2_000));
        }
        transcript.push(ChatMessage::user("THE LATEST QUESTION"));
        assert_eq!(
            transcript.messages().last().unwrap().content,
            "THE LATEST QUESTION"
        );
    }

    #[test]
    fn the_last_assistant_reply_is_retrievable() {
        let mut transcript = Transcript::new(10_000);
        transcript.push(ChatMessage::assistant("first reply"));
        transcript.push(ChatMessage::user("and then?"));
        transcript.push(ChatMessage::assistant("second reply"));
        assert_eq!(transcript.last_assistant_text(), Some("second reply"));
    }

    #[test]
    fn a_context_window_produces_a_conservative_budget() {
        let transcript = Transcript::for_context_window(32_768);
        assert!(transcript.budget <= 16_384);
        assert!(transcript.budget >= 2_000);
    }

    #[test]
    fn a_tiny_budget_is_raised_to_something_workable() {
        // A one-token budget would evict everything and leave nothing to send.
        let transcript = Transcript::new(1);
        assert!(transcript.budget >= 2_000);
    }

    #[test]
    fn clearing_resets_the_dropped_counter() {
        let mut transcript = Transcript::new(2_000);
        transcript.push(ChatMessage::system("s"));
        transcript.push(ChatMessage::user("first"));
        for _ in 0..40 {
            transcript.push(big("assistant", 2_000));
        }
        transcript.clear();
        assert!(transcript.is_empty());
        assert_eq!(transcript.dropped_count(), 0);
    }
}
