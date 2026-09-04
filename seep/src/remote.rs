//! Asking a running gateway a question, from a terminal.
//!
//! `seep "why is nginx restarting"` builds SeeP in-process when nothing else is
//! using the data directory. When a gateway *is* running — which on any real
//! installation is most of the time — that directory is already claimed, and the
//! embedded path used to fail with a lock error.
//!
//! Failing there would be the wrong answer twice over: the machine plainly can
//! answer the question, and making the same command mean different things
//! depending on whether a background service happens to be up is exactly the
//! kind of inconsistency that teaches people not to trust a tool.
//!
//! So this is a terminal client for the gateway. The question goes over the API,
//! the reasoning streams back over the event socket, and an approval card is
//! answered from the same terminal — the gateway does not care that the operator
//! is at a shell rather than in Slack.

use anyhow::Result;
use colored::Colorize;
use futures_util::{SinkExt, StreamExt};
use std::io::{IsTerminal, Write};
use tokio_tungstenite::tungstenite::Message;

use crate::client::{Client, Ctx};

/// A conversation with a running gateway.
///
/// Held open across questions so the agent remembers the last one. A socket per
/// question would give each turn a fresh session id, which in a shell means
/// "what about the other one?" answers as though nothing had been said.
pub struct RemoteSession {
    socket: Socket,
    session: String,
    operator: String,
    assume_yes: bool,
}

impl RemoteSession {
    pub async fn open(ctx: &Ctx, operator: &str, assume_yes: bool) -> Result<Self> {
        let config = seep_core::Config::load()?;
        let client = Client::new(&config, ctx)?;
        let mut socket = connect(&client, ctx, &config).await?;
        let session = handshake(&mut socket).await?;
        Ok(Self {
            socket,
            session,
            operator: operator.to_string(),
            assume_yes,
        })
    }

    /// Ask one question and print what comes back.
    pub async fn ask(&mut self, input: &str) -> Result<()> {
        // Asked over the socket rather than the REST endpoint so the answer
        // arrives on the connection that is already listening for it. Posting to
        // `/api/v1/chat` would work, but leaves a race between the reply
        // starting and the subscription being established.
        let ask = serde_json::json!({ "operator": self.operator, "text": input });
        self.socket.send(Message::Text(ask.to_string())).await?;
        stream_until_idle(&mut self.socket, &self.session, &self.operator, self.assume_yes).await
    }
}

/// Ask a running gateway one question.
pub async fn ask(ctx: &Ctx, operator: &str, input: &str, assume_yes: bool) -> Result<()> {
    RemoteSession::open(ctx, operator, assume_yes).await?.ask(input).await
}

async fn connect(
    client: &Client,
    ctx: &Ctx,
    config: &seep_core::Config,
) -> Result<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>
{
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let url = format!(
        "{}/ws",
        client.base().replacen("https://", "wss://", 1).replacen("http://", "ws://", 1)
    );
    let mut request = url.into_client_request()?;

    let token = ctx.token.clone().unwrap_or_else(|| config.gateway.api_token.clone());
    if !token.is_empty() {
        request
            .headers_mut()
            .insert("authorization", format!("Bearer {}", token).parse()?);
    }

    let (socket, _) = tokio_tungstenite::connect_async(request).await.map_err(|e| {
        anyhow::anyhow!(
            "could not open an event stream to {} — {}.\n  \
             The gateway is answering HTTP, so this is usually a proxy that does not \
             forward WebSocket upgrades.",
            client.base(),
            e
        )
    })?;
    Ok(socket)
}

type Socket = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

/// Read the gateway's hello and return the session id it assigned.
async fn handshake(socket: &mut Socket) -> Result<String> {
    let deadline = tokio::time::Duration::from_secs(10);
    let Ok(Some(Ok(Message::Text(text)))) = tokio::time::timeout(deadline, socket.next()).await
    else {
        anyhow::bail!("the gateway did not greet the connection");
    };
    let value: serde_json::Value = serde_json::from_str(&text)?;
    Ok(value["session"].as_str().unwrap_or_default().to_string())
}

/// Print events until the turn finishes and nothing is left waiting.
async fn stream_until_idle(
    socket: &mut Socket,
    session: &str,
    operator: &str,
    assume_yes: bool,
) -> Result<()> {
    // Once the turn completes, a plan may still be on its way to policy and an
    // approval card behind it. Rather than exiting on `SessionComplete`, a short
    // grace period lets whatever follows arrive — and any approval extends it,
    // because the run's own output is the thing worth waiting for.
    let grace = tokio::time::Duration::from_secs(5);
    let mut idle_after: Option<tokio::time::Instant> = None;
    let mut streaming_text = false;

    loop {
        let wait = match idle_after {
            Some(at) => at.saturating_duration_since(tokio::time::Instant::now()),
            None => tokio::time::Duration::from_secs(600),
        };
        if wait.is_zero() {
            break;
        }

        let frame = match tokio::time::timeout(wait, socket.next()).await {
            Err(_) => break,
            Ok(None) => break,
            Ok(Some(Err(e))) => anyhow::bail!("the event stream ended: {}", e),
            Ok(Some(Ok(Message::Text(text)))) => text,
            Ok(Some(Ok(_))) => continue,
        };

        let Ok(value) = serde_json::from_str::<serde_json::Value>(&frame) else {
            continue;
        };

        match value["type"].as_str().unwrap_or_default() {
            // `EventEnvelope` flattens its event, so the kind and the payload
            // are both on the envelope itself rather than nested under it.
            "event" => {
                let event = &value["envelope"];
                // Other conversations share this socket. Only ours is ours to
                // print — a gateway serving Slack and a terminal at once would
                // otherwise interleave two answers.
                if let Some(id) = event["session_id"].as_str() {
                    if !session.is_empty() && !id.is_empty() && id != session {
                        continue;
                    }
                }
                if render_event(event, &mut streaming_text) {
                    idle_after = Some(tokio::time::Instant::now() + grace);
                }
            }
            "message" => {
                let message = &value["message"];
                if streaming_text {
                    println!();
                    streaming_text = false;
                }
                render_message(message);
                if let Some(action) = approval_action(message) {
                    answer(socket, operator, &action, assume_yes).await?;
                }
                idle_after = Some(tokio::time::Instant::now() + grace);
            }
            _ => {}
        }
    }

    if streaming_text {
        println!();
    }
    Ok(())
}

/// Print one event. Returns whether the turn looks finished.
fn render_event(event: &serde_json::Value, streaming_text: &mut bool) -> bool {
    match event["event"].as_str().unwrap_or_default() {
        "session_delta" => {
            print!("{}", event["text"].as_str().unwrap_or_default());
            let _ = std::io::stdout().flush();
            *streaming_text = true;
            false
        }
        "session_tool_call" => {
            if *streaming_text {
                println!();
                *streaming_text = false;
            }
            // Shown because an agent that goes quiet for thirty seconds while it
            // reads a log looks broken.
            println!("  {} {}", "·".dimmed(), event["tool"].as_str().unwrap_or("").dimmed());
            false
        }
        "session_error" => {
            eprintln!("\n  {} {}", "✗".red(), event["error"].as_str().unwrap_or(""));
            true
        }
        "session_complete" => {
            if *streaming_text {
                println!();
                *streaming_text = false;
            }
            true
        }
        _ => false,
    }
}

fn render_message(message: &serde_json::Value) {
    if let Some(title) = message["title"].as_str() {
        println!("\n  {}", title.bold());
    }
    for line in message["text"].as_str().unwrap_or("").lines() {
        println!("  {}", line);
    }
    if let Some(code) = message["code_block"].as_str() {
        println!();
        for line in code.lines() {
            println!("    {}", line);
        }
    }
}

/// The approve action on a card, if it carries one.
fn approval_action(message: &serde_json::Value) -> Option<String> {
    message["actions"]
        .as_array()?
        .iter()
        .filter_map(|a| a["id"].as_str())
        .find(|id| id.starts_with("approve:"))
        .map(String::from)
}

/// Ask, and send the decision back over the same socket.
async fn answer(
    socket: &mut Socket,
    operator: &str,
    action: &str,
    assume_yes: bool,
) -> Result<()> {
    let id = action.trim_start_matches("approve:");

    if assume_yes {
        println!("\n  Approving automatically (--yes).\n");
    } else if !std::io::stdin().is_terminal() {
        println!(
            "\n  This needs a decision and nothing is attached to answer.\n  \
             It is waiting as {}. Decide with `seep approve {}`.\n",
            id, id
        );
        return Ok(());
    } else {
        print!("  Approve? [y/N] ");
        let _ = std::io::stdout().flush();
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            let deny = serde_json::json!({ "operator": operator, "action": format!("deny:{}", id) });
            socket.send(Message::Text(deny.to_string())).await?;
            println!();
            return Ok(());
        }
        println!();
    }

    let approve = serde_json::json!({ "operator": operator, "action": action });
    socket.send(Message::Text(approve.to_string())).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_approval_card_is_recognised_by_its_action() {
        let card = serde_json::json!({
            "actions": [
                { "id": "approve:apr_1", "label": "Approve" },
                { "id": "deny:apr_1", "label": "Deny" }
            ]
        });
        assert_eq!(approval_action(&card).as_deref(), Some("approve:apr_1"));
    }

    #[test]
    fn a_plain_message_carries_no_decision() {
        assert!(approval_action(&serde_json::json!({ "text": "all quiet" })).is_none());
        assert!(approval_action(&serde_json::json!({ "actions": [] })).is_none());
    }

    #[test]
    fn a_critical_card_offers_no_approve_button() {
        // Deliberate: a CRITICAL action must not be one keypress away, so the
        // card carries only a deny action and the phrase is typed via
        // `seep approve --confirm`.
        let card = serde_json::json!({
            "actions": [{ "id": "deny:apr_1", "label": "Deny" }]
        });
        assert!(approval_action(&card).is_none());
    }

    #[test]
    fn a_completed_turn_is_recognised() {
        // The discriminant is `event`, matching how `EventEnvelope` flattens
        // its `Event`. Reading `type` here silently matched nothing, so the
        // client waited out its grace period on every question.
        let mut streaming = false;
        assert!(render_event(
            &serde_json::json!({ "event": "session_complete", "text": "" }),
            &mut streaming
        ));
        assert!(!render_event(
            &serde_json::json!({ "event": "session_delta", "text": "" }),
            &mut streaming
        ));
    }

    #[test]
    fn the_wire_shape_matches_what_the_gateway_sends() {
        // Pinned against the real type rather than a hand-written literal: the
        // two drifting apart is invisible until a user sees a silent terminal.
        let envelope = seep_proto::event::EventEnvelope::new(
            1,
            seep_proto::event::Event::SessionDelta {
                session_id: seep_proto::ids::SessionId::parse("abc"),
                text: "hello".into(),
            },
        );
        let value = serde_json::to_value(&envelope).unwrap();
        assert_eq!(value["event"], "session_delta");
        assert_eq!(value["text"], "hello");
        assert!(value["session_id"].is_string());

        let mut streaming = false;
        assert!(!render_event(&value, &mut streaming));
        assert!(streaming, "a delta should leave the line open for the next one");
    }
}
