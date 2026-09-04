//! Turning a `.seep` script into a plan.
//!
//! A script used to run through its own executor, with its own confirmation
//! prompt and its own idea of what was dangerous. That made `seep run deploy.seep`
//! the one way to get a shell command onto a machine without policy seeing it —
//! and a deploy script is exactly the thing an organization has change-management
//! rules about.
//!
//! Compiling to a [`Plan`] instead means a script gets everything a typed request
//! gets: independent blast-radius scoring, the policy engine, an approval a human
//! signs, a node that verifies that approval itself, and one line in the audit
//! chain per step. The script becomes a *proposal*, which is what it always
//! should have been.
//!
//! Not every construct survives the translation, and the ones that do not are
//! refused by name rather than quietly dropped. A script whose `on_error` block
//! was silently discarded would look like it ran correctly right up until
//! something went wrong.

use seep_core::types::BlastRadius;
use seep_proto::plan::{Plan, PlanStep, StepKind};
use seep_proto::selector::NodeSelector;
use std::collections::HashMap;

use crate::parser::{Script, Statement};

/// Why a script could not become a plan.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum CompileError {
    #[error("the script has no executable steps")]
    Empty,
    #[error(
        "`{construct}` cannot be expressed as an approvable plan yet.\n  \
         A plan is a fixed list of steps a human reads and authorizes; {why}.\n  \
         Rewrite this script without it, or drive the same work by asking SeeP directly."
    )]
    Unsupported { construct: &'static str, why: &'static str },
}

/// Compile a script into a plan awaiting authorization.
///
/// `target` is where the steps run. Variables set with `set` are substituted at
/// compile time, so the plan a human approves contains the literal commands that
/// will run rather than templates whose values could change afterwards.
pub fn compile(script: &Script, target: NodeSelector) -> Result<Plan, CompileError> {
    let mut variables: HashMap<String, String> = HashMap::new();
    let mut steps: Vec<PlanStep> = Vec::new();

    flatten(&script.statements, &mut variables, &mut steps, false)?;

    if steps.is_empty() {
        return Err(CompileError::Empty);
    }

    let goal = script
        .meta
        .name
        .clone()
        .unwrap_or_else(|| "run a SeeP script".to_string());

    let mut plan = Plan::new(goal, steps, target);
    plan.rationale = format!(
        "Compiled from a SeeP script{}. Every step is shown above exactly as it \
         will run; variables have already been substituted.",
        script
            .meta
            .version
            .as_ref()
            .map(|v| format!(" (version {})", v))
            .unwrap_or_default()
    );
    Ok(plan)
}

fn flatten(
    statements: &[Statement],
    variables: &mut HashMap<String, String>,
    steps: &mut Vec<PlanStep>,
    parallel: bool,
) -> Result<(), CompileError> {
    for statement in statements {
        match statement {
            // Compile-time only. Substituting here rather than at execution time
            // is what makes the approved text and the executed text the same.
            Statement::Set { var, value } => {
                let expanded = expand(value, variables);
                variables.insert(var.clone(), expanded);
            }
            Statement::Comment(_) => {}

            Statement::Shell(command) => {
                let command = expand(command, variables);
                steps.push(step(
                    steps.len(),
                    format!("run: {}", first_line(&command)),
                    StepKind::Shell { command, cwd: None, timeout_secs: None },
                    parallel,
                ));
            }
            Statement::Mcp { tool, args } => {
                let args: serde_json::Map<String, serde_json::Value> = args
                    .iter()
                    .map(|(key, value)| (key.clone(), parse_value(&expand(value, variables))))
                    .collect();
                steps.push(step(
                    steps.len(),
                    format!("call {}", tool),
                    StepKind::Tool { tool: tool.clone(), args: serde_json::Value::Object(args) },
                    parallel,
                ));
            }
            Statement::Think(prompt) => {
                let prompt = expand(prompt, variables);
                steps.push(step(
                    steps.len(),
                    "consider".to_string(),
                    StepKind::Think { prompt },
                    parallel,
                ));
            }
            Statement::Notify(message) => {
                let message = expand(message, variables);
                steps.push(step(
                    steps.len(),
                    "report".to_string(),
                    StepKind::Notify { message },
                    parallel,
                ));
            }
            Statement::Checkpoint(label) => {
                let label = expand(label, variables);
                steps.push(step(
                    steps.len(),
                    format!("checkpoint: {}", label),
                    StepKind::Checkpoint { label },
                    parallel,
                ));
            }
            // A mid-plan question. The operator already authorized the plan; this
            // is a second look before a particular step, which the runner honours
            // by pausing rather than by asking the script.
            Statement::Ask(question) => {
                let question = expand(question, variables);
                steps.push(step(
                    steps.len(),
                    "pause for confirmation".to_string(),
                    StepKind::Confirm { question },
                    parallel,
                ));
            }

            // Preview was a way to see the steps before running them. A plan is
            // that, for every script, so the block itself is just a grouping.
            Statement::Preview(body) => flatten(body, variables, steps, parallel)?,
            Statement::Parallel(body) => flatten(body, variables, steps, true)?,

            Statement::IfThink { .. } => {
                return Err(CompileError::Unsupported {
                    construct: "if_think",
                    why: "a branch decided by a model at execution time means the \
                          steps that actually run are not the steps that were approved",
                })
            }
            Statement::OnError(_) => {
                return Err(CompileError::Unsupported {
                    construct: "on_error",
                    why: "a plan has no failure edges, so the recovery steps would \
                          be approved but never shown as conditional",
                })
            }
            Statement::Abort(_) => {
                return Err(CompileError::Unsupported {
                    construct: "abort",
                    why: "stopping early is what a failed step already does, and an \
                          unconditional abort would make the rest of the plan a lie",
                })
            }
        }
    }
    Ok(())
}

fn step(index: usize, description: String, kind: StepKind, parallel: bool) -> PlanStep {
    PlanStep {
        id: (index + 1) as u32,
        description,
        kind,
        target: None,
        depends_on: Vec::new(),
        reversible: false,
        // Deliberately the floor, not a guess. The planner's independent scorer
        // raises this from the command itself, and a script author's opinion of
        // their own blast radius carries no more weight than a model's.
        blast_radius: BlastRadius::Low,
        estimated_secs: None,
        continue_on_error: false,
        parallel,
    }
}

/// Substitute `{{ VAR }}` references.
///
/// An unknown variable is left as written rather than replaced with an empty
/// string: `rm -rf {{ TARGET }}/` silently becoming `rm -rf /` is the exact
/// failure this must not have.
pub fn expand(text: &str, variables: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            // An unterminated placeholder is text, not a substitution.
            out.push_str(&rest[start..]);
            return out;
        };
        let name = after[..end].trim();
        match variables.get(name) {
            Some(value) => out.push_str(value),
            None => {
                out.push_str("{{");
                out.push_str(&after[..end]);
                out.push_str("}}");
            }
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

/// Read a script argument as JSON where it looks like JSON, and as a string
/// otherwise — so `no_cache=false` is a boolean and `path="."` is a string.
fn parse_value(raw: &str) -> serde_json::Value {
    let trimmed = raw.trim();
    if trimmed.starts_with(['{', '[']) || matches!(trimmed, "true" | "false" | "null") {
        if let Ok(value) = serde_json::from_str(trimmed) {
            return value;
        }
    }
    if let Ok(number) = trimmed.parse::<i64>() {
        return serde_json::json!(number);
    }
    serde_json::json!(trimmed.trim_matches('"'))
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or(text).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load_script;

    fn plan_from(source: &str) -> Result<Plan, CompileError> {
        let script = load_script(source).expect("the script should parse");
        compile(&script, NodeSelector::local())
    }

    #[test]
    fn a_linear_script_becomes_a_plan() {
        let plan = plan_from(
            r#"@name Backup
shell "tar -czf backup.tar.gz /data"
notify "backup done"
"#,
        )
        .unwrap();

        assert_eq!(plan.goal, "Backup");
        assert_eq!(plan.steps.len(), 2);
        assert!(matches!(plan.steps[0].kind, StepKind::Shell { .. }));
        assert!(matches!(plan.steps[1].kind, StepKind::Notify { .. }));
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn variables_are_substituted_before_a_human_sees_the_plan() {
        // The command shown in the approval must be the command that runs. A
        // template resolved afterwards is a plan whose meaning can change after
        // it was authorized.
        let plan = plan_from(
            r#"@name Deploy
set TAG = "v1.2.3"
shell "docker pull myapp:{{ TAG }}"
"#,
        )
        .unwrap();

        match &plan.steps[0].kind {
            StepKind::Shell { command, .. } => assert_eq!(command, "docker pull myapp:v1.2.3"),
            other => panic!("expected a shell step, got {:?}", other),
        }
    }

    #[test]
    fn an_unknown_variable_is_left_alone_rather_than_emptied() {
        // `rm -rf {{ TARGET }}/` becoming `rm -rf /` is the failure this exists
        // to prevent. Leaving the placeholder makes the mistake visible in the
        // approval instead of catastrophic at execution.
        let mut variables = HashMap::new();
        variables.insert("KNOWN".to_string(), "yes".to_string());

        assert_eq!(expand("a {{ KNOWN }} b", &variables), "a yes b");
        assert_eq!(expand("rm -rf {{ TARGET }}/", &variables), "rm -rf {{ TARGET }}/");
        assert_eq!(expand("{{ unterminated", &variables), "{{ unterminated");
        assert_eq!(expand("no placeholders", &variables), "no placeholders");
    }

    #[test]
    fn tool_arguments_keep_their_types() {
        let plan = plan_from(
            r#"@name Build
mcp docker_build path="." tag="app:latest" no_cache=false retries=3
"#,
        )
        .unwrap();

        match &plan.steps[0].kind {
            StepKind::Tool { tool, args } => {
                assert_eq!(tool, "docker_build");
                assert_eq!(args["path"], serde_json::json!("."));
                assert_eq!(args["no_cache"], serde_json::json!(false));
                assert_eq!(args["retries"], serde_json::json!(3));
            }
            other => panic!("expected a tool step, got {:?}", other),
        }
    }

    #[test]
    fn a_parallel_block_marks_its_steps() {
        let plan = plan_from(
            r#"@name Fan out
parallel:
    shell "echo one"
    shell "echo two"
"#,
        )
        .unwrap();

        assert_eq!(plan.steps.len(), 2);
        assert!(plan.steps.iter().all(|s| s.parallel));
    }

    #[test]
    fn control_flow_is_refused_by_name_rather_than_dropped() {
        // A script whose recovery block vanished would look like it ran fine
        // right up until something went wrong.
        let error = plan_from(
            r#"@name Risky
shell "true"
on_error:
    notify "it broke"
"#,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            CompileError::Unsupported { construct: "on_error", .. }
        ));
        assert!(error.to_string().contains("on_error"));
    }

    #[test]
    fn a_script_with_nothing_to_do_is_refused() {
        let error = plan_from("@name Nothing\n# just a comment\n").unwrap_err();
        assert_eq!(error, CompileError::Empty);
    }

    #[test]
    fn steps_are_scored_from_the_floor_up() {
        // The compiler asserts nothing about danger. Scoring is the planner's
        // job and it only ever raises, so a script cannot argue itself into the
        // tier that runs without asking anyone.
        let plan = plan_from("@name X\nshell \"rm -rf /var/lib/postgresql\"\n").unwrap();
        assert_eq!(plan.steps[0].blast_radius, BlastRadius::Low);
        assert!(!plan.steps[0].reversible);
    }

    #[test]
    fn an_ask_becomes_a_pause_not_a_skipped_step() {
        let plan = plan_from("@name X\nask \"are you sure?\"\nshell \"true\"\n").unwrap();
        assert!(matches!(plan.steps[0].kind, StepKind::Confirm { .. }));
        assert_eq!(plan.steps.len(), 2);
    }
}
