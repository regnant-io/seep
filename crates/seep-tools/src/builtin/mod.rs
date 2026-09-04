//! The native tool library.
//!
//! These are the operations SeeP performs on real machines. Each one declares its
//! worst-case blast radius and whether it mutates anything, and those declarations
//! are what policy and autonomous triage rely on — so they are conservative by
//! construction. A tool that *might* change something is never marked read-only.

use crate::spec::Tool;
use std::sync::Arc;

pub mod container;
pub mod fs;
pub mod git;
pub mod http;
pub mod kube;
pub mod proc;
pub mod secrets;
pub mod service;
pub mod shell;
pub mod system;

/// Define a tool struct and its `Tool` implementation from a description of what
/// it is, delegating the work to a free async function.
///
/// The boilerplate this removes is not incidental: fifty hand-written impls is
/// fifty chances to mislabel a mutating tool as read-only, and one such mistake
/// would let unattended triage change production.
#[macro_export]
macro_rules! define_tool {
    (
        $struct:ident,
        name: $name:literal,
        description: $desc:literal,
        blast: $blast:literal,
        read_only: $read_only:expr,
        reversible: $reversible:expr,
        schema: $schema:expr,
        available: $available:expr,
        run: $func:path
    ) => {
        pub struct $struct;

        #[async_trait::async_trait]
        impl $crate::spec::Tool for $struct {
            fn name(&self) -> &str {
                $name
            }

            fn spec(&self) -> seep_proto::node::ToolSpec {
                seep_proto::node::ToolSpec::builtin(
                    $name,
                    $desc,
                    $schema,
                    $blast,
                    $read_only,
                    $reversible,
                )
            }

            fn is_available(&self) -> bool {
                $available
            }

            async fn execute(
                &self,
                args: &serde_json::Value,
                ctx: &$crate::spec::ExecContext,
            ) -> Result<$crate::spec::ToolOutcome, $crate::spec::ToolError> {
                $func(args, ctx).await
            }
        }
    };
}

/// Every native tool, in a stable order.
pub fn all() -> Vec<Arc<dyn Tool>> {
    let mut tools: Vec<Arc<dyn Tool>> = Vec::new();
    tools.extend(fs::tools());
    tools.extend(shell::tools());
    tools.extend(system::tools());
    tools.extend(git::tools());
    tools.extend(container::tools());
    tools.extend(service::tools());
    tools.extend(http::tools());
    tools.extend(kube::tools());
    tools.extend(secrets::tools());
    tools
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_tool_name_is_unique() {
        // A duplicate would silently shadow another tool in the registry map.
        let mut seen = HashSet::new();
        for tool in all() {
            assert!(
                seen.insert(tool.name().to_string()),
                "duplicate tool name: {}",
                tool.name()
            );
        }
    }

    #[test]
    fn every_tool_declares_a_recognised_blast_radius() {
        for tool in all() {
            let spec = tool.spec();
            assert!(
                matches!(spec.max_blast_radius.as_str(), "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"),
                "{} declared blast radius {:?}",
                spec.name,
                spec.max_blast_radius
            );
        }
    }

    #[test]
    fn read_only_tools_never_declare_a_mutating_blast_radius() {
        // The invariant unattended triage depends on: if a tool claims it only
        // observes, it must not also claim it can make high-impact changes.
        for tool in all() {
            let spec = tool.spec();
            if spec.read_only {
                assert_eq!(
                    spec.max_blast_radius, "LOW",
                    "{} is marked read-only but declares {}",
                    spec.name, spec.max_blast_radius
                );
            }
        }
    }

    #[test]
    fn every_tool_has_a_description_and_an_object_schema() {
        for tool in all() {
            let spec = tool.spec();
            assert!(!spec.description.trim().is_empty(), "{} has no description", spec.name);
            assert_eq!(
                spec.input_schema["type"], "object",
                "{} schema must be an object",
                spec.name
            );
        }
    }

    #[test]
    fn tool_names_are_namespaced_by_prefix() {
        // The prefix is what capability detection and read-only filtering key on.
        for tool in all() {
            assert!(
                tool.name().contains('_'),
                "{} should be named <area>_<verb>",
                tool.name()
            );
        }
    }

    #[test]
    fn the_library_is_not_trivially_small() {
        assert!(all().len() >= 40, "expected a full tool library, got {}", all().len());
    }
}
