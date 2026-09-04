//! The command surface.
//!
//! Two shapes of command live here and the split is deliberate:
//!
//! * **Things you ask SeeP to do.** `seep "why is nginx restarting"`, `seep shell`,
//!   `seep run deploy.seep`. Natural language and scripts.
//! * **Things you ask SeeP about itself.** The fleet, approvals, runs, policy,
//!   tools, models, config. These are the ones an operator reaches for at 3am,
//!   and every one of them answers without needing an argument: `seep fleet`,
//!   `seep approvals`, `seep runs`, `seep models`.
//!
//! Every read-only command takes `--json`, so anything you can look at you can
//! also pipe into `jq`. A tool that can only be used by a human reading a
//! terminal is a tool that cannot be automated around.

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "seep",
    version,
    about = "SeeP — the auditable AI SRE",
    long_about = "SeeP is an always-on operations agent for your machines.\n\
                  \n\
                  It investigates with read-only tools, and when it wants to change\n\
                  something it produces a plan that goes through policy, then a human,\n\
                  then an executor that verifies the authorization independently.\n\
                  \n\
                  Start here:\n  \
                    seep init                 set up this machine\n  \
                    seep gateway              run the control plane\n  \
                    seep status               is everything healthy?\n  \
                    seep approvals            what is waiting on you",
    after_help = "Run `seep <command> --help` for detail on any command.",
)]
pub struct Cli {
    /// Natural language command or query
    pub input: Option<String>,

    /// Dry-run — show what would happen without executing
    #[arg(long, short = 'n', global = true)]
    pub dry_run: bool,

    /// Skip safety confirmations (use with caution)
    #[arg(long, global = true)]
    pub yes: bool,

    /// Suppress AI streaming, only show final result
    #[arg(long, global = true)]
    pub no_stream: bool,

    /// Emit JSON instead of formatted output, for scripting
    #[arg(long, global = true)]
    pub json: bool,

    /// Gateway to talk to, overriding the configured one
    #[arg(long, global = true, env = "SEEP_GATEWAY", value_name = "URL")]
    pub gateway_url: Option<String>,

    /// API token to authenticate with, overriding the configured one
    #[arg(long, global = true, env = "SEEP_TOKEN", value_name = "TOKEN", hide_env_values = true)]
    pub token: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    // ── Getting started ──────────────────────────────────────────────────
    /// Initialize SeeP in the current environment
    Init {
        /// Initialize in offline mode (no model download)
        #[arg(long)]
        offline: bool,
        /// Path to local model file
        #[arg(long)]
        model_path: Option<String>,
    },

    /// Launch the interactive REPL shell
    Shell,

    /// Check that this installation is healthy and can reach its models
    Doctor,

    /// Show version, protocol, and build information
    Version,

    /// Show the effective configuration and where everything lives
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },

    /// Print a shell completion script
    ///
    /// Add it to your shell, e.g.:
    ///   seep completions bash > /etc/bash_completion.d/seep
    ///   seep completions zsh  > ~/.zfunc/_seep
    Completions {
        /// bash, zsh, fish, powershell, or elvish
        shell: String,
    },

    // ── The control plane ────────────────────────────────────────────────
    /// Run the gateway: the always-on control plane
    Gateway {
        #[command(subcommand)]
        action: Option<GatewayAction>,
        /// Address to bind
        #[arg(long)]
        bind: Option<String>,
        /// Port to listen on
        #[arg(long)]
        port: Option<u16>,
        /// Verbose logging
        #[arg(long, short)]
        verbose: bool,
    },

    /// A one-screen summary of the whole system
    Status,

    // ── The fleet ────────────────────────────────────────────────────────
    /// List the machines in the fleet, or act on one
    Fleet {
        #[command(subcommand)]
        action: Option<FleetAction>,
    },

    /// Join this machine to a fleet, or run its agent
    Node {
        #[command(subcommand)]
        action: NodeAction,
    },

    // ── People ───────────────────────────────────────────────────────────
    /// Manage the people who can authorize actions
    Operator {
        #[command(subcommand)]
        action: OperatorAction,
    },

    // ── Authorization ────────────────────────────────────────────────────
    /// Show approval requests awaiting a decision
    Approvals,

    /// Show one approval request in full
    Show {
        /// Approval request id
        id: String,
    },

    /// Authorize a pending request
    Approve {
        /// Approval request id
        id: String,
        /// Record the decision as this operator
        #[arg(long)]
        as_operator: Option<String>,
        /// Typed confirmation phrase, for CRITICAL actions
        #[arg(long)]
        confirm: Option<String>,
        /// Sign with this machine's operator key rather than letting the gateway
        /// sign on your behalf. Produces `device-signed` assurance.
        #[arg(long)]
        sign: bool,
    },

    /// Refuse a pending request
    Deny {
        /// Approval request id
        id: String,
        #[arg(long)]
        as_operator: Option<String>,
    },

    /// Check that policy loads cleanly and show what it enforces
    Policy {
        /// Show every rule, not just a summary
        #[arg(long)]
        rules: bool,
    },

    // ── What happened ────────────────────────────────────────────────────
    /// List recent runs
    Runs {
        #[arg(long, default_value = "20")]
        limit: usize,
        /// Only runs that did not succeed
        #[arg(long)]
        failed: bool,
    },

    /// Show one run, step by step
    Run {
        /// A run id, or a path to a .seep script to execute
        target: String,
        /// Dry-run the script
        #[arg(long, short = 'n')]
        dry_run: bool,
        /// Preview all steps before executing
        #[arg(long)]
        preview: bool,
    },

    /// Undo what a run overwrote
    Rollback {
        /// The run to undo, or a snapshot id from the 1.x snapshot store
        id: Option<String>,
        /// Show what would be restored without restoring it
        #[arg(long)]
        preview: bool,
    },

    /// List available snapshots
    Rollbacks,

    /// Show incidents
    Incidents {
        /// Include resolved incidents
        #[arg(long)]
        all: bool,
    },

    /// Show or act on one incident
    Incident {
        #[command(subcommand)]
        action: IncidentAction,
    },

    /// View and manage the audit log
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },

    /// AI-powered history search
    History {
        /// Search query
        query: Option<String>,
    },

    // ── What SeeP knows ──────────────────────────────────────────────────
    /// List the tools SeeP can run, and how badly each could go wrong
    Tools {
        /// Only tools the agent may call while investigating
        #[arg(long)]
        read_only: bool,
        /// Filter by name or description
        #[arg(long)]
        filter: Option<String>,
    },

    /// Show which model handles which task, and whether each is answering
    Models,

    /// List installed skills
    Skills,

    /// List scheduled runbooks and when they next run
    Runbooks,

    /// Search what SeeP remembers about this infrastructure
    Memory {
        /// What to look for. Omit to list the most recent.
        query: Option<String>,
        #[arg(long, default_value = "20")]
        limit: usize,
    },

    /// Manage MCP servers
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },

    // ── Conveniences ─────────────────────────────────────────────────────
    /// Watch a condition and trigger actions
    Watch {
        /// Natural language condition to watch
        condition: String,
    },

    /// Git-aware AI operations
    Git {
        /// Natural language git operation
        operation: String,
    },

    /// Docker-aware AI operations
    Docker {
        /// Natural language docker operation
        operation: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Print the path to the config file
    Path,
    /// Show every directory SeeP reads or writes
    Paths,
    /// Open the config file in $EDITOR
    Edit,
    /// Write a config file with the current defaults, if none exists
    Init,
}

#[derive(Subcommand, Debug)]
pub enum GatewayAction {
    /// Issue a token that lets one machine join the fleet
    EnrollToken {
        /// Environment to stamp on the node: dev, staging, or prod
        #[arg(long, default_value = "unknown")]
        env: String,
        /// Labels to apply, as key=value
        #[arg(long)]
        label: Vec<String>,
        /// Tags to apply
        #[arg(long)]
        tag: Vec<String>,
        /// How long the token stays valid
        #[arg(long, default_value = "1")]
        hours: i64,
        /// How many machines may use it
        #[arg(long, default_value = "1")]
        uses: u32,
    },
    /// Show the gateway's status
    Status,
    /// Generate a strong API token and write it to the config
    Token {
        /// Replace an existing token rather than refusing
        #[arg(long)]
        rotate: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum FleetAction {
    /// List every enrolled machine
    List,
    /// Show one machine in detail
    Show { node: String },
    /// Stop sending work to a machine, without removing it
    Quarantine {
        node: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Let a quarantined machine take work again
    Release { node: String },
    /// Remove a machine from the fleet entirely
    Remove {
        node: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum NodeAction {
    /// Enrol this machine with a gateway
    Enroll {
        /// Gateway URL, e.g. https://ops.example.com
        gateway: String,
        /// Enrollment token from `seep gateway enroll-token`
        token: String,
    },
    /// Run the agent
    Run,
    /// Show this machine's enrollment
    Status,
}

#[derive(Subcommand, Debug)]
pub enum OperatorAction {
    /// Register a person who can interact with SeeP
    Add {
        /// Short name, e.g. alice
        name: String,
        /// observer, operator, or admin
        #[arg(long, default_value = "operator")]
        role: String,
    },
    /// List registered operators
    List,
    /// Bind a chat account to an operator
    Bind {
        /// Operator name
        name: String,
        /// telegram, slack, discord, or whatsapp
        channel: String,
        /// The platform's user id for that person
        account: String,
    },
    /// Remove a chat account binding
    Unbind { name: String, channel: String },
    /// Change what an operator is allowed to do
    Role {
        name: String,
        /// observer, operator, or admin
        role: String,
    },
    /// Stop an operator authorizing anything, without deleting them
    Disable { name: String },
    /// Undo `disable`
    Enable { name: String },
    /// Remove an operator entirely
    Remove {
        name: String,
        #[arg(long)]
        yes: bool,
    },
    /// Create a signing key on this machine for an operator
    ///
    /// The private half never leaves here, and the gateway never sees it. From
    /// then on `seep approve --sign` produces `device-signed` assurance: proof
    /// that this person authorized it, which a gateway could not have forged.
    Key {
        name: String,
        /// Replace an existing key rather than refusing
        #[arg(long)]
        rotate: bool,
    },
    /// Issue a personal API token, shown once
    Token { name: String },
    /// Revoke an operator's API token
    RevokeToken { name: String },
}

#[derive(Subcommand, Debug)]
pub enum IncidentAction {
    /// Show one incident and its timeline
    Show { id: String },
    /// Mark an incident as being looked at
    Ack {
        id: String,
        #[arg(long)]
        as_operator: Option<String>,
    },
    /// Close an incident
    Resolve {
        id: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Stop an incident notifying, without resolving it
    Suppress {
        id: String,
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ServerAction {
    /// Install an MCP server
    Install {
        /// Server name or path
        server: String,
    },
    /// List installed servers
    List,
    /// Enable a server
    Enable { name: String },
    /// Disable a server
    Disable { name: String },
    /// Remove a server
    Remove { name: String },
    /// Show server logs
    Logs { name: String },
    /// Update a server
    Update { name: String },
    /// Show full capability manifest
    Inspect { name: String },
    /// Show server status
    Status,
}

#[derive(Subcommand, Debug)]
pub enum AuditAction {
    /// List recent audit entries
    List {
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// Show a specific audit entry
    Show { event_id: String },
    /// Export audit log
    Export {
        #[arg(long)]
        from: Option<String>,
        #[arg(long, default_value = "json")]
        format: String,
    },
    /// Verify audit log cryptographic integrity
    Verify,
    /// Generate activity summary report
    Report {
        #[arg(long, default_value = "week")]
        period: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_tree_is_well_formed() {
        // clap validates argument conflicts, duplicate names, and bad defaults
        // here rather than at the moment an operator types the one command that
        // happens to hit the broken subtree.
        Cli::command().debug_assert();
    }

    #[test]
    fn a_bare_invocation_is_a_question_not_an_error() {
        let cli = Cli::parse_from(["seep", "why is nginx restarting"]);
        assert_eq!(cli.input.as_deref(), Some("why is nginx restarting"));
        assert!(cli.command.is_none());
    }

    #[test]
    fn the_commands_an_operator_reaches_for_need_no_arguments() {
        // At 3am, `seep approvals` should work. Requiring an argument on the
        // commands people use under pressure is how a tool stops being used.
        for command in [
            "approvals", "fleet", "runs", "incidents", "models", "tools", "skills",
            "runbooks", "policy", "status", "doctor", "config", "version", "memory",
        ] {
            assert!(
                Cli::try_parse_from(["seep", command]).is_ok(),
                "`seep {}` should work on its own",
                command
            );
        }
    }

    #[test]
    fn every_read_only_command_can_emit_json() {
        // Anything you can look at, you can pipe into jq.
        for command in ["approvals", "fleet", "runs", "models", "tools"] {
            let cli = Cli::try_parse_from(["seep", command, "--json"]).unwrap();
            assert!(cli.json, "`seep {} --json` should set the flag", command);
        }
    }

    #[test]
    fn the_gateway_can_be_pointed_elsewhere() {
        let cli = Cli::parse_from(["seep", "--gateway-url", "https://ops.example.com", "fleet"]);
        assert_eq!(cli.gateway_url.as_deref(), Some("https://ops.example.com"));
    }

    #[test]
    fn approving_can_ask_for_a_real_signature() {
        let cli = Cli::parse_from(["seep", "approve", "apr_1", "--sign"]);
        match cli.command {
            Some(Commands::Approve { id, sign, .. }) => {
                assert_eq!(id, "apr_1");
                assert!(sign);
            }
            other => panic!("expected an approve command, got {:?}", other),
        }
    }

    #[test]
    fn run_accepts_both_a_run_id_and_a_script() {
        // One verb, because from the operator's side they are the same question:
        // "show me this thing running".
        assert!(Cli::try_parse_from(["seep", "run", "run_abc123"]).is_ok());
        assert!(Cli::try_parse_from(["seep", "run", "deploy.seep", "--dry-run"]).is_ok());
    }

    #[test]
    fn destructive_fleet_actions_are_named_not_implied() {
        // `seep fleet` lists. Removing a machine takes saying so.
        assert!(Cli::try_parse_from(["seep", "fleet"]).is_ok());
        assert!(Cli::try_parse_from(["seep", "fleet", "remove", "web-01"]).is_ok());
    }
}
