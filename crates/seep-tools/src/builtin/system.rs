//! Host observability.
//!
//! These are the tools the agent reaches for first during triage: what is the
//! machine doing, what is consuming it, and what changed. They are all read-only
//! and cheap, which is what makes unattended investigation viable — the agent can
//! look at everything before it proposes anything.

use crate::define_tool;
use crate::spec::{
    arg_str_opt, arg_u64, prop, schema, ExecContext, Tool, ToolError, ToolOutcome,
};
use std::sync::Arc;
use sysinfo::{Disks, Networks, System};

use super::proc;

pub fn tools() -> Vec<Arc<dyn Tool>> {
    vec![
        Arc::new(SysInfo),
        Arc::new(SysCpu),
        Arc::new(SysMemory),
        Arc::new(SysDisk),
        Arc::new(SysProcesses),
        Arc::new(SysPorts),
        Arc::new(SysNetwork),
        Arc::new(SysUptime),
        Arc::new(SysHealth),
    ]
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{:.1} {}", value, UNITS[unit])
}

fn bar(percent: f32) -> String {
    let filled = ((percent / 5.0).round() as usize).min(20);
    format!("[{}{}] {:.1}%", "#".repeat(filled), "·".repeat(20 - filled), percent)
}

/// Sample CPU usage properly.
///
/// `sysinfo` computes CPU as a delta between two refreshes, so a single refresh
/// reports zero — or worse, a meaningless number. Sampling twice with the
/// library's minimum interval is the difference between a real reading and a
/// confidently wrong one that the agent will then reason from.
fn sample_cpu(system: &mut System) {
    system.refresh_cpu_usage();
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    system.refresh_cpu_usage();
}

// ── sys_info ──────────────────────────────────────────────────────────────

async fn sys_info(_args: &serde_json::Value, _ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let mut system = System::new_all();
    system.refresh_all();

    let mut out = String::new();
    out.push_str(&format!("Host:      {}\n", System::host_name().unwrap_or_else(|| "unknown".into())));
    out.push_str(&format!(
        "OS:        {} {}\n",
        System::name().unwrap_or_else(|| "unknown".into()),
        System::os_version().unwrap_or_default()
    ));
    out.push_str(&format!("Kernel:    {}\n", System::kernel_version().unwrap_or_default()));
    out.push_str(&format!("Arch:      {}\n", std::env::consts::ARCH));
    out.push_str(&format!("CPUs:      {}\n", system.cpus().len()));
    out.push_str(&format!("Memory:    {}\n", human_bytes(system.total_memory())));
    out.push_str(&format!("Uptime:    {}\n", format_duration(System::uptime())));
    out.push_str(&format!("Processes: {}\n", system.processes().len()));

    Ok(ToolOutcome::ok(out).with_data(serde_json::json!({
        "hostname": System::host_name(),
        "os": System::name(),
        "os_version": System::os_version(),
        "kernel": System::kernel_version(),
        "arch": std::env::consts::ARCH,
        "cpu_count": system.cpus().len(),
        "total_memory_bytes": system.total_memory(),
        "uptime_secs": System::uptime(),
    })))
}

fn format_duration(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if days > 0 {
        format!("{}d {}h {}m", days, hours, minutes)
    } else if hours > 0 {
        format!("{}h {}m", hours, minutes)
    } else {
        format!("{}m", minutes)
    }
}

define_tool!(
    SysInfo,
    name: "sys_info",
    description: "Summarise this host: OS, kernel, architecture, CPU count, total memory, uptime.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(serde_json::json!({}), &[]),
    available: true,
    run: sys_info
);

// ── sys_cpu ───────────────────────────────────────────────────────────────

async fn sys_cpu(_args: &serde_json::Value, _ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let mut system = System::new();
    sample_cpu(&mut system);

    let per_core: Vec<f32> = system.cpus().iter().map(|c| c.cpu_usage()).collect();
    let average = if per_core.is_empty() {
        0.0
    } else {
        per_core.iter().sum::<f32>() / per_core.len() as f32
    };

    let mut out = format!("CPU {} across {} core(s)\n\n", bar(average), per_core.len());
    for (index, usage) in per_core.iter().enumerate() {
        out.push_str(&format!("  core {:<3} {}\n", index, bar(*usage)));
    }
    let load = System::load_average();
    out.push_str(&format!("\nLoad average: {:.2} {:.2} {:.2}", load.one, load.five, load.fifteen));

    Ok(ToolOutcome::ok(out).with_data(serde_json::json!({
        "average_percent": average,
        "per_core": per_core,
        "load_1m": load.one,
        "load_5m": load.five,
        "load_15m": load.fifteen,
    })))
}

define_tool!(
    SysCpu,
    name: "sys_cpu",
    description: "Current CPU utilisation, per core and averaged, plus load average.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(serde_json::json!({}), &[]),
    available: true,
    run: sys_cpu
);

// ── sys_memory ────────────────────────────────────────────────────────────

async fn sys_memory(_args: &serde_json::Value, _ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let mut system = System::new();
    system.refresh_memory();

    let total = system.total_memory();
    let used = system.used_memory();
    let available = system.available_memory();
    let percent = if total == 0 { 0.0 } else { used as f32 / total as f32 * 100.0 };

    let swap_total = system.total_swap();
    let swap_used = system.used_swap();
    let swap_percent = if swap_total == 0 {
        0.0
    } else {
        swap_used as f32 / swap_total as f32 * 100.0
    };

    let mut out = format!("Memory {}\n", bar(percent));
    out.push_str(&format!("  used:      {}\n", human_bytes(used)));
    out.push_str(&format!("  available: {}\n", human_bytes(available)));
    out.push_str(&format!("  total:     {}\n", human_bytes(total)));
    if swap_total > 0 {
        out.push_str(&format!("\nSwap {}\n", bar(swap_percent)));
        out.push_str(&format!("  used:  {} of {}\n", human_bytes(swap_used), human_bytes(swap_total)));
        // Sustained swap use is the classic precursor to the OOM killer, and is
        // worth stating rather than leaving for the model to infer.
        if swap_percent > 50.0 {
            out.push_str("\n  Note: heavy swap use often precedes OOM kills.\n");
        }
    }

    Ok(ToolOutcome::ok(out).with_data(serde_json::json!({
        "used_bytes": used,
        "available_bytes": available,
        "total_bytes": total,
        "used_percent": percent,
        "swap_used_bytes": swap_used,
        "swap_total_bytes": swap_total,
    })))
}

define_tool!(
    SysMemory,
    name: "sys_memory",
    description: "Memory and swap usage for this host.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(serde_json::json!({}), &[]),
    available: true,
    run: sys_memory
);

// ── sys_disk ──────────────────────────────────────────────────────────────

async fn sys_disk(_args: &serde_json::Value, _ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let disks = Disks::new_with_refreshed_list();
    let mut out = String::from("Filesystems\n\n");
    let mut records = Vec::new();
    let mut worst = 0.0f32;

    for disk in disks.list() {
        let total = disk.total_space();
        let available = disk.available_space();
        let used = total.saturating_sub(available);
        let percent = if total == 0 { 0.0 } else { used as f32 / total as f32 * 100.0 };
        worst = worst.max(percent);

        out.push_str(&format!(
            "  {:<28} {:<10} {}\n     {} used of {}, {} free\n",
            disk.mount_point().display(),
            disk.file_system().to_string_lossy(),
            bar(percent),
            human_bytes(used),
            human_bytes(total),
            human_bytes(available),
        ));
        records.push(serde_json::json!({
            "mount": disk.mount_point().display().to_string(),
            "filesystem": disk.file_system().to_string_lossy(),
            "total_bytes": total,
            "available_bytes": available,
            "used_percent": percent,
        }));
    }

    if worst >= 90.0 {
        out.push_str("\n  Warning: a filesystem is above 90% full.\n");
    }

    Ok(ToolOutcome::ok(out).with_data(serde_json::json!({ "disks": records, "worst_percent": worst })))
}

define_tool!(
    SysDisk,
    name: "sys_disk",
    description: "Disk usage per mounted filesystem.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(serde_json::json!({}), &[]),
    available: true,
    run: sys_disk
);

// ── sys_processes ─────────────────────────────────────────────────────────

async fn sys_processes(args: &serde_json::Value, _ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let limit = arg_u64(args, "limit", 15).clamp(1, 200) as usize;
    let sort_by = arg_str_opt(args, "sort_by").unwrap_or("memory");
    let filter = arg_str_opt(args, "name").map(|n| n.to_lowercase());

    let mut system = System::new_all();
    sample_cpu(&mut system);
    system.refresh_processes();

    let mut processes: Vec<_> = system
        .processes()
        .values()
        .filter(|p| match &filter {
            Some(needle) => p.name().to_lowercase().contains(needle.as_str()),
            None => true,
        })
        .collect();

    match sort_by {
        "cpu" => processes.sort_by(|a, b| {
            b.cpu_usage().partial_cmp(&a.cpu_usage()).unwrap_or(std::cmp::Ordering::Equal)
        }),
        _ => processes.sort_by_key(|p| std::cmp::Reverse(p.memory())),
    }
    processes.truncate(limit);

    let mut out = format!("Top {} processes by {}\n\n", processes.len(), sort_by);
    out.push_str(&format!("{:>8}  {:>6}  {:>10}  {}\n", "PID", "CPU%", "MEM", "COMMAND"));
    let mut records = Vec::new();
    for process in &processes {
        out.push_str(&format!(
            "{:>8}  {:>6.1}  {:>10}  {}\n",
            process.pid(),
            process.cpu_usage(),
            human_bytes(process.memory()),
            process.name()
        ));
        records.push(serde_json::json!({
            "pid": process.pid().as_u32(),
            "name": process.name(),
            "cpu_percent": process.cpu_usage(),
            "memory_bytes": process.memory(),
        }));
    }
    if processes.is_empty() {
        out.push_str("(no matching processes)\n");
    }

    Ok(ToolOutcome::ok(out).with_data(serde_json::json!({ "processes": records })))
}

define_tool!(
    SysProcesses,
    name: "sys_processes",
    description: "List running processes, sorted by memory or CPU, optionally filtered by name.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(
        serde_json::json!({
            "limit": prop("integer", "How many processes to show, default 15"),
            "sort_by": prop("string", "Either 'memory' or 'cpu'"),
            "name": prop("string", "Only show processes whose name contains this")
        }),
        &[]
    ),
    available: true,
    run: sys_processes
);

// ── sys_ports ─────────────────────────────────────────────────────────────

async fn sys_ports(_args: &serde_json::Value, ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    // There is no portable API for listening sockets, so this shells out to
    // whichever of the usual tools exists, in order of how good the output is.
    let (program, args): (&str, Vec<String>) = if cfg!(windows) {
        ("netstat", vec!["-ano".into()])
    } else if proc::has_program("ss") {
        ("ss", vec!["-tulpn".into()])
    } else if proc::has_program("netstat") {
        ("netstat", vec!["-tulpn".into()])
    } else if proc::has_program("lsof") {
        ("lsof", vec!["-iTCP".into(), "-sTCP:LISTEN".into(), "-P".into(), "-n".into()])
    } else {
        return Err(ToolError::Unavailable {
            tool: "sys_ports".into(),
            requirement: "ss, netstat, or lsof".into(),
        });
    };

    let result = proc::run(program, &args, ctx).await?;
    Ok(ToolOutcome {
        ok: result.ok(),
        output: if result.output.trim().is_empty() {
            "No listening sockets reported".into()
        } else {
            result.output
        },
        exit_code: Some(result.exit_code),
        data: None,
        metadata: serde_json::json!({ "source": program }),
        snapshot_id: None,
    })
}

define_tool!(
    SysPorts,
    name: "sys_ports",
    description: "List listening network ports and the processes bound to them.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(serde_json::json!({}), &[]),
    available: true,
    run: sys_ports
);

// ── sys_network ───────────────────────────────────────────────────────────

async fn sys_network(_args: &serde_json::Value, _ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let networks = Networks::new_with_refreshed_list();
    let mut out = String::from("Network interfaces\n\n");
    let mut records = Vec::new();
    for (name, data) in networks.list() {
        out.push_str(&format!(
            "  {:<16} rx {:>10}  tx {:>10}  (errors rx {} / tx {})\n",
            name,
            human_bytes(data.total_received()),
            human_bytes(data.total_transmitted()),
            data.total_errors_on_received(),
            data.total_errors_on_transmitted(),
        ));
        records.push(serde_json::json!({
            "interface": name,
            "rx_bytes": data.total_received(),
            "tx_bytes": data.total_transmitted(),
            "rx_errors": data.total_errors_on_received(),
            "tx_errors": data.total_errors_on_transmitted(),
        }));
    }
    Ok(ToolOutcome::ok(out).with_data(serde_json::json!({ "interfaces": records })))
}

define_tool!(
    SysNetwork,
    name: "sys_network",
    description: "Per-interface network traffic counters and error counts.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(serde_json::json!({}), &[]),
    available: true,
    run: sys_network
);

// ── sys_uptime ────────────────────────────────────────────────────────────

async fn sys_uptime(_args: &serde_json::Value, _ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let uptime = System::uptime();
    let boot = System::boot_time();
    let booted_at = chrono::DateTime::from_timestamp(boot as i64, 0)
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(|| "unknown".into());
    Ok(ToolOutcome::ok(format!(
        "Up {} (booted {})",
        format_duration(uptime),
        booted_at
    ))
    .with_data(serde_json::json!({ "uptime_secs": uptime, "booted_at": booted_at })))
}

define_tool!(
    SysUptime,
    name: "sys_uptime",
    description: "How long this host has been running, and when it last booted.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(serde_json::json!({}), &[]),
    available: true,
    run: sys_uptime
);

// ── sys_health ────────────────────────────────────────────────────────────

async fn sys_health(_args: &serde_json::Value, _ctx: &ExecContext) -> Result<ToolOutcome, ToolError> {
    let mut system = System::new_all();
    sample_cpu(&mut system);
    system.refresh_memory();

    let cpus = system.cpus();
    let cpu = if cpus.is_empty() {
        0.0
    } else {
        cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32
    };
    let memory = if system.total_memory() == 0 {
        0.0
    } else {
        system.used_memory() as f32 / system.total_memory() as f32 * 100.0
    };
    let disks = Disks::new_with_refreshed_list();
    let disk = disks
        .list()
        .iter()
        .map(|d| {
            let total = d.total_space();
            if total == 0 {
                0.0
            } else {
                (total - d.available_space()) as f32 / total as f32 * 100.0
            }
        })
        .fold(0.0f32, f32::max);

    // A single verdict rather than three numbers, because the caller usually
    // wants to know whether to look further, not to do the arithmetic itself.
    let mut concerns = Vec::new();
    if cpu > 90.0 {
        concerns.push(format!("CPU at {:.0}%", cpu));
    }
    if memory > 90.0 {
        concerns.push(format!("memory at {:.0}%", memory));
    }
    if disk > 90.0 {
        concerns.push(format!("a filesystem at {:.0}%", disk));
    }
    let verdict = if concerns.is_empty() { "healthy" } else { "degraded" };

    let mut out = format!("Status: {}\n\n", verdict);
    out.push_str(&format!("  CPU     {}\n", bar(cpu)));
    out.push_str(&format!("  Memory  {}\n", bar(memory)));
    out.push_str(&format!("  Disk    {}\n", bar(disk)));
    if !concerns.is_empty() {
        out.push_str(&format!("\n  Concerns: {}\n", concerns.join(", ")));
    }

    Ok(ToolOutcome::ok(out).with_data(serde_json::json!({
        "status": verdict,
        "cpu_percent": cpu,
        "memory_percent": memory,
        "worst_disk_percent": disk,
        "concerns": concerns,
    })))
}

define_tool!(
    SysHealth,
    name: "sys_health",
    description: "One-shot health verdict for this host, combining CPU, memory and disk into a healthy/degraded status.",
    blast: "LOW",
    read_only: true,
    reversible: true,
    schema: schema(serde_json::json!({}), &[]),
    available: true,
    run: sys_health
);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> ExecContext {
        ExecContext::new(std::env::temp_dir())
    }

    #[tokio::test]
    async fn host_information_is_populated() {
        let out = sys_info(&json!({}), &ctx()).await.unwrap();
        assert!(out.ok);
        let data = out.data.unwrap();
        assert!(data["cpu_count"].as_u64().unwrap() >= 1);
        assert!(data["total_memory_bytes"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn cpu_sampling_returns_a_plausible_percentage() {
        // Guards the double-sample: a single refresh reports a meaningless value.
        let out = sys_cpu(&json!({}), &ctx()).await.unwrap();
        let average = out.data.unwrap()["average_percent"].as_f64().unwrap();
        assert!((0.0..=100.0).contains(&average), "got {}", average);
    }

    #[tokio::test]
    async fn memory_percentages_are_internally_consistent() {
        let out = sys_memory(&json!({}), &ctx()).await.unwrap();
        let data = out.data.unwrap();
        let used = data["used_bytes"].as_u64().unwrap();
        let total = data["total_bytes"].as_u64().unwrap();
        assert!(used <= total);
        let percent = data["used_percent"].as_f64().unwrap();
        assert!((0.0..=100.0).contains(&percent));
    }

    #[tokio::test]
    async fn disk_usage_lists_at_least_one_filesystem() {
        let out = sys_disk(&json!({}), &ctx()).await.unwrap();
        let disks = out.data.unwrap()["disks"].as_array().unwrap().len();
        assert!(disks >= 1);
    }

    #[tokio::test]
    async fn process_listing_respects_the_limit() {
        let out = sys_processes(&json!({ "limit": 3 }), &ctx()).await.unwrap();
        let count = out.data.unwrap()["processes"].as_array().unwrap().len();
        assert!(count <= 3);
    }

    #[tokio::test]
    async fn process_filtering_by_name_narrows_results() {
        let out = sys_processes(&json!({ "name": "seep-no-such-process" }), &ctx())
            .await
            .unwrap();
        assert!(out.data.unwrap()["processes"].as_array().unwrap().is_empty());
        assert!(out.ok, "an empty result is still a successful query");
    }

    #[tokio::test]
    async fn health_returns_a_single_verdict() {
        let out = sys_health(&json!({}), &ctx()).await.unwrap();
        let status = out.data.unwrap()["status"].as_str().unwrap().to_string();
        assert!(status == "healthy" || status == "degraded");
    }

    #[tokio::test]
    async fn uptime_is_reported() {
        let out = sys_uptime(&json!({}), &ctx()).await.unwrap();
        assert!(out.data.unwrap()["uptime_secs"].as_u64().is_some());
    }

    #[test]
    fn every_system_tool_is_read_only() {
        // These are what unattended triage is allowed to use; none may mutate.
        for tool in tools() {
            let spec = tool.spec();
            assert!(spec.read_only, "{} must be read-only", spec.name);
            assert_eq!(spec.max_blast_radius, "LOW");
        }
    }

    #[test]
    fn durations_render_readably() {
        assert_eq!(format_duration(90), "1m");
        assert_eq!(format_duration(3_700), "1h 1m");
        assert_eq!(format_duration(90_061), "1d 1h 1m");
    }

    #[test]
    fn bars_are_fixed_width_and_clamped() {
        assert!(bar(0.0).starts_with("[····"));
        assert!(bar(100.0).starts_with("[####################]"));
        // A percentage above 100 must not overflow the bar.
        assert!(bar(150.0).contains("####################"));
    }
}
