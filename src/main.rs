use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::mem::MaybeUninit;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use anyhow::Result;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use serde_json::{Value, json};

include!(concat!(env!("OUT_DIR"), "/skel.rs"));

const SCHED_SWITCH_EVENT: u32 = 1;
const TASK_COMM_LEN: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
struct Event {
    type_: u32,
    cpu: u32,
    ts: u64,
    prev_pid: u32,
    next_pid: u32,
    prev_tgid: u32,
    next_tgid: u32,
    prev_comm: [u8; TASK_COMM_LEN],
    next_comm: [u8; TASK_COMM_LEN],
}

struct ProcessInfo {
    comm: String,
    switches_from: u64,
    switches_to: u64,
}

struct Stats {
    total_events: u64,
    per_cpu_switches: HashMap<u32, u64>,
    per_process: HashMap<u32, ProcessInfo>,
    start_time: Instant,
    filter_tgid: u32,
}

impl Stats {
    fn new(filter_tgid: u32) -> Self {
        Self {
            total_events: 0,
            per_cpu_switches: HashMap::new(),
            per_process: HashMap::new(),
            start_time: Instant::now(),
            filter_tgid,
        }
    }

    fn record_switch(&mut self, event: &Event) {
        self.total_events += 1;
        *self.per_cpu_switches.entry(event.cpu).or_insert(0) += 1;

        let prev_comm = comm_to_string(&event.prev_comm);
        let next_comm = comm_to_string(&event.next_comm);

        self.per_process
            .entry(event.prev_tgid)
            .or_insert_with(|| ProcessInfo {
                comm: prev_comm,
                switches_from: 0,
                switches_to: 0,
            })
            .switches_from += 1;

        self.per_process
            .entry(event.next_tgid)
            .or_insert_with(|| ProcessInfo {
                comm: next_comm,
                switches_from: 0,
                switches_to: 0,
            })
            .switches_to += 1;
    }
}

fn comm_to_string(comm: &[u8; TASK_COMM_LEN]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(TASK_COMM_LEN);
    String::from_utf8_lossy(&comm[..end]).to_string()
}

// --- MCP Protocol ---

fn handle_request(
    request: &Value,
    stats: &Arc<Mutex<Stats>>,
    skel: &mut MainSkel<'_>,
) -> Option<Value> {
    let id = request.get("id")?;
    let method = request.get("method")?.as_str()?;

    let response = match method {
        "initialize" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "bpf-sched-monitor",
                    "version": "0.1.0"
                }
            }
        }),

        "ping" => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),

        "tools/list" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "tools": tool_definitions() }
        }),

        "tools/call" => {
            let params = request.get("params")?;
            let name = params.get("name")?.as_str()?;
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": call_tool(name, &args, stats, skel)
            })
        }

        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("Method not found: {method}") }
        }),
    };

    Some(response)
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "get_scheduling_stats",
            "description": "Get overall scheduling statistics: per-CPU context switch counts, events/sec, and collection duration. Data comes from the tp_btf/sched_switch tracepoint.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "get_top_processes",
            "description": "Get top processes by context switch activity. Useful for identifying CPU-bound or frequently-preempted workloads.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Max processes to return",
                        "default": 10
                    },
                    "sort_by": {
                        "type": "string",
                        "enum": ["switches_from", "switches_to", "total"],
                        "description": "Sort by: preempted (switches_from), scheduled (switches_to), or total",
                        "default": "total"
                    }
                }
            }
        },
        {
            "name": "reset_stats",
            "description": "Reset all collected scheduling statistics and start fresh.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "enable_collection",
            "description": "Enable BPF event collection. Resets stats and starts recording sched_switch events.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "disable_collection",
            "description": "Disable BPF event collection. Stats remain available for querying.",
            "inputSchema": { "type": "object", "properties": {} }
        }
    ])
}

fn call_tool(
    name: &str,
    args: &Value,
    stats: &Arc<Mutex<Stats>>,
    skel: &mut MainSkel<'_>,
) -> Value {
    match name {
        "get_scheduling_stats" => {
            let stats = stats.lock().unwrap();
            let elapsed = stats.start_time.elapsed();
            let collecting = skel.links.handle_sched_switch.is_some();

            let filtered: HashMap<_, _> = stats
                .per_process
                .iter()
                .filter(|&(&tgid, _)| stats.filter_tgid == 0 || tgid != stats.filter_tgid)
                .collect();

            let total: u64 = filtered
                .values()
                .map(|p| p.switches_from + p.switches_to)
                .sum();
            let eps = if elapsed.as_secs_f64() > 0.0 {
                total as f64 / elapsed.as_secs_f64()
            } else {
                0.0
            };

            let mut cpu_stats: Vec<_> = stats
                .per_cpu_switches
                .iter()
                .map(|(&cpu, &switches)| json!({ "cpu": cpu, "switches": switches }))
                .collect();
            cpu_stats.sort_by_key(|v| v["cpu"].as_u64().unwrap());

            json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string_pretty(&json!({
                        "total_events": total,
                        "collection_duration_secs": elapsed.as_secs_f64(),
                        "events_per_sec": eps,
                        "num_cpus_observed": stats.per_cpu_switches.len(),
                        "per_cpu": cpu_stats,
                        "unique_processes": filtered.len(),
                        "collection_enabled": collecting,
                    })).unwrap()
                }]
            })
        }

        "get_top_processes" => {
            let stats = stats.lock().unwrap();
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
            let sort_by = args
                .get("sort_by")
                .and_then(|v| v.as_str())
                .unwrap_or("total");

            let mut procs: Vec<_> = stats
                .per_process
                .iter()
                .filter(|&(&tgid, _)| stats.filter_tgid == 0 || tgid != stats.filter_tgid)
                .map(|(&tgid, info)| {
                    json!({
                        "tgid": tgid,
                        "comm": info.comm,
                        "switches_from": info.switches_from,
                        "switches_to": info.switches_to,
                        "total_switches": info.switches_from + info.switches_to,
                    })
                })
                .collect();

            let key = match sort_by {
                "switches_from" => "switches_from",
                "switches_to" => "switches_to",
                _ => "total_switches",
            };
            procs.sort_by(|a, b| b[key].as_u64().cmp(&a[key].as_u64()));
            procs.truncate(limit);

            json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string_pretty(&json!({
                        "top_processes": procs,
                        "sort_by": sort_by,
                        "limit": limit,
                    })).unwrap()
                }]
            })
        }

        "reset_stats" => {
            let filter_tgid = stats.lock().unwrap().filter_tgid;
            *stats.lock().unwrap() = Stats::new(filter_tgid);
            json!({ "content": [{ "type": "text", "text": "Statistics reset successfully" }] })
        }

        "enable_collection" => {
            if skel.links.handle_sched_switch.is_some() {
                return json!({ "content": [{ "type": "text", "text": "Collection already enabled" }] });
            }
            match skel.progs.handle_sched_switch.attach() {
                Ok(link) => {
                    skel.links.handle_sched_switch = Some(link);
                    let filter_tgid = stats.lock().unwrap().filter_tgid;
                    *stats.lock().unwrap() = Stats::new(filter_tgid);
                    json!({ "content": [{ "type": "text", "text": "Collection enabled, stats reset" }] })
                }
                Err(e) => {
                    json!({ "content": [{ "type": "text", "text": format!("Failed to attach: {e}") }], "isError": true })
                }
            }
        }

        "disable_collection" => {
            if skel.links.handle_sched_switch.take().is_some() {
                json!({ "content": [{ "type": "text", "text": "Collection disabled" }] })
            } else {
                json!({ "content": [{ "type": "text", "text": "Collection already disabled" }] })
            }
        }

        _ => json!({
            "content": [{ "type": "text", "text": format!("Unknown tool: {name}") }],
            "isError": true
        }),
    }
}

fn main() -> Result<()> {
    eprintln!("bpf-sched-monitor: loading BPF program...");

    let mut open_object = MaybeUninit::uninit();
    let skel_builder = MainSkelBuilder::default();
    let open_skel = skel_builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;

    eprintln!(
        "bpf-sched-monitor: BPF program loaded (collection disabled, use enable_collection tool)"
    );

    let self_tgid = std::process::id();
    let stats = Arc::new(Mutex::new(Stats::new(self_tgid)));
    let stats_rb = stats.clone();

    // Ring buffer: receive sched_switch events from BPF
    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&skel.maps.events, move |data: &[u8]| {
        if data.len() >= size_of::<Event>() {
            let event: Event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Event) };
            if event.type_ == SCHED_SWITCH_EVENT
                && let Ok(mut s) = stats_rb.try_lock()
            {
                s.record_switch(&event);
            }
        }
        0
    })?;
    let ring_buf = rb_builder.build()?;

    // Consume BPF ring buffer events in a background thread, waking via epoll
    let epoll_fd = ring_buf.epoll_fd();
    thread::spawn(move || {
        use std::os::fd::BorrowedFd;
        let fd = unsafe { BorrowedFd::borrow_raw(epoll_fd) };
        let mut pollfd = [nix::poll::PollFd::new(fd, nix::poll::PollFlags::POLLIN)];
        loop {
            if nix::poll::poll(&mut pollfd, nix::poll::PollTimeout::NONE).unwrap_or(0) > 0 {
                let _ = ring_buf.consume();
            }
        }
    });

    eprintln!("bpf-sched-monitor: MCP server ready on stdio");

    // MCP message loop on main thread (blocking stdin reads)
    let stdin = io::stdin();
    let stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) if !l.trim().is_empty() => l,
            Ok(_) => continue,
            Err(_) => break,
        };
        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("bpf-sched-monitor: parse error: {e}");
                continue;
            }
        };
        // Notifications have no id — skip them
        if request.get("id").is_none() {
            continue;
        }
        if let Some(response) = handle_request(&request, &stats, &mut skel) {
            let mut out = stdout.lock();
            serde_json::to_writer(&mut out, &response)?;
            out.write_all(b"\n")?;
            out.flush()?;
        }
    }

    Ok(())
}
