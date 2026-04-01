# bpf-mcp-example

A minimal example of a BPF-powered [MCP](https://modelcontextprotocol.io)
server in Rust. Attaches to the `tp_btf/sched_switch` tracepoint to collect
real-time context switch data from the kernel, then exposes it to AI models (or
any MCP client) as callable tools.

Built with [libbpf-rs](https://docs.rs/libbpf-rs) and following the patterns
from [scxtop](https://github.com/sched-ext/scx/tree/main/tools/scxtop).

## Architecture

```
  MCP Client (Claude, etc.)          bpf-sched-monitor
  ┌──────────────────────┐          ┌──────────────────────────────────┐
  │                      │  stdin   │  MCP Server (JSON-RPC/stdio)     │
  │  "Which processes    │─────────>│    ┌──────────────────────────┐  │
  │   are switching      │  stdout  │    │ enable/disable_collection│  │
  │   the most?"         │<─────────│    │ get_scheduling_stats     │  │
  │                      │          │    │ get_top_processes        │  │
  └──────────────────────┘          │    │ reset_stats              │  │
                                    │    └────────────┬─────────────┘  │
                                    │                 │                │
                                    │    ┌────────────▼────────────┐   │
                                    │    │ Stats Aggregation       │   │
                                    │    │ Arc<Mutex<Stats>>       │   │
                                    │    └────────────┬────────────┘   │
                                    │                 │                │
                                    │    ┌────────────▼────────────┐   │
                                    │    │ Ring Buffer Consumer    │   │
                                    │    │ epoll (blocking)        │   │
                                    ├────┴─────────────────────────┴───┤
                                    │  Kernel                          │
                                    │    ┌─────────────────────────┐   │
                                    │    │ BPF: tp_btf/sched_switch│   │
                                    │    │ → ringbuf submit        │   │
                                    │    └─────────────────────────┘   │
                                    └──────────────────────────────────┘
```

## Prerequisites

- Linux kernel with BTF support (`/sys/kernel/btf/vmlinux` must exist)
- `bpftool` (generates `vmlinux.h` at build time)
- `clang` (compiles BPF C code)
- Rust 1.85+ (edition 2024)
- Root privileges or `CAP_BPF` + `CAP_PERFMON` to run

On Arch:
```bash
sudo pacman -S bpf clang
```

On Ubuntu/Debian:
```bash
sudo apt install bpftool clang linux-tools-common
```

## Build

```bash
cargo build
# or
cargo build --release
```

The build process:
1. Runs `bpftool btf dump` to generate `vmlinux.h` from your running kernel's BTF
2. Compiles `src/bpf/main.bpf.c` to BPF bytecode with clang
3. Generates a Rust skeleton for type-safe access to BPF programs and maps

## Run

```bash
sudo ./target/debug/bpf-mcp-example
```

The server attaches to the `sched_switch` tracepoint but collection is
**disabled by default** to avoid unnecessary CPU usage. Use the
`enable_collection` / `disable_collection` MCP tools to control when events are
recorded.

## MCP Tools

| Tool | Description |
|------|-------------|
| `enable_collection` | Enable BPF event collection (resets stats) |
| `disable_collection` | Disable BPF event collection (stats remain queryable) |
| `get_scheduling_stats` | Per-CPU context switch counts, events/sec, collection duration |
| `get_top_processes` | Top N processes by context switch activity (sortable) |
| `reset_stats` | Reset all counters and start fresh |

## Examples

### Quick test

Pipe JSON-RPC messages to stdin with a sleep to let events accumulate:

```bash
(
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"enable_collection","arguments":{}}}'
sleep 2
echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_scheduling_stats","arguments":{}}}'
echo '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_top_processes","arguments":{"limit":5,"sort_by":"total"}}}'
echo '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"disable_collection","arguments":{}}}'
) | sudo ./target/release/bpf-mcp-example
```

### MCP protocol walkthrough

**1. Initialize the session:**

```json
→ {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}

← {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"bpf-sched-monitor","version":"0.1.0"}}}
```

**2. Send the initialized notification (no response):**

```json
→ {"jsonrpc":"2.0","method":"notifications/initialized"}
```

**3. List available tools:**

```json
→ {"jsonrpc":"2.0","id":2,"method":"tools/list"}

← {"jsonrpc":"2.0","id":2,"result":{"tools":[
    {"name":"get_scheduling_stats","description":"Get overall scheduling statistics...","inputSchema":{...}},
    {"name":"get_top_processes","description":"Get top processes by context switch activity...","inputSchema":{...}},
    {"name":"reset_stats","description":"Reset all collected scheduling statistics...","inputSchema":{...}},
    {"name":"enable_collection","description":"Enable BPF event collection...","inputSchema":{...}},
    {"name":"disable_collection","description":"Disable BPF event collection...","inputSchema":{...}}
  ]}}
```

**4. Enable collection:**

```json
→ {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"enable_collection","arguments":{}}}

← {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"Collection enabled, stats reset"}]}}
```

**5. Get scheduling stats** (after collecting events for a few seconds):

```json
→ {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_scheduling_stats","arguments":{}}}

← {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"{\n  \"total_events\": 84523,\n  \"collection_duration_secs\": 2.01,\n  \"events_per_sec\": 42050.7,\n  \"num_cpus_observed\": 16,\n  \"per_cpu\": [\n    {\"cpu\": 0, \"switches\": 5204},\n    {\"cpu\": 1, \"switches\": 5891},\n    ...\n  ],\n  \"unique_processes\": 127,\n  \"collection_enabled\": true\n}"}]}}
```

**6. Get top processes** by total context switches:

```json
→ {"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_top_processes","arguments":{"limit":5,"sort_by":"total"}}}

← {"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"{\n  \"top_processes\": [\n    {\"tgid\": 1423, \"comm\": \"firefox\", \"switches_from\": 12050, \"switches_to\": 11998, \"total_switches\": 24048},\n    {\"tgid\": 892, \"comm\": \"Xwayland\", \"switches_from\": 8721, \"switches_to\": 8700, \"total_switches\": 17421},\n    {\"tgid\": 0, \"comm\": \"swapper/0\", \"switches_from\": 3102, \"switches_to\": 7845, \"total_switches\": 10947},\n    {\"tgid\": 2841, \"comm\": \"code\", \"switches_from\": 4201, \"switches_to\": 4150, \"total_switches\": 8351},\n    {\"tgid\": 567, \"comm\": \"pipewire\", \"switches_from\": 3800, \"switches_to\": 3790, \"total_switches\": 7590}\n  ],\n  \"sort_by\": \"total\",\n  \"limit\": 5\n}"}]}}
```

**7. Get most-preempted processes:**

```json
→ {"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_top_processes","arguments":{"limit":3,"sort_by":"switches_from"}}}
```

**8. Reset stats and start fresh:**

```json
→ {"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"reset_stats","arguments":{}}}

← {"jsonrpc":"2.0","id":6,"result":{"content":[{"type":"text","text":"Statistics reset successfully"}]}}
```

**9. Disable collection** when done:

```json
→ {"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"disable_collection","arguments":{}}}

← {"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"Collection disabled"}]}}
```

### Interactive session

For an interactive session where you type messages one at a time:

```bash
sudo ./target/debug/bpf-mcp-example
```

Then paste JSON-RPC lines into stdin. Responses appear on stdout, diagnostic messages on stderr.

### Using with Claude Code

Add to your MCP server configuration (`.claude/settings.json` or similar):

```json
{
  "mcpServers": {
    "bpf-sched-monitor": {
      "command": "sudo",
      "args": ["./target/release/bpf-mcp-example"]
    }
  }
}
```

Then Claude can call `get_scheduling_stats` and `get_top_processes` to analyze
live kernel scheduling behavior.

## Project Structure

```
├── build.rs              # Generates vmlinux.h, compiles BPF, generates Rust skeleton
├── Cargo.toml
├── src/
│   ├── bpf/
│   │   ├── intf.h        # Shared event struct between BPF C and Rust
│   │   └── main.bpf.c   # BPF program: tp_btf/sched_switch → ring buffer
│   └── main.rs           # Ring buffer consumer, stats aggregation, MCP server
```

### Data flow

1. **Kernel**: `sched_switch` tracepoint fires on every context switch
2. **BPF program** (when attached): captures prev/next task PID, TGID, comm; submits to ring buffer
3. **Ring buffer callback**: parses event, updates `Stats` (per-CPU counts, per-process counts)
4. **MCP tool call**: reads from `Stats`, returns JSON to the client

### Key design decisions

- **`tp_btf/sched_switch`** — stable tracepoint, available on all modern kernels, BTF-typed arguments for CO-RE portability
- **Single ring buffer** — sufficient for an example; production tools (like scxtop) use hash-of-maps for multi-ring-buffer scalability
- **`try_lock()` in BPF callback** — avoids blocking the ring buffer consumer if the MCP handler holds the lock
- **Ring buffer consumer in background thread** — uses epoll to block until events arrive; main thread handles blocking stdin reads for MCP; no async runtime needed
- **Collection disabled by default** — the BPF program is loaded but not attached at startup; `enable_collection` attaches to the tracepoint and `disable_collection` detaches, so there is truly zero overhead when not collecting

## Extending this example

Some ideas for building on this:

- **Add more tracepoints** — `sched_wakeup` for wakeup latency, `softirq_entry/exit` for interrupt analysis
- **shared ring buffers** — use `BPF_MAP_TYPE_HASH_OF_MAPS` for scalability
- **Sampling** — add a configurable sample rate to reduce overhead on busy systems
- **More MCP tools** — latency histograms, waker-wakee analysis, anomaly detection
- **MCP resources** — expose live stats as MCP resources for passive reads

## References

- [scxtop](https://github.com/sched-ext/scx/tree/main/tools/scxtop) — full-featured BPF + MCP scheduler observability tool
- [libbpf-rs docs](https://docs.rs/libbpf-rs)
- [MCP specification](https://modelcontextprotocol.io)
- [BPF documentation](https://docs.kernel.org/bpf/)
