# NetSentinel LA-IDRS — Architecture Notes

## Component Responsibilities

### Packet Engine (C / libpcap)
- Captures raw packets on a given network interface in promiscuous mode
- Applies a BPF filter (`ip`) to discard non-IP frames early
- Parses Ethernet → IP → TCP/UDP headers into a fixed `packet_meta_t` struct
- Streams structs over a UNIX domain socket to the Python detection engine
- Supervised by `orchestrator/supervisor.py` — auto-restarts on crash

### Detection Engine (Python)
| Sub-component | Role |
|---|---|
| `BaselineLearner` | 24-hour passive phase — observes traffic without blocking |
| `EMATracker` | Per-IP exponential moving average of packet rate |
| `NetworkProfile` | Per-IP historical port diversity and rate statistics |
| `RecentPacketCache` | Rolling 10-second window of recent packets per IP |
| `SignatureEngine` | JSON-driven rule evaluation (port scan, SYN flood, brute force) |
| `BehaviorEngine` | EMA deviation scoring, port diversity anomaly, protocol mismatch |
| `RiskScorer` | Accumulates weighted score per IP from all finding sources |
| `DecisionEngine` | Maps score thresholds to actions: LOG / ALERT / BLOCK / HONEYPOT |
| `Detector` | UNIX socket server — dispatches packets through all engines |

### Attack Graph Engine
- Builds a `networkx.DiGraph` of causal events per IP
- Chains events as they arrive: `[Scan] → [Enum] → [Brute Force] → [Block]`
- Finalises and persists the graph to JSON when a block is triggered
- Narrative string rendered in the dashboard as a visual timeline

### Deception Layer
- Triggered by `DecisionEngine` when a port scan is detected
- Spawns N randomised TCP listeners (`MicroHoneypot`) in the ephemeral port range
- Any connection to a honeypot port → `HoneypotSignal.emit()` → instant block (score 100)
- Honeypot ports are torn down automatically after the IP is blocked

### XAI Report Generator
- Fires for every automated block action
- Produces a structured JSON report: IP, timestamp, score, per-event reasons, graph ID
- Stored in `data/db/reports/` and served via the REST API
- HTML template (`xai/templates/block_report.html`) for human-readable rendering

### Response Engine
- `IPBlocker`: wraps `iptables.sh` — adds/removes rules in `NETSENTINEL_BLOCK` chain
- `ScheduledUnblocker`: TTL-based automatic unban (default 1 hour)
- `TaskScheduler`: generic periodic task runner for housekeeping

### P2P Threat Intelligence (opt-in)
- `GossipNode`: asyncio-based TCP gossip server + broadcaster
- `SignatureSanitizer`: strips all IP addresses before any outbound share
- `PeerRegistry`: JSON-persisted list of known peer node addresses
- Disabled by default (`NS_P2P=false`)

### API (FastAPI)
- Stateless REST layer — all state injected from live engine references
- Routes: `/status`, `/alerts`, `/blocks`, `/graphs`, `/honeypots`, `/reports`
- CORS enabled for dashboard access
- Served by `uvicorn` from inside `NetSentinelRunner`

### Dashboard (HTML/CSS/JS)
- Static single-page app — no build step required
- Polls the API every 5 seconds
- Displays: live alerts table, blocked IP list, attack graph timeline, XAI reports
- Unblock action via DELETE `/api/v1/blocks/{ip}` with confirmation modal

---

## Data Flow Summary

```
NIC → libpcap (C)
    → UNIX socket → Detector (Python)
        → BaselineLearner (passive phase)
        → [after baseline] SignatureEngine + BehaviorEngine
        → RiskScorer → IPState
        → DecisionEngine
            ├─ score 31-70  → Alert via API
            ├─ scan detect  → HoneypotManager.spawn_for_ip()
            │                   └─ contact → HoneypotSignal → instant block
            └─ score >= 71  → IPBlocker (iptables)
                             → AttackGraphBuilder.finalize()
                             → AttackGraphStore.save()
                             → XAIReportGenerator.generate()
                             → [P2P] GossipNode.broadcast()
```

---

## Scoring Table

| Score Range | Action |
|---|---|
| 0 – 30 | Log only |
| 31 – 70 | Alert via API |
| 71 – 100 | Auto-block via iptables |
| Honeypot contact | Instant block (score = 100) |

---

## Key Design Decisions

**Why C for packet capture?**
libpcap operates in the kernel's fast path. A C layer minimises per-packet overhead before handing off to Python. The binary struct protocol keeps IPC overhead negligible.

**Why EMA instead of static thresholds?**
Static thresholds produce excessive false positives on networks with unusual but legitimate traffic patterns (e.g. lab environments with large file transfers). EMA adapts to each network's actual baseline within hours.

**Why micro-honeypots for zero-FP blocking?**
Any IP that deliberately connects to a dynamically-opened, randomised fake port has no legitimate reason to do so. This gives a binary, near-zero-false-positive block signal that doesn't depend on scoring thresholds.

**Why P2P instead of a central threat feed?**
A central server is a single point of failure and a privacy liability. The gossip protocol distributes threat intelligence within minutes with no central dependency, and the sanitizer guarantees no raw IPs leave the node.
