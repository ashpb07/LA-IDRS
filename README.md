# NetSentinel — LA-IDRS

**Lightweight Autonomous Intrusion Detection and Response System**

A plug-and-play, self-defending network intrusion detection system for small-scale environments. Monitors traffic at the packet level, detects intrusions using rule-based and behavioral analysis, and autonomously responds to threats while explaining every decision it makes.

---

## Designed For

- Small businesses
- College labs and research environments
- Home and personal networks

---

## Features

| Feature | Description |
|---|---|
| Real-time packet capture | C + libpcap, minimal per-packet overhead |
| Signature detection | Port scan, SYN flood, brute force (JSON-driven rules) |
| Behavior detection | EMA deviation scoring, port diversity anomaly, protocol mismatch |
| Adaptive baseline | 24-hour passive observation phase, per-network thresholds |
| Risk scoring | Weighted cumulative score with three response tiers |
| Micro-honeypot deception | Dynamic fake listeners — any contact triggers instant block |
| Causal attack graphs | Per-attacker event chains stored as JSON, rendered in dashboard |
| XAI block reports | Structured explanation for every automated block action |
| Auto-unban | TTL-based scheduled IP release (default 1 hour) |
| P2P threat intelligence | Anonymized gossip broadcast to peer nodes (opt-in, off by default) |
| REST API | FastAPI with live engine state |
| Dashboard | Single-page HTML/JS, auto-refreshing every 5 seconds |

---

## Risk Score Table

| Score | Action |
|---|---|
| 0 - 30 | Log only |
| 31 - 70 | Alert via API and dashboard |
| 71 - 100 | Auto-block via iptables |
| Honeypot contact | Instant block regardless of score |

---

## Architecture

```
NIC
 |
 v
Packet Engine (C / libpcap)
 |  raw packet_meta_t structs over UNIX socket
 v
Detection Engine (Python)
 |-- BaselineLearner    24-hour passive observation phase
 |-- EMATracker         Per-IP exponential moving average
 |-- SignatureEngine    JSON rule evaluation
 |-- BehaviorEngine     Anomaly scoring against baseline
 |-- RiskScorer         Cumulative weighted score per IP
 |
 v
DecisionEngine
 |-- score 31-70   --> Alert via API
 |-- scan detected --> HoneypotManager (spawn fake listeners)
 |                      |
 |                      +-- contact --> instant block
 |-- score 71+     --> IPBlocker (iptables)
                        |-- AttackGraphBuilder.finalize()
                        |-- AttackGraphStore.save()
                        |-- XAIReportGenerator.generate()
                        |-- GossipNode.broadcast() [if P2P enabled]
 |
 v
FastAPI  -->  Dashboard
         -->  P2P Peer Nodes (opt-in)
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Packet capture | C, libpcap |
| Detection engine | Python |
| Baseline engine | Python, numpy |
| Attack graph engine | Python, networkx |
| Deception layer | Python, socket |
| XAI report generator | Python |
| Response engine | Python, Bash |
| Firewall control | iptables |
| API | FastAPI, uvicorn |
| Dashboard | HTML, CSS, JavaScript |
| P2P threat intel | Python, asyncio |
| OS | Linux |

---

## Quick Start

Requirements: Linux, Python 3.11+, GCC, libpcap-dev, iptables, root access.

```bash
git clone https://github.com/your-username/netsentinel-laidrs.git
cd netsentinel-laidrs
chmod +x scripts/setup.sh
sudo ./scripts/setup.sh
sudo ./scripts/run.sh
```

On first run the system enters a 24-hour baseline learning phase. No blocking occurs during this phase. To skip it for testing, set `NS_SKIP_BASELINE=true` in `.env`.

---

## Configuration

Copy `.env.example` to `.env` and edit before running:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `NS_IFACE` | `eth0` | Network interface to monitor |
| `NS_BASELINE_SEC` | `86400` | Baseline learning duration in seconds |
| `NS_SKIP_BASELINE` | `false` | Skip baseline phase (testing only) |
| `NS_API_HOST` | `0.0.0.0` | API bind address |
| `NS_API_PORT` | `8000` | API port |
| `NS_LOG_LEVEL` | `INFO` | DEBUG / INFO / WARNING / ERROR |
| `NS_BAN_TTL_SEC` | `3600` | Seconds before a blocked IP is automatically unbanned |
| `NS_HP_PORTS` | `5` | Number of honeypot ports to open per scan event |
| `NS_P2P` | `false` | Enable P2P threat intelligence sharing |
| `NS_P2P_PORT` | `9999` | Gossip listener port |
| `NS_P2P_PEERS` | _(empty)_ | Comma-separated list of peer node IPs |

---

## API Endpoints

Base URL: `http://<host>:8000/api/v1`

| Method | Path | Description |
|---|---|---|
| GET | `/status` | System status, baseline progress, block count |
| GET | `/alerts` | All tracked IPs with risk scores and events |
| GET | `/alerts/{ip}` | Full alert detail for a single IP |
| GET | `/blocks` | Currently blocked IPs |
| DELETE | `/blocks/{ip}` | Manually unblock an IP |
| GET | `/graphs` | All recorded attack graphs |
| GET | `/graphs/{id}` | Single attack graph by ID |
| GET | `/honeypots` | Honeypot contact count |
| GET | `/honeypots/contacts` | Recent honeypot contacts |
| GET | `/reports` | All XAI block reports |
| GET | `/reports/{ip}` | Most recent block report for an IP |

Interactive API docs available at `http://<host>:8000/docs`.

---

## Dashboard

Open `http://localhost:8000` in a browser after starting the system.

The dashboard auto-refreshes every 5 seconds and displays:

- System status and baseline learning progress
- Live alerts table with per-IP risk scores
- Blocked IP list with manual unblock option
- Attack graph timeline showing the causal chain of events per attacker
- XAI block reports with per-reason breakdown

---

## Example: nmap Scan Response

Attacker runs:

```bash
nmap -sS <target>
```

NetSentinel response sequence:

1. Packet engine detects SYN packets across multiple ports
2. Signature engine fires PORT_SCAN_001 rule — score +35
3. Behavior engine detects rate anomaly against baseline — score +20
4. Decision engine triggers honeypot spawn for the source IP
5. Attacker connects to a honeypot port — score set to 100, instant block
6. iptables rule added to NETSENTINEL_BLOCK chain
7. Attack graph finalized: `[TCP Port Scan] --> [Packet Rate Anomaly] --> [Honeypot Contact] --> [Block]`
8. XAI report generated and pushed to API
9. Dashboard displays full alert with causal context
10. Anonymized signature broadcast to peer nodes (if P2P enabled)

---

## XAI Block Report Format

```json
{
  "ip": "192.168.1.45",
  "blocked_at": "2025-06-01T14:32:10Z",
  "risk_score": 87,
  "reasons": [
    "TCP Port Scan: 24 unique ports in 5 seconds",
    "Packet Rate Anomaly: 4.2 standard deviations above baseline",
    "Honeypot Contact: connected to port 31337"
  ],
  "honeypot_contacts": 1,
  "attack_graph_id": "graph_192_168_1_45_1748784730"
}
```

---

## Docker

```bash
cd docker
docker-compose up --build
```

The container uses `network_mode: host` and requires `NET_ADMIN` and `NET_RAW` capabilities for packet capture and iptables access.

---

## Testing

```bash
source .venv/bin/activate
pytest tests/ -v
```

Test coverage includes: detection engine, EMA baseline, risk scoring, attack graph builder, XAI report generator, P2P sanitizer, and deception layer.

---

## Project Structure

```
netsentinel-laidrs/
├── packet_engine/          C layer — libpcap packet capture
│   ├── src/                capture.c, parser.c, emitter.c, main.c
│   ├── include/            capture.h, parser.h, emitter.h
│   └── Makefile
├── detection_engine/       Core detection pipeline
│   ├── core/               detector, signature, behavior, scorer, decision
│   ├── baseline/           learner, ema, profile
│   ├── rules/              port_scan.json, syn_flood.json, brute_force.json
│   ├── state/              ip_state, cache
│   └── utils/              logger, parser
├── attack_graph/           Causal event graph builder and store
├── deception/              Micro-honeypot spawner
├── xai/                    Explainable block report generator
├── response_engine/        iptables blocker, unblocker, scheduler
├── p2p/                    Gossip-based threat intelligence sharing
├── api/                    FastAPI routes, services, schemas
├── dashboard/              Static HTML/CSS/JS dashboard
├── comms/                  UNIX socket server and IPC protocol spec
├── orchestrator/           Startup runner, process supervisor, config loader
├── tests/                  pytest test suite
├── docs/                   Architecture notes
├── scripts/                setup.sh, run.sh, cleanup.sh
├── docker/                 Dockerfile, docker-compose.yml
├── requirements.txt
├── .env.example
└── main.py
```

---

## Cleanup

```bash
sudo ./scripts/cleanup.sh           # flush iptables rules, remove socket
sudo ./scripts/cleanup.sh --purge   # also delete all logs and database files
```

---

## Roadmap

| Version | Feature | Status |
|---|---|---|
| v1.0 | Packet capture, signature detection, iptables blocking | Complete |
| v1.1 | Adaptive baseline engine | Planned |
| v1.2 | Micro-honeypot deception layer | Planned |
| v1.3 | Causal attack graph engine | Planned |
| v1.4 | XAI block reports | Planned |
| v2.0 | Federated P2P threat intelligence | Research |
| v2.1 | SDN integration | Research |
| v2.2 | Distributed detection nodes | Research |

---

## Disclaimer

This project is intended for educational purposes and small-scale deployments. It is not a replacement for enterprise-grade IDS solutions. The deception layer and automated blocking features must only be deployed on networks you own or have explicit written authorization to protect. Unauthorized use on third-party networks may violate applicable law.

---

## License

MIT License

---

## Authors

Anish G Prabhu — [github.com/ashpb07](https://github.com/ashpb07)

Hithansh Arekere — [github.com/hithansharekere-debug](https://github.com/hithansharekere-debug)
