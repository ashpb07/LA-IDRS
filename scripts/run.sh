#!/usr/bin/env bash
# scripts/run.sh
# Start NetSentinel LA-IDRS. Must be run as root (iptables + pcap).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."

# ── Root check ────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: NetSentinel must run as root (required for libpcap and iptables)."
  exit 1
fi

# ── Activate venv ─────────────────────────────────────────────────────────
if [ -f "$ROOT/.venv/bin/activate" ]; then
  source "$ROOT/.venv/bin/activate"
fi

# ── Load .env ─────────────────────────────────────────────────────────────
if [ -f "$ROOT/.env" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$ROOT/.env"
  set +a
fi

echo "╔══════════════════════════════════════════╗"
echo "║   NetSentinel LA-IDRS — Starting         ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "  Interface : ${NS_IFACE:-eth0}"
echo "  API port  : ${NS_API_PORT:-8000}"
echo "  Log level : ${NS_LOG_LEVEL:-INFO}"
echo "  Baseline  : ${NS_BASELINE_SEC:-86400}s"
echo "  P2P       : ${NS_P2P:-false}"
echo ""

cd "$ROOT"
exec python3 main.py
