#!/usr/bin/env bash
# scripts/cleanup.sh
# Tear down iptables rules, remove socket, optionally wipe data.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."

echo "╔══════════════════════════════════════════╗"
echo "║   NetSentinel LA-IDRS — Cleanup          ║"
echo "╚══════════════════════════════════════════╝"

# ── Remove UNIX socket ────────────────────────────────────────────────────
SOCK="/tmp/netsentinel.sock"
if [ -S "$SOCK" ]; then
  rm -f "$SOCK"
  echo "  Removed socket: $SOCK"
fi

# ── Flush iptables chain ──────────────────────────────────────────────────
CHAIN="NETSENTINEL_BLOCK"
if iptables -n -L "$CHAIN" &>/dev/null 2>&1; then
  iptables -F "$CHAIN"
  iptables -D INPUT   -j "$CHAIN" 2>/dev/null || true
  iptables -D FORWARD -j "$CHAIN" 2>/dev/null || true
  iptables -X "$CHAIN"
  echo "  iptables chain $CHAIN flushed and removed."
else
  echo "  iptables chain $CHAIN not found — skipping."
fi

# ── Optionally wipe runtime data ──────────────────────────────────────────
if [ "${1:-}" = "--purge" ]; then
  echo "  --purge: removing data/db and data/logs …"
  rm -rf "$ROOT/data/db" "$ROOT/data/logs" "$ROOT/data/runtime"
  echo "  Data directories removed."
fi

echo ""
echo "✔  Cleanup complete."
