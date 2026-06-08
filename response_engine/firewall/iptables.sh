#!/usr/bin/env bash
# response_engine/firewall/iptables.sh
# Usage: iptables.sh block <ip> | iptables.sh unblock <ip>

set -euo pipefail

ACTION="${1:-}"
IP="${2:-}"

if [[ -z "$ACTION" || -z "$IP" ]]; then
    echo "Usage: $0 block|unblock <ip>" >&2
    exit 1
fi

# Validate IP format
if ! [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Invalid IP address: $IP" >&2
    exit 1
fi

CHAIN="NETSENTINEL_BLOCK"

# Ensure our chain exists
if ! iptables -n -L "$CHAIN" &>/dev/null; then
    iptables -N "$CHAIN"
    iptables -I INPUT -j "$CHAIN"
    iptables -I FORWARD -j "$CHAIN"
fi

case "$ACTION" in
  block)
    # Avoid duplicate rules
    if ! iptables -C "$CHAIN" -s "$IP" -j DROP &>/dev/null; then
        iptables -A "$CHAIN" -s "$IP" -j DROP
        echo "[iptables] Blocked $IP"
    else
        echo "[iptables] $IP already blocked"
    fi
    ;;
  unblock)
    if iptables -C "$CHAIN" -s "$IP" -j DROP &>/dev/null; then
        iptables -D "$CHAIN" -s "$IP" -j DROP
        echo "[iptables] Unblocked $IP"
    else
        echo "[iptables] $IP not in block list"
    fi
    ;;
  *)
    echo "Unknown action: $ACTION" >&2
    exit 1
    ;;
esac