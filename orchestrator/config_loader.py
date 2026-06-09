# orchestrator/config_loader.py
"""
Loads and validates runtime configuration from environment variables
and the .env file. Returns a unified config dict used by the runner.
"""

import os
from pathlib import Path


def load_env_file(path: str = ".env") -> None:
    """Parse a simple KEY=VALUE .env file into os.environ."""
    env_path = Path(path)
    if not env_path.exists():
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key   = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def get_config() -> dict:
    load_env_file()
    return {
        "interface":        os.getenv("NS_IFACE", "eth0"),
        "socket_path":      os.getenv("NS_SOCKET", "/tmp/netsentinel.sock"),
        "baseline_sec":     int(os.getenv("NS_BASELINE_SEC", "86400")),
        "ema_alpha":        float(os.getenv("NS_EMA_ALPHA", "0.05")),
        "api_host":         os.getenv("NS_API_HOST", "0.0.0.0"),
        "api_port":         int(os.getenv("NS_API_PORT", "8000")),
        "log_level":        os.getenv("NS_LOG_LEVEL", "INFO"),
        "p2p_enabled":      os.getenv("NS_P2P", "false").lower() == "true",
        "p2p_port":         int(os.getenv("NS_P2P_PORT", "9999")),
        "p2p_peers":        [p for p in os.getenv("NS_P2P_PEERS", "").split(",") if p],
        "ban_ttl_sec":      int(os.getenv("NS_BAN_TTL_SEC", "3600")),
        "honeypot_ports":   int(os.getenv("NS_HP_PORTS", "5")),
        "skip_baseline":    os.getenv("NS_SKIP_BASELINE", "false").lower() == "true",
        "data_dir":         os.getenv("NS_DATA_DIR", "data"),
    }
