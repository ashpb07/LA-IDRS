# detection_engine/config.py
import os

# --- Network ---
NETWORK_INTERFACE   = os.getenv("NS_IFACE", "eth0")
SOCKET_PATH         = os.getenv("NS_SOCKET", "/tmp/netsentinel.sock")

# --- Baseline ---
BASELINE_DURATION_SEC = int(os.getenv("NS_BASELINE_SEC", 86400))  # 24 h
EMA_ALPHA             = float(os.getenv("NS_EMA_ALPHA", 0.05))    # smoothing factor

# --- Risk scoring thresholds ---
SCORE_LOG_ONLY  = 30
SCORE_ALERT     = 70
SCORE_BLOCK     = 100
HONEYPOT_SCORE  = 100   # instant block on honeypot contact

# --- Honeypot ---
HONEYPOT_PORT_COUNT = int(os.getenv("NS_HP_PORTS", 5))
HONEYPOT_PORT_MIN   = 20000
HONEYPOT_PORT_MAX   = 60000

# --- P2P ---
P2P_ENABLED = os.getenv("NS_P2P", "false").lower() == "true"
P2P_PORT    = int(os.getenv("NS_P2P_PORT", 9999))
P2P_PEERS   = [p for p in os.getenv("NS_P2P_PEERS", "").split(",") if p]

# --- API ---
API_HOST = os.getenv("NS_API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("NS_API_PORT", 8000))

# --- Logging ---
LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "logs")
DB_DIR  = os.path.join(os.path.dirname(__file__), "..", "data", "db")