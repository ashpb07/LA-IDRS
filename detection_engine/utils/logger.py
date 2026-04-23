import json
import time
import os

LOG_FILE = "data/logs/events.json"

def log_event(ip, event, action):
    log = {
        "ip": ip,
        "event": event,
        "action": action,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log) + "\n")