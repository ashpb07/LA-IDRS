from detection_engine.utils.logger import log_event
from response_engine.blocker import block_ip

def take_action(ip, score):
    if score >= 70:
        print(f"[🔥] Blocking {ip}")
        block_ip(ip)
        log_event(ip, "Intrusion Detected", "Blocked")

    elif score >= 40:
        print(f"[!] Suspicious {ip}")
        log_event(ip, "Suspicious Activity", "Alert")