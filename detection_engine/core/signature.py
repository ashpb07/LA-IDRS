from detection_engine.config import PORT_SCAN_THRESHOLD
from detection_engine.state.ip_state import get_ip_data

def detect_port_scan(ip):
    data = get_ip_data(ip)
    unique_ports = len(data["ports"])

    if unique_ports > PORT_SCAN_THRESHOLD:
        return True

    return False