from detection_engine.state.ip_state import get_ip_data

def high_packet_rate(ip):
    data = get_ip_data(ip)
    if len(data["timestamps"]) > 20:
        return True
    return False