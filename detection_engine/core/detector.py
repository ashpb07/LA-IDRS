from detection_engine.state.ip_state import update_ip
from detection_engine.core.signature import detect_port_scan
from detection_engine.core.behavior import high_packet_rate
from detection_engine.core.scorer import calculate_score
from detection_engine.core.decision import take_action

def analyze_packet(packet):
    ip = packet.get("src_ip")
    port = packet.get("dst_port")

    if not ip or not port:
        return

    # Update state
    update_ip(ip, port)

    # Detection
    port_scan = detect_port_scan(ip)
    high_rate = high_packet_rate(ip)

    # Scoring
    score = calculate_score(port_scan, high_rate)

    # Decision
    take_action(ip, score)