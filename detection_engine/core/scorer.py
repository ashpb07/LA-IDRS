def calculate_score(port_scan=False, high_rate=False):
    score = 0

    if port_scan:
        score += 50

    if high_rate:
        score += 30

    return score