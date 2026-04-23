from collections import defaultdict
import time

ip_data = defaultdict(lambda: {
    "ports": set(),
    "timestamps": []
})

TIME_WINDOW = 10  # seconds

def update_ip(ip, port):
    now = time.time()
    ip_data[ip]["ports"].add(port)
    ip_data[ip]["timestamps"].append(now)

    # remove old timestamps
    ip_data[ip]["timestamps"] = [
        t for t in ip_data[ip]["timestamps"] if now - t < TIME_WINDOW
    ]

def get_ip_data(ip):
    return ip_data[ip]